defmodule AttestoClient.ResourceServer do
  @moduledoc """
  Verify JWT access tokens issued by a remote OAuth authorization server.

  A resource server starts one supervised process per trusted issuer. The
  process discovers the issuer's JWKS, retains a bounded key set, coordinates
  refreshes, and permits a configured stale-key interval when a transient
  upstream failure prevents refresh. Signature and claim verification happens
  in the caller process; the server process only owns cache state and refresh
  coordination.

  ## Security properties

    * discovery metadata must report the configured issuer exactly;
    * metadata and JWKS are fetched only over HTTPS with redirects disabled;
    * signing algorithms are an explicit allowlist and are never learned from
      the presented token;
    * a `kid` selects exactly one eligible verification key, and RSA keys below
      2048 bits are rejected;
    * RFC 9068 `typ`, issuer, audience, time, identity, client, JWT ID, and scope
      claims are checked;
    * an unknown `kid` causes at most one coordinated refresh per cache
      generation and refresh interval, preventing request fan-out and random
      `kid` refresh storms;
    * stale keys are used only within the configured stale interval and only
      after transient transport, 429, or 5xx refresh failures;
    * DPoP and mTLS confirmation claims fail closed unless the matching verified
      proof-key or certificate thumbprint is supplied.

  The module authenticates tokens and can require exact OAuth scope tokens. It
  does not decide which subjects may perform an application action, map claims
  to local users, or retain sessions; those remain application policy.

  ## Example

      children = [
        {AttestoClient.ResourceServer,
         name: MyApp.RemoteIssuer,
         issuer: "https://issuer.example",
         audience: "https://api.example",
         accepted_algs: ["PS256", "ES256"],
         fresh_ttl: :timer.minutes(5),
         stale_ttl: :timer.hours(1),
         refresh_retry_interval: :timer.seconds(5),
         max_response_bytes: 512 * 1024}
      ]

      :ok = AttestoClient.ResourceServer.warm(MyApp.RemoteIssuer)

      {:ok, claims} =
        AttestoClient.ResourceServer.verify(MyApp.RemoteIssuer, access_token,
          required_scopes: ["documents.read"]
        )

  `fresh_ttl` and `stale_ttl` are milliseconds. `stale_ttl` starts when the
  fresh interval ends. `refresh_retry_interval` avoids retrying a failed
  upstream refresh on every request while a stale snapshot remains usable.
  """

  use GenServer

  alias Attesto.SecureCompare
  alias Attesto.SigningAlg
  alias AttestoClient.Discovery
  alias AttestoClient.Verifier

  @default_fresh_ttl :timer.minutes(5)
  @default_stale_ttl :timer.hours(1)
  @default_unknown_kid_refresh_interval :timer.seconds(30)
  @default_refresh_retry_interval :timer.seconds(5)
  @default_refresh_timeout :timer.seconds(15)
  @default_clock_skew_seconds 60
  @default_max_jwks_keys 32
  @default_max_response_bytes 512 * 1024

  @type server :: GenServer.server()
  @type jwks :: %{optional(String.t()) => term()} | [map()] | map()

  @type start_opt ::
          {:name, GenServer.name()}
          | {:issuer, String.t()}
          | {:audience, String.t() | [String.t()]}
          | {:accepted_algs, [SigningAlg.alg()]}
          | {:well_known, Discovery.well_known()}
          | {:metadata, map()}
          | {:jwks_uri, String.t()}
          | {:req_options, keyword()}
          | {:fresh_ttl, non_neg_integer()}
          | {:stale_ttl, non_neg_integer()}
          | {:unknown_kid_refresh_interval, non_neg_integer()}
          | {:refresh_retry_interval, non_neg_integer()}
          | {:refresh_timeout, pos_integer()}
          | {:clock_skew_seconds, non_neg_integer()}
          | {:max_jwks_keys, pos_integer()}
          | {:max_response_bytes, pos_integer()}

  @type verify_opt ::
          {:required_scopes, [String.t()]}
          | {:allowed_subjects, [String.t()]}
          | {:allowed_client_ids, [String.t()]}
          | {:max_token_age_seconds, non_neg_integer()}
          | {:max_token_lifetime_seconds, pos_integer()}
          | {:now, integer() | DateTime.t()}
          | {:dpop_jkt, String.t()}
          | {:mtls_cert_thumbprint, String.t()}

  @type error ::
          :invalid_token
          | :invalid_signature
          | :ambiguous_key
          | :weak_key
          | :unsupported_alg
          | :unsupported_critical_header
          | :unexpected_typ
          | :invalid_issuer
          | :invalid_audience
          | :expired
          | :not_yet_valid
          | :invalid_claims
          | :invalid_scope
          | :insufficient_scope
          | :subject_not_allowed
          | :client_not_allowed
          | :token_too_old
          | :token_lifetime_exceeded
          | :invalid_policy
          | :unsupported_confirmation
          | :dpop_proof_required
          | :dpop_proof_unexpected
          | :dpop_key_mismatch
          | :mtls_certificate_required
          | :mtls_certificate_mismatch
          | {:jwks_refresh_failed, term()}

  @doc "Start a supervised remote-issuer verifier."
  @spec start_link([start_opt()]) :: GenServer.on_start()
  def start_link(opts) when is_list(opts) do
    config = config!(opts)

    case Keyword.fetch(opts, :name) do
      {:ok, name} -> GenServer.start_link(__MODULE__, config, name: name)
      :error -> GenServer.start_link(__MODULE__, config)
    end
  end

  def child_spec(opts) do
    id = Keyword.get(opts, :name, {__MODULE__, Keyword.get(opts, :issuer)})

    %{
      id: id,
      start: {__MODULE__, :start_link, [opts]},
      type: :worker,
      restart: :permanent,
      shutdown: 5_000
    }
  end

  @doc """
  Verify a remote issuer's JWT access token.

  `:required_scopes` is an optional list of exact RFC 6749 scope tokens. Every
  listed scope must occur in the token's space-delimited `scope` claim.
  `:allowed_subjects`, `:allowed_client_ids`, `:max_token_age_seconds`, and
  `:max_token_lifetime_seconds` provide optional authentication policy bounds.
  Sender-constrained tokens additionally require the verified `:dpop_jkt` or
  `:mtls_cert_thumbprint` from the current request.
  """
  @spec verify(server(), String.t(), [verify_opt()]) :: {:ok, map()} | {:error, error()}
  def verify(server, access_token, opts \\ [])

  def verify(server, access_token, opts) when is_binary(access_token) and is_list(opts) do
    with {:ok, snapshot} <- usable_snapshot(server) do
      result = verify_snapshot(snapshot, access_token, opts)
      maybe_refresh_unknown_kid(server, snapshot, access_token, opts, result)
    end
  catch
    :exit, reason -> {:error, {:jwks_refresh_failed, call_exit_reason(reason)}}
  end

  def verify(_server, _access_token, _opts), do: {:error, :invalid_token}

  @doc "Warm the verifier by completing metadata/JWKS retrieval."
  @spec warm(server()) :: :ok | {:error, {:jwks_refresh_failed, term()}}
  def warm(server), do: refresh(server)

  @doc "Return whether the verifier retains a currently usable key snapshot."
  @spec ready?(server()) :: boolean()
  def ready?(server) do
    case GenServer.call(server, :snapshot) do
      %{stale_until: stale_until} -> monotonic_ms() < stale_until
      nil -> false
    end
  catch
    :exit, _reason -> false
  end

  @doc "Force a metadata/JWKS refresh."
  @spec refresh(server()) :: :ok | {:error, {:jwks_refresh_failed, term()}}
  def refresh(server) do
    snapshot = GenServer.call(server, :snapshot)
    generation = if snapshot, do: snapshot.generation, else: nil

    case refresh_snapshot(server, generation, :forced) do
      {:ok, _snapshot} -> :ok
      {:error, reason} -> {:error, {:jwks_refresh_failed, reason}}
    end
  catch
    :exit, reason -> {:error, {:jwks_refresh_failed, call_exit_reason(reason)}}
  end

  @impl true
  def init(config) do
    Process.flag(:trap_exit, true)

    {:ok,
     Map.merge(config, %{
       snapshot: nil,
       generation: 0,
       refresh_task: nil,
       refresh_timer: nil,
       refresh_waiters: [],
       next_unknown_refresh_at: nil
     })}
  end

  @impl true
  def handle_call(:snapshot, _from, state), do: {:reply, state.snapshot, state}
  def handle_call(:refresh_timeout, _from, state), do: {:reply, state.refresh_timeout, state}

  def handle_call({:refresh, observed_generation, reason}, from, state) do
    cond do
      newer_snapshot?(state, observed_generation) ->
        {:reply, {:ok, state.snapshot}, state}

      state.refresh_task != nil ->
        {:noreply, %{state | refresh_waiters: [from | state.refresh_waiters]}}

      refresh_suppressed?(state, reason) ->
        {:reply, {:ok, state.snapshot}, state}

      true ->
        task = Task.async(fn -> fetch_snapshot(state) end)
        timer = Process.send_after(self(), {:refresh_deadline, task.ref}, state.refresh_timeout)

        next_unknown_refresh_at =
          if reason == :unknown_kid,
            do: monotonic_ms() + state.unknown_kid_refresh_interval,
            else: state.next_unknown_refresh_at

        {:noreply,
         %{
           state
           | refresh_task: task,
             refresh_timer: timer,
             refresh_waiters: [from],
             next_unknown_refresh_at: next_unknown_refresh_at
         }}
    end
  end

  @impl true
  def handle_info({ref, result}, %{refresh_task: %Task{ref: ref} = task} = state) do
    Process.demonitor(task.ref, [:flush])
    cancel_timer(state.refresh_timer)
    {reply, state} = apply_refresh_result(result, state)
    Enum.each(state.refresh_waiters, &GenServer.reply(&1, reply))
    {:noreply, %{state | refresh_task: nil, refresh_timer: nil, refresh_waiters: []}}
  end

  def handle_info({:DOWN, ref, :process, _pid, reason}, %{refresh_task: %Task{ref: ref}} = state) do
    cancel_timer(state.refresh_timer)
    reply = {:error, {:refresh_task_exit, reason}}
    Enum.each(state.refresh_waiters, &GenServer.reply(&1, reply))
    state = record_refresh_failure(state, elem(reply, 1))

    {:noreply, %{state | refresh_task: nil, refresh_timer: nil, refresh_waiters: []}}
  end

  def handle_info({:refresh_deadline, ref}, %{refresh_task: %Task{ref: ref} = task} = state) do
    _ = Task.shutdown(task, :brutal_kill)
    reply = {:error, :refresh_timeout}
    Enum.each(state.refresh_waiters, &GenServer.reply(&1, reply))
    state = record_refresh_failure(state, :refresh_timeout)

    {:noreply, %{state | refresh_task: nil, refresh_timer: nil, refresh_waiters: []}}
  end

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, %{refresh_task: %Task{} = task}) do
    Task.shutdown(task, :brutal_kill)
    :ok
  end

  def terminate(_reason, _state), do: :ok

  defp usable_snapshot(server) do
    snapshot = GenServer.call(server, :snapshot)
    now = monotonic_ms()

    cond do
      snapshot == nil ->
        initial_snapshot(server)

      now < snapshot.fresh_until ->
        {:ok, snapshot}

      stale_retry_active?(snapshot, now) ->
        {:ok, snapshot}

      true ->
        refresh_expired_snapshot(server, snapshot, now)
    end
  end

  defp initial_snapshot(server) do
    case refresh_snapshot(server, nil, :initial) do
      {:ok, refreshed} -> {:ok, refreshed}
      {:error, reason} -> {:error, {:jwks_refresh_failed, reason}}
    end
  end

  defp refresh_expired_snapshot(server, snapshot, now) do
    case refresh_snapshot(server, snapshot.generation, :expired) do
      {:ok, refreshed} -> {:ok, refreshed}
      {:error, reason} -> stale_or_refresh_error(snapshot, now, reason)
    end
  end

  defp stale_or_refresh_error(snapshot, now, reason) do
    if now < snapshot.stale_until and transient_refresh_error?(reason),
      do: {:ok, snapshot},
      else: {:error, {:jwks_refresh_failed, reason}}
  end

  defp refresh_snapshot(server, generation, reason) do
    GenServer.call(server, {:refresh, generation, reason}, refresh_call_timeout(server))
  catch
    :exit, exit_reason -> {:error, call_exit_reason(exit_reason)}
  end

  defp refresh_call_timeout(server), do: GenServer.call(server, :refresh_timeout) + 1_000

  defp maybe_refresh_unknown_kid(_server, _snapshot, _token, _opts, {:ok, claims}),
    do: {:ok, claims}

  defp maybe_refresh_unknown_kid(
         server,
         snapshot,
         token,
         opts,
         {:error, :invalid_signature} = error
       ) do
    if unknown_kid?(token, snapshot.keys) do
      case refresh_snapshot(server, snapshot.generation, :unknown_kid) do
        {:ok, refreshed} -> verify_snapshot(refreshed, token, opts)
        {:error, _reason} -> error
      end
    else
      error
    end
  end

  defp maybe_refresh_unknown_kid(_server, _snapshot, _token, _opts, error), do: error

  defp verify_snapshot(snapshot, access_token, opts) do
    now = now(opts)

    with {:ok, algs} <- Verifier.accepted_algs(accepted_algs: snapshot.accepted_algs),
         {:ok, claims, header} <- Verifier.verify_signature(access_token, snapshot.keys, algs),
         :ok <- check_typ(header),
         :ok <- check_issuer(claims, snapshot.issuer),
         :ok <- check_audience(claims, snapshot.audiences),
         :ok <- check_claims(claims),
         :ok <- check_expiry(claims, now),
         :ok <- check_not_before(claims, now, snapshot.clock_skew_seconds),
         :ok <- check_issued_at(claims, now, snapshot.clock_skew_seconds),
         :ok <- check_token_policy(claims, opts, now, snapshot.clock_skew_seconds),
         {:ok, scopes} <- scopes(claims),
         :ok <- check_required_scopes(scopes, Keyword.get(opts, :required_scopes, [])),
         :ok <- check_confirmation(claims, opts) do
      {:ok, claims}
    end
  end

  defp check_typ(%{"typ" => typ}) when is_binary(typ) do
    if String.downcase(typ) in ["at+jwt", "application/at+jwt"],
      do: :ok,
      else: {:error, :unexpected_typ}
  end

  defp check_typ(_header), do: {:error, :unexpected_typ}

  defp check_issuer(%{"iss" => issuer}, issuer), do: :ok
  defp check_issuer(_claims, _issuer), do: {:error, :invalid_issuer}

  defp check_audience(%{"aud" => aud}, expected) when is_binary(aud) do
    if aud in expected, do: :ok, else: {:error, :invalid_audience}
  end

  defp check_audience(%{"aud" => audiences}, expected) when is_list(audiences) do
    if audiences != [] and Enum.all?(audiences, &is_binary/1) and
         Enum.any?(audiences, &(&1 in expected)),
       do: :ok,
       else: {:error, :invalid_audience}
  end

  defp check_audience(_claims, _expected), do: {:error, :invalid_audience}

  defp check_claims(claims) do
    if non_empty_string?(claims["sub"]) and non_empty_string?(claims["client_id"]) and
         non_empty_string?(claims["jti"]) and non_negative_integer?(claims["iat"]),
       do: :ok,
       else: {:error, :invalid_claims}
  end

  defp check_expiry(%{"exp" => exp}, now) when is_integer(exp) and exp > now, do: :ok
  defp check_expiry(_claims, _now), do: {:error, :expired}

  defp check_not_before(%{"nbf" => nbf}, now, skew) when is_integer(nbf) do
    if nbf <= now + skew, do: :ok, else: {:error, :not_yet_valid}
  end

  defp check_not_before(%{"nbf" => _invalid}, _now, _skew), do: {:error, :invalid_claims}
  defp check_not_before(_claims, _now, _skew), do: :ok

  defp check_issued_at(%{"iat" => iat}, now, skew) when is_integer(iat) do
    if iat <= now + skew, do: :ok, else: {:error, :not_yet_valid}
  end

  defp check_issued_at(_claims, _now, _skew), do: {:error, :invalid_claims}

  defp check_token_policy(claims, opts, now, skew) do
    with :ok <-
           check_allowed(
             claims["sub"],
             Keyword.get(opts, :allowed_subjects),
             :subject_not_allowed
           ),
         :ok <-
           check_allowed(
             claims["client_id"],
             Keyword.get(opts, :allowed_client_ids),
             :client_not_allowed
           ),
         :ok <- check_max_age(claims["iat"], now, skew, Keyword.get(opts, :max_token_age_seconds)) do
      check_max_lifetime(
        claims["iat"],
        claims["exp"],
        Keyword.get(opts, :max_token_lifetime_seconds)
      )
    end
  end

  defp check_allowed(_value, nil, _error), do: :ok

  defp check_allowed(value, allowed, error) when is_list(allowed) do
    cond do
      not Enum.all?(allowed, &non_empty_string?/1) -> {:error, :invalid_policy}
      value in allowed -> :ok
      true -> {:error, error}
    end
  end

  defp check_allowed(_value, _invalid, _error), do: {:error, :invalid_policy}

  defp check_max_age(_iat, _now, _skew, nil), do: :ok

  defp check_max_age(iat, now, skew, max_age)
       when is_integer(max_age) and max_age >= 0 do
    if now - iat <= max_age + skew, do: :ok, else: {:error, :token_too_old}
  end

  defp check_max_age(_iat, _now, _skew, _invalid), do: {:error, :invalid_policy}

  defp check_max_lifetime(_iat, _exp, nil), do: :ok

  defp check_max_lifetime(iat, exp, max_lifetime)
       when is_integer(max_lifetime) and max_lifetime > 0 do
    lifetime = exp - iat

    if lifetime > 0 and lifetime <= max_lifetime,
      do: :ok,
      else: {:error, :token_lifetime_exceeded}
  end

  defp check_max_lifetime(_iat, _exp, _invalid), do: {:error, :invalid_policy}

  defp scopes(%{"scope" => scope}) when is_binary(scope) do
    scopes = String.split(scope, " ", trim: true)

    if scopes != [] and Enum.all?(scopes, &Attesto.Scope.valid_token?/1),
      do: {:ok, scopes},
      else: {:error, :invalid_scope}
  end

  defp scopes(claims) when not is_map_key(claims, "scope"), do: {:ok, []}
  defp scopes(_claims), do: {:error, :invalid_scope}

  defp check_required_scopes(_granted, []), do: :ok

  defp check_required_scopes(granted, required) when is_list(required) do
    if Enum.all?(required, &Attesto.Scope.valid_token?/1) and
         Enum.all?(required, &(&1 in granted)),
       do: :ok,
       else: {:error, :insufficient_scope}
  end

  defp check_required_scopes(_granted, _invalid), do: {:error, :insufficient_scope}

  defp check_confirmation(%{"cnf" => %{"jkt" => expected} = confirmation}, opts)
       when is_binary(expected) and map_size(confirmation) == 1 do
    presented = Keyword.get(opts, :dpop_jkt)

    cond do
      not Attesto.MTLS.thumbprint_shape?(expected) -> {:error, :unsupported_confirmation}
      presented == nil -> {:error, :dpop_proof_required}
      not Attesto.MTLS.thumbprint_shape?(presented) -> {:error, :dpop_key_mismatch}
      SecureCompare.equal?(expected, presented) -> :ok
      true -> {:error, :dpop_key_mismatch}
    end
  end

  defp check_confirmation(%{"cnf" => %{"x5t#S256" => expected} = confirmation}, opts)
       when is_binary(expected) and map_size(confirmation) == 1 do
    presented = Keyword.get(opts, :mtls_cert_thumbprint)

    cond do
      Keyword.get(opts, :dpop_jkt) != nil -> {:error, :dpop_proof_unexpected}
      not Attesto.MTLS.thumbprint_shape?(expected) -> {:error, :unsupported_confirmation}
      presented == nil -> {:error, :mtls_certificate_required}
      not Attesto.MTLS.thumbprint_shape?(presented) -> {:error, :mtls_certificate_mismatch}
      SecureCompare.equal?(expected, presented) -> :ok
      true -> {:error, :mtls_certificate_mismatch}
    end
  end

  defp check_confirmation(%{"cnf" => _unsupported}, _opts),
    do: {:error, :unsupported_confirmation}

  defp check_confirmation(_claims, opts) do
    if Keyword.get(opts, :dpop_jkt) != nil, do: {:error, :dpop_proof_unexpected}, else: :ok
  end

  defp fetch_snapshot(state) do
    with {:ok, jwks_uri} <- resolve_jwks_uri(state),
         {:ok, jwks} <- Discovery.fetch_jwks(jwks_uri, discovery_opts(state)),
         {:ok, keys} <- Verifier.normalize_jwks(jwks),
         :ok <- check_key_bound(keys, state.max_jwks_keys),
         :ok <- Verifier.validate_verification_keys(keys, state.accepted_algs) do
      now = monotonic_ms()

      {:ok,
       %{
         accepted_algs: state.accepted_algs,
         audiences: state.audiences,
         clock_skew_seconds: state.clock_skew_seconds,
         fresh_until: now + state.fresh_ttl,
         generation: state.generation + 1,
         issuer: state.issuer,
         keys: keys,
         retry_after: nil,
         stale_until: now + state.fresh_ttl + state.stale_ttl
       }}
    end
  rescue
    error -> {:error, {:transport, Exception.message(error)}}
  catch
    kind, reason -> {:error, {:transport, {kind, reason}}}
  end

  defp resolve_jwks_uri(%{jwks_uri: uri}) when is_binary(uri), do: {:ok, uri}

  defp resolve_jwks_uri(%{metadata: %{} = metadata, issuer: issuer}),
    do: jwks_uri_from_metadata(metadata, issuer)

  defp resolve_jwks_uri(state) do
    with {:ok, metadata} <- Discovery.fetch(state.issuer, discovery_opts(state)) do
      jwks_uri_from_metadata(metadata, state.issuer)
    end
  end

  defp jwks_uri_from_metadata(%{"issuer" => issuer, "jwks_uri" => uri}, issuer)
       when is_binary(uri) and uri != "",
       do: {:ok, uri}

  defp jwks_uri_from_metadata(%{"issuer" => _other}, _issuer), do: {:error, :issuer_mismatch}
  defp jwks_uri_from_metadata(_metadata, _issuer), do: {:error, :invalid_metadata}

  defp discovery_opts(state) do
    [well_known: state.well_known, req_options: state.req_options]
  end

  defp check_key_bound(keys, max) when keys != [] and length(keys) <= max, do: :ok
  defp check_key_bound(_keys, _max), do: {:error, :invalid_jwks}

  defp apply_refresh_result({:ok, snapshot}, state) do
    {{:ok, snapshot}, %{state | snapshot: snapshot, generation: snapshot.generation}}
  end

  defp apply_refresh_result({:error, reason}, state),
    do: {{:error, reason}, record_refresh_failure(state, reason)}

  defp apply_refresh_result(other, state), do: {{:error, {:invalid_fetch_result, other}}, state}

  defp newer_snapshot?(%{snapshot: nil}, _observed), do: false
  defp newer_snapshot?(_state, nil), do: false

  defp newer_snapshot?(state, observed),
    do: state.snapshot.generation > observed

  defp refresh_suppressed?(state, :expired),
    do: stale_retry_active?(state.snapshot, monotonic_ms())

  defp refresh_suppressed?(%{next_unknown_refresh_at: next_refresh}, :unknown_kid)
       when is_integer(next_refresh),
       do: monotonic_ms() < next_refresh

  defp refresh_suppressed?(_state, _reason), do: false

  defp unknown_kid?(token, keys) do
    case Verifier.peek_header(token) do
      {:ok, %{"kid" => kid}} when is_binary(kid) and kid != "" ->
        not Enum.any?(keys, &(Map.get(&1, "kid") == kid))

      _other ->
        false
    end
  end

  defp transient_refresh_error?({:transport, _reason}), do: true
  defp transient_refresh_error?(:refresh_timeout), do: true
  defp transient_refresh_error?({:refresh_task_exit, _reason}), do: true
  defp transient_refresh_error?({:http_status, 429}), do: true
  defp transient_refresh_error?({:http_status, status}) when status in 500..599, do: true
  defp transient_refresh_error?(_reason), do: false

  defp config!(opts) do
    issuer = required_https_issuer!(Keyword.get(opts, :issuer))
    audiences = audiences!(Keyword.get(opts, :audience))
    accepted_algs = accepted_algs!(Keyword.get(opts, :accepted_algs))
    refresh_timeout = positive_integer!(opts, :refresh_timeout, @default_refresh_timeout)

    max_response_bytes =
      positive_integer!(opts, :max_response_bytes, @default_max_response_bytes)

    %{
      accepted_algs: accepted_algs,
      audiences: audiences,
      clock_skew_seconds:
        non_negative_integer!(opts, :clock_skew_seconds, @default_clock_skew_seconds),
      fresh_ttl: non_negative_integer!(opts, :fresh_ttl, @default_fresh_ttl),
      issuer: issuer,
      jwks_uri: optional_string!(opts, :jwks_uri),
      max_jwks_keys: positive_integer!(opts, :max_jwks_keys, @default_max_jwks_keys),
      max_response_bytes: max_response_bytes,
      metadata: optional_map!(opts, :metadata),
      refresh_retry_interval:
        non_negative_integer!(
          opts,
          :refresh_retry_interval,
          @default_refresh_retry_interval
        ),
      refresh_timeout: refresh_timeout,
      req_options: req_options!(opts, refresh_timeout, max_response_bytes),
      stale_ttl: non_negative_integer!(opts, :stale_ttl, @default_stale_ttl),
      unknown_kid_refresh_interval:
        non_negative_integer!(
          opts,
          :unknown_kid_refresh_interval,
          @default_unknown_kid_refresh_interval
        ),
      well_known: Keyword.get(opts, :well_known, :openid_configuration)
    }
  end

  defp required_https_issuer!(issuer) do
    case Discovery.validate_issuer_identifier(issuer) do
      :ok -> issuer
      {:error, _reason} -> raise ArgumentError, "ResourceServer requires an HTTPS :issuer"
    end
  end

  defp audiences!(audience) when is_binary(audience) and audience != "", do: [audience]

  defp audiences!(audiences) when is_list(audiences) and audiences != [] do
    if Enum.all?(audiences, &(is_binary(&1) and &1 != "")),
      do: Enum.uniq(audiences),
      else: raise(ArgumentError, "ResourceServer :audience entries must be non-empty strings")
  end

  defp audiences!(_invalid),
    do: raise(ArgumentError, "ResourceServer requires :audience as a string or non-empty list")

  defp accepted_algs!(algs) when is_list(algs) and algs != [] do
    if Enum.all?(algs, &(&1 in SigningAlg.allowed())),
      do: Enum.uniq(algs),
      else:
        raise(ArgumentError, "ResourceServer :accepted_algs contains an unsupported algorithm")
  end

  defp accepted_algs!(_invalid),
    do: raise(ArgumentError, "ResourceServer requires :accepted_algs as a non-empty list")

  defp optional_string!(opts, key) do
    case Keyword.get(opts, key) do
      nil -> nil
      value when is_binary(value) and value != "" -> value
      _invalid -> raise ArgumentError, "ResourceServer #{inspect(key)} must be a non-empty string"
    end
  end

  defp optional_map!(opts, key) do
    case Keyword.get(opts, key) do
      nil -> nil
      %{} = value -> value
      _invalid -> raise ArgumentError, "ResourceServer #{inspect(key)} must be a map"
    end
  end

  defp req_options!(opts, refresh_timeout, max_response_bytes) do
    case Keyword.get(opts, :req_options, []) do
      req_options when is_list(req_options) ->
        phase_timeout = max(div(max(refresh_timeout - 1_000, 1), 4), 1)
        connect_options = connect_options!(req_options, phase_timeout)

        req_options
        |> Keyword.put(:retry, false)
        |> Keyword.put(:receive_timeout, phase_timeout)
        |> Keyword.put(:connect_options, connect_options)
        |> Keyword.put(:compressed, false)
        |> Keyword.put(:into, bounded_response_into(max_response_bytes))

      _invalid ->
        raise ArgumentError, "ResourceServer :req_options must be a keyword list"
    end
  end

  defp connect_options!(req_options, timeout) do
    case Keyword.get(req_options, :connect_options, []) do
      connect_options when is_list(connect_options) ->
        Keyword.put(connect_options, :timeout, timeout)

      _invalid ->
        raise ArgumentError, "ResourceServer :connect_options must be a keyword list"
    end
  end

  defp positive_integer!(opts, key, default) do
    case Keyword.get(opts, key, default) do
      value when is_integer(value) and value > 0 -> value
      _invalid -> raise ArgumentError, "ResourceServer #{inspect(key)} must be a positive integer"
    end
  end

  defp non_negative_integer!(opts, key, default) do
    case Keyword.get(opts, key, default) do
      value when is_integer(value) and value >= 0 ->
        value

      _invalid ->
        raise ArgumentError, "ResourceServer #{inspect(key)} must be a non-negative integer"
    end
  end

  defp now(opts) do
    case Keyword.get(opts, :now) do
      %DateTime{} = value -> DateTime.to_unix(value)
      value when is_integer(value) -> value
      _other -> System.system_time(:second)
    end
  end

  defp record_refresh_failure(%{snapshot: nil} = state, _reason), do: state

  defp record_refresh_failure(state, reason) do
    now = monotonic_ms()

    if transient_refresh_error?(reason) and now < state.snapshot.stale_until do
      snapshot =
        Map.put(state.snapshot, :retry_after, now + state.refresh_retry_interval)

      %{state | snapshot: snapshot}
    else
      state
    end
  end

  defp stale_retry_active?(%{retry_after: retry_after, stale_until: stale_until}, now)
       when is_integer(retry_after),
       do: now < retry_after and now < stale_until

  defp stale_retry_active?(_snapshot, _now), do: false

  defp bounded_response_into(max_bytes) do
    fn {:data, data}, {request, response} ->
      body = if is_binary(response.body), do: response.body, else: ""

      if byte_size(body) + byte_size(data) > max_bytes do
        response = %{
          response
          | body: "",
            private: Map.put(response.private, :attesto_client_response_too_large, true)
        }

        {:halt, {request, response}}
      else
        {:cont, {request, %{response | body: body <> data}}}
      end
    end
  end

  defp call_exit_reason({:noproc, _call}), do: :server_not_running
  defp call_exit_reason({:timeout, _call}), do: :refresh_timeout
  defp call_exit_reason({:shutdown, _call}), do: :server_stopping
  defp call_exit_reason({{:shutdown, _reason}, _call}), do: :server_stopping
  defp call_exit_reason({:killed, _call}), do: :server_stopping
  defp call_exit_reason(:noproc), do: :server_not_running
  defp call_exit_reason(:timeout), do: :refresh_timeout
  defp call_exit_reason(:shutdown), do: :server_stopping
  defp call_exit_reason(:killed), do: :server_stopping
  defp call_exit_reason(reason), do: {:server_exit, reason}

  defp monotonic_ms, do: System.monotonic_time(:millisecond)
  defp cancel_timer(nil), do: :ok
  defp cancel_timer(timer), do: Process.cancel_timer(timer, async: true, info: false)
  defp non_empty_string?(value), do: is_binary(value) and value != ""
  defp non_negative_integer?(value), do: is_integer(value) and value >= 0
end
