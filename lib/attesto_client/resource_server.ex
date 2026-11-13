defmodule AttestoClient.ResourceServer do
  @moduledoc """
  Verify JWT access tokens issued by a remote OAuth authorization server.

  A resource server starts one supervised process per trusted issuer. The
  process discovers the issuer's JWKS, retains a bounded key set, coordinates
  refreshes, and permits a configured stale-key interval when a transient
  upstream failure prevents refresh. Signature and claim verification happens
  in the caller process; the server process only owns cache state and refresh
  coordination.

  The process is an `AttestoClient.Issuer` cache that also carries this
  module's token policy, so there is one cache and one refresh logic for both.
  Its name can be given as `issuer: {AttestoClient.Issuer, name}` to verify ID
  Tokens from the same issuer against the same keys.

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
      after transient transport, 429, or 5xx refresh failures; every refresh
      failure receives a retry cooldown so a persistent hard failure cannot
      make every token verification wait on the issuer;
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
  upstream refresh on every request. During that interval, a transient failure
  may use a still-valid stale snapshot; a hard failure or an exhausted stale
  interval returns the remembered refresh error without another fetch. The
  same applies before the first successful refresh: verification returns the
  remembered error until the interval ends, while `warm/1` and `refresh/1`
  still fetch.

  `clock_skew_seconds` bounds how far in the future `iat` and `nbf` may lie,
  and widens `:max_token_age_seconds`; it defaults to `60`.
  `expiry_leeway_seconds` is how long past `exp` a token is still accepted
  (RFC 7519 §4.1.4): an integer from `0` to `300`, default `0`, so an expired
  token is rejected at `exp`. `AttestoClient.IDToken.verify/2` takes the same
  two options with the same meanings.

  `:outbound` names deliberate exceptions to the HTTPS and public-address
  rules for the metadata and JWKS fetches: an issuer at a private address, or
  a loopback `http` issuer in development. See `AttestoClient.Outbound`.
  `:resolver` is a two-argument function used to resolve host names for those
  fetches; every address it returns is screened the same way.
  """

  alias Attesto.{NumericDate, SigningAlg}
  alias AttestoClient.{ClaimValidation, Discovery, Issuer, Verifier}

  @label "ResourceServer"
  @default_clock_skew_seconds 60

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
          | {:expiry_leeway_seconds, 0..300}
          | {:max_jwks_keys, pos_integer()}
          | {:max_response_bytes, pos_integer()}
          | {:outbound, AttestoClient.Outbound.t()}
          | {:resolver,
             (charlist(), :inet | :inet6 -> {:ok, [:inet.ip_address()]} | {:error, term()})}

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
    opts |> config!() |> Issuer.start_server(opts)
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
    Issuer.verify(server, access_token, &verify_snapshot(&1, access_token, opts))
  end

  def verify(_server, _access_token, _opts), do: {:error, :invalid_token}

  @doc "Warm the verifier by completing metadata/JWKS retrieval."
  @spec warm(server()) :: :ok | {:error, {:jwks_refresh_failed, term()}}
  defdelegate warm(server), to: Issuer

  @doc "Return whether the verifier retains a currently usable key snapshot."
  @spec ready?(server()) :: boolean()
  defdelegate ready?(server), to: Issuer

  @doc "Force a metadata/JWKS refresh."
  @spec refresh(server()) :: :ok | {:error, {:jwks_refresh_failed, term()}}
  defdelegate refresh(server), to: Issuer

  # The keys come from the snapshot; the token policy is the one this module
  # validated at start, carried on the snapshot as `private`.
  defp verify_snapshot(%{private: policy} = snapshot, access_token, opts) do
    with {:ok, algs} <- Verifier.accepted_algs(accepted_algs: policy.accepted_algs),
         {:ok, claims, header, _verified_jwk} <-
           Verifier.verify_signature(access_token, snapshot.keys, algs),
         :ok <- check_typ(header),
         :ok <- check_issuer(claims, snapshot.issuer),
         :ok <- ClaimValidation.audience(claims, policy.audiences, :invalid_audience),
         :ok <- check_claims(claims),
         now = now(opts),
         :ok <-
           ClaimValidation.expiration(claims, now,
             missing_error: :expired,
             invalid_error: :expired,
             expired_error: :expired,
             leeway: policy.expiry_leeway_seconds
           ),
         :ok <-
           ClaimValidation.not_before(claims, now,
             invalid_error: :invalid_claims,
             future_error: :not_yet_valid,
             skew: policy.clock_skew_seconds
           ),
         :ok <-
           ClaimValidation.issued_at(claims, now,
             missing_error: :invalid_claims,
             invalid_error: :invalid_claims,
             future_error: :not_yet_valid,
             non_negative: false,
             skew: policy.clock_skew_seconds
           ),
         :ok <- check_token_policy(claims, opts, now, policy.clock_skew_seconds),
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

  defp check_claims(claims) do
    if non_empty_string?(claims["sub"]) and non_empty_string?(claims["client_id"]) and
         non_empty_string?(claims["jti"]) and non_negative_integer?(claims["iat"]),
       do: :ok,
       else: {:error, :invalid_claims}
  end

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
         :ok <-
           ClaimValidation.issued_within(
             claims["iat"],
             now,
             Keyword.get(opts, :max_token_age_seconds),
             skew,
             too_old_error: :token_too_old,
             invalid_error: :invalid_policy
           ) do
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

  defp check_confirmation(claims, opts) do
    confirm_opts = [
      dpop_jkt: Keyword.get(opts, :dpop_jkt),
      mtls_cert_thumbprint: Keyword.get(opts, :mtls_cert_thumbprint),
      allow_ambient_mtls: true
    ]

    case Attesto.Token.check_confirmation(claims, confirm_opts) do
      :ok -> :ok
      {:error, :dpop_binding_mismatch} -> {:error, :dpop_key_mismatch}
      {:error, :mtls_cert_required} -> {:error, :mtls_certificate_required}
      {:error, :mtls_binding_mismatch} -> {:error, :mtls_certificate_mismatch}
      {:error, reason} -> {:error, reason}
    end
  end

  # The cache options are validated by `AttestoClient.Issuer`; the token policy
  # is validated here and travels with the cache as its `private` term.
  defp config!(opts) do
    config = Issuer.config!(opts, @label)

    policy = %{
      audiences: audiences!(Keyword.get(opts, :audience)),
      accepted_algs: Issuer.accepted_algs!(Keyword.get(opts, :accepted_algs), @label),
      clock_skew_seconds: clock_skew_seconds!(opts),
      expiry_leeway_seconds: expiry_leeway_seconds!(opts)
    }

    %{config | private: policy} |> Map.put(:accepted_algs, policy.accepted_algs)
  end

  defp audiences!(audience) when is_binary(audience) and audience != "", do: [audience]

  defp audiences!(audiences) when is_list(audiences) and audiences != [] do
    if Enum.all?(audiences, &(is_binary(&1) and &1 != "")),
      do: Enum.uniq(audiences),
      else: raise(ArgumentError, "ResourceServer :audience entries must be non-empty strings")
  end

  defp audiences!(_invalid),
    do: raise(ArgumentError, "ResourceServer requires :audience as a string or non-empty list")

  defp expiry_leeway_seconds!(opts) do
    case ClaimValidation.tolerance(opts, :expiry_leeway_seconds, 0) do
      {:ok, seconds} ->
        seconds

      :error ->
        raise ArgumentError,
              "ResourceServer :expiry_leeway_seconds must be an integer from 0 to " <>
                "#{ClaimValidation.max_tolerance_seconds()}"
    end
  end

  defp clock_skew_seconds!(opts) do
    case Keyword.get(opts, :clock_skew_seconds, @default_clock_skew_seconds) do
      value when is_integer(value) and value >= 0 ->
        value

      _invalid ->
        raise ArgumentError, "ResourceServer :clock_skew_seconds must be a non-negative integer"
    end
  end

  defp now(opts), do: NumericDate.now(opts, default: :system, invalid_override: :fallback)

  defp non_empty_string?(value), do: is_binary(value) and value != ""
  defp non_negative_integer?(value), do: is_integer(value) and value >= 0
end
