defmodule AttestoClient.Issuer do
  @moduledoc """
  A supervised cache of one issuer's discovery metadata and JWKS.

  Without it, each `AttestoClient.IDToken.verify/2` call that is not handed a
  `:jwks` fetches the issuer's discovery document and key set again. An
  `Issuer` process fetches them once, serves them from memory, and refreshes
  them on a schedule and when a token names a `kid` it has not seen (RFC 7517
  key rotation). `AttestoClient.ResourceServer` is built on the same process,
  so access-token and ID Token verification share one cache and one refresh
  logic.

  ## Example

      children = [
        {AttestoClient.Issuer,
         name: MyApp.Issuer,
         issuer: "https://issuer.example",
         fresh_ttl: :timer.minutes(5),
         stale_ttl: :timer.hours(1)}
      ]

      :ok = AttestoClient.Issuer.warm(MyApp.Issuer)

      {:ok, claims} =
        AttestoClient.IDToken.verify(id_token,
          issuer: {AttestoClient.Issuer, MyApp.Issuer},
          client_id: "my-client",
          nonce: nonce
        )

  `issuer: {AttestoClient.Issuer, name}` is accepted wherever those functions
  take an `:issuer` string: `AttestoClient.IDToken.verify/2`,
  `AttestoClient.AuthorizationCode.start/2` and `callback/3`, and
  `AttestoClient.Token.refresh/4`. The issuer identifier compared with the ID
  Token's `iss` and the RFC 9207 response `iss` is the one this process was
  started with. A process started by `AttestoClient.ResourceServer` can be
  named the same way, so one process per issuer serves both kinds of token.

  ## Options

    * `:issuer` - required. The HTTPS issuer identifier.
    * `:name` - a `GenServer` name for the process.
    * `:well_known` - which discovery document to fetch; defaults to
      `:openid_configuration`.
    * `:metadata` - discovery metadata supplied by the caller, used in place
      of a discovery fetch.
    * `:jwks_uri` - fetch only the JWKS from this URI. With `:jwks_uri` and no
      `:metadata` the process holds no discovery metadata, and `metadata/1`
      returns `{:error, :metadata_unavailable}`.
    * `:accepted_algs` - a fetched JWKS must hold at least one key usable with
      one of these algorithms. Defaults to every algorithm Attesto verifies.
    * `:fresh_ttl`, `:stale_ttl` - milliseconds; default 5 minutes and 1 hour.
      The stale interval starts when the fresh interval ends.
    * `:unknown_kid_refresh_interval` - milliseconds between refreshes caused
      by an unknown `kid`; default 30 seconds.
    * `:refresh_retry_interval` - milliseconds before a failed refresh is
      retried; default 5 seconds.
    * `:refresh_timeout` - milliseconds allowed for one metadata and JWKS
      fetch; default 15 seconds.
    * `:max_jwks_keys` - default 32. `:max_response_bytes` - default 512 KiB.
    * `:req_options` - options for the underlying `Req` request.

  ## Cache behavior

    * discovery metadata must report the configured issuer exactly, and
      metadata and JWKS are fetched only over HTTPS with redirects disabled;
    * concurrent callers that need a refresh share one fetch;
    * an unknown `kid` causes at most one refresh per cache generation and
      `:unknown_kid_refresh_interval`, so random `kid` values cannot cause a
      fetch per request;
    * stale keys are used only within `:stale_ttl` and only after a transient
      refresh failure (transport error, timeout, 429, or 5xx);
    * every refresh failure starts a `:refresh_retry_interval` cooldown, so a
      persistent failure does not make every verification wait on the issuer.
      Before the first successful fetch, verification returns the remembered
      error until the cooldown ends, while `warm/1` and `refresh/1` still
      fetch.

  Signature and claim verification run in the calling process. The process
  owns only the cache and the refresh coordination.
  """

  use GenServer

  alias Attesto.SigningAlg
  alias AttestoClient.{Discovery, Verifier}
  alias AttestoClient.Issuer.Cache

  @default_fresh_ttl :timer.minutes(5)
  @default_stale_ttl :timer.hours(1)
  @default_unknown_kid_refresh_interval :timer.seconds(30)
  @default_refresh_retry_interval :timer.seconds(5)
  @default_refresh_timeout :timer.seconds(15)
  @default_max_jwks_keys 32
  @default_max_response_bytes 512 * 1024

  @type server :: GenServer.server()

  @typedoc "The value of an `:issuer` option that names an issuer cache."
  @type ref :: {__MODULE__, server()}

  @type start_opt ::
          {:name, GenServer.name()}
          | {:issuer, String.t()}
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
          | {:max_jwks_keys, pos_integer()}
          | {:max_response_bytes, pos_integer()}

  @type refresh_error :: {:jwks_refresh_failed, term()}

  @doc "Start a supervised issuer cache."
  @spec start_link([start_opt()]) :: GenServer.on_start()
  def start_link(opts) when is_list(opts) do
    accepted_algs =
      accepted_algs!(Keyword.get(opts, :accepted_algs, SigningAlg.allowed()), "Issuer")

    opts
    |> config!("Issuer")
    |> Map.put(:accepted_algs, accepted_algs)
    |> start_server(opts)
  end

  def child_spec(opts) do
    %{
      id: Keyword.get(opts, :name, {__MODULE__, Keyword.get(opts, :issuer)}),
      start: {__MODULE__, :start_link, [opts]},
      type: :worker,
      restart: :permanent,
      shutdown: 5_000
    }
  end

  @doc "Return the issuer identifier the cache was started with."
  @spec issuer(server()) :: {:ok, String.t()} | {:error, refresh_error()}
  def issuer(server) do
    {:ok, GenServer.call(server, :issuer)}
  catch
    :exit, reason -> {:error, {:jwks_refresh_failed, call_exit_reason(reason)}}
  end

  @doc """
  Return the issuer's discovery metadata, fetching it when the cache has none
  that is usable.
  """
  @spec metadata(server()) ::
          {:ok, map()} | {:error, :metadata_unavailable | refresh_error()}
  def metadata(server) do
    case snapshot(server) do
      {:ok, %{metadata: %{} = metadata}} -> {:ok, metadata}
      {:ok, _snapshot} -> {:error, :metadata_unavailable}
      {:error, _reason} = error -> error
    end
  end

  @doc """
  Return the issuer's verification keys, fetching them when the cache has none
  that are usable.
  """
  @spec keys(server()) :: {:ok, [map()]} | {:error, refresh_error()}
  def keys(server) do
    with {:ok, snapshot} <- snapshot(server), do: {:ok, snapshot.keys}
  end

  @doc "Warm the cache by completing metadata/JWKS retrieval."
  @spec warm(server()) :: :ok | {:error, refresh_error()}
  def warm(server), do: refresh(server)

  @doc "Return whether the cache holds a currently usable key snapshot."
  @spec ready?(server()) :: boolean()
  def ready?(server) do
    Cache.usable?(GenServer.call(server, :snapshot), monotonic_ms())
  catch
    :exit, _reason -> false
  end

  @doc "Force a metadata/JWKS refresh."
  @spec refresh(server()) :: :ok | {:error, refresh_error()}
  def refresh(server) do
    snapshot = GenServer.call(server, :snapshot)
    generation = if snapshot, do: snapshot.generation

    case request_refresh(server, generation, :forced) do
      {:ok, _snapshot} -> :ok
      {:error, reason} -> {:error, {:jwks_refresh_failed, reason}}
    end
  catch
    :exit, reason -> {:error, {:jwks_refresh_failed, call_exit_reason(reason)}}
  end

  @doc false
  # The usable snapshot: fresh, or stale under the rules in the moduledoc,
  # refreshing first when the cache is empty or expired.
  @spec snapshot(server()) :: {:ok, Cache.snapshot()} | {:error, refresh_error()}
  def snapshot(server) do
    snapshot = GenServer.call(server, :snapshot)
    now = monotonic_ms()

    result =
      case Cache.lookup(snapshot, now) do
        {:refresh, generation, :initial} ->
          request_refresh(server, generation, :initial)

        {:refresh, generation, :expired} ->
          with {:error, reason} <- request_refresh(server, generation, :expired),
               do: Cache.stale_fallback(snapshot, now, reason)

        result ->
          result
      end

    with {:error, reason} <- result, do: {:error, {:jwks_refresh_failed, reason}}
  catch
    :exit, reason -> {:error, {:jwks_refresh_failed, call_exit_reason(reason)}}
  end

  @doc false
  # Run `fun` against the usable snapshot. When it answers
  # `{:error, :invalid_signature}` and `token` names a `kid` the snapshot does
  # not hold, ask for one coordinated refresh and run `fun` once more against
  # the refreshed snapshot. `fun`'s result is returned as is.
  @spec verify(server(), String.t(), (Cache.snapshot() -> result)) ::
          result | {:error, refresh_error()}
        when result: term()
  def verify(server, token, fun) when is_binary(token) and is_function(fun, 1) do
    with {:ok, snapshot} <- snapshot(server) do
      retry_unknown_kid(server, snapshot, token, fun, fun.(snapshot))
    end
  catch
    :exit, reason -> {:error, {:jwks_refresh_failed, call_exit_reason(reason)}}
  end

  @doc false
  # Replace `issuer: {AttestoClient.Issuer, server}` with the issuer string the
  # process was started with, and record the process under `:issuer_cache`.
  # With any other `:issuer`, a caller-supplied `:issuer_cache` is dropped, so
  # the keys of one issuer's cache are never applied to another issuer.
  @spec expand_option(keyword()) :: {:ok, keyword()} | {:error, refresh_error()}
  def expand_option(opts) when is_list(opts) do
    case Keyword.fetch(opts, :issuer) do
      {:ok, {__MODULE__, server}} ->
        with {:ok, issuer} <- issuer(server) do
          {:ok, opts |> Keyword.put(:issuer, issuer) |> Keyword.put(:issuer_cache, server)}
        end

      _string_or_absent ->
        {:ok, Keyword.delete(opts, :issuer_cache)}
    end
  end

  @doc false
  # The `:issuer` value to hand on to another function taking the option: the
  # cache reference when `expand_option/1` recorded one, the string otherwise.
  @spec option(keyword(), String.t()) :: String.t() | ref()
  def option(opts, issuer) when is_list(opts) and is_binary(issuer) do
    case Keyword.get(opts, :issuer_cache) do
      nil -> issuer
      server -> {__MODULE__, server}
    end
  end

  @doc false
  # `AttestoClient.Verifier.resolve_jwks/2`, taking the keys from the cache
  # when `expand_option/1` recorded one and the caller supplied no `:jwks`.
  @spec resolve_jwks(keyword(), String.t()) :: {:ok, [map()]} | {:error, term()}
  def resolve_jwks(opts, issuer) do
    case cache(opts) do
      nil -> Verifier.resolve_jwks(opts, issuer)
      server -> keys(server)
    end
  end

  @doc false
  # Verify `jwt`'s signature against the issuer's keys: the caller's `:jwks`,
  # the cache (with a refresh on an unknown `kid`), or a one-off fetch.
  @spec verify_signature(String.t(), keyword(), String.t(), [SigningAlg.alg()], keyword()) ::
          {:ok, map(), map(), JOSE.JWK.t()} | {:error, term()}
  def verify_signature(jwt, opts, issuer, accepted_algs, verify_opts) do
    case cache(opts) do
      nil ->
        with {:ok, jwks} <- Verifier.resolve_jwks(opts, issuer),
             do: Verifier.verify_signature(jwt, jwks, accepted_algs, verify_opts)

      server ->
        verify(server, jwt, &Verifier.verify_signature(jwt, &1.keys, accepted_algs, verify_opts))
    end
  end

  defp cache(opts) do
    if Keyword.has_key?(opts, :jwks), do: nil, else: Keyword.get(opts, :issuer_cache)
  end

  @doc false
  # Validate the cache options. `label` names the module in error messages, so
  # `AttestoClient.ResourceServer` reports its own name for options it passes
  # through.
  @spec config!(keyword(), String.t()) :: map()
  def config!(opts, label) when is_list(opts) and is_binary(label) do
    refresh_timeout = positive_integer!(opts, :refresh_timeout, @default_refresh_timeout, label)

    %{
      issuer: required_https_issuer!(Keyword.get(opts, :issuer), label),
      fresh_ttl: non_negative_integer!(opts, :fresh_ttl, @default_fresh_ttl, label),
      jwks_uri: optional_string!(opts, :jwks_uri, label),
      max_jwks_keys: positive_integer!(opts, :max_jwks_keys, @default_max_jwks_keys, label),
      max_response_bytes:
        positive_integer!(opts, :max_response_bytes, @default_max_response_bytes, label),
      metadata: optional_map!(opts, :metadata, label),
      private: nil,
      refresh_retry_interval:
        non_negative_integer!(
          opts,
          :refresh_retry_interval,
          @default_refresh_retry_interval,
          label
        ),
      refresh_timeout: refresh_timeout,
      req_options: req_options!(opts, refresh_timeout, label),
      stale_ttl: non_negative_integer!(opts, :stale_ttl, @default_stale_ttl, label),
      unknown_kid_refresh_interval:
        non_negative_integer!(
          opts,
          :unknown_kid_refresh_interval,
          @default_unknown_kid_refresh_interval,
          label
        ),
      well_known: Keyword.get(opts, :well_known, :openid_configuration)
    }
  end

  @doc false
  @spec accepted_algs!(term(), String.t()) :: [SigningAlg.alg()]
  def accepted_algs!(algs, label) when is_list(algs) and algs != [] do
    if Enum.all?(algs, &(&1 in SigningAlg.allowed())),
      do: Enum.uniq(algs),
      else: raise(ArgumentError, "#{label} :accepted_algs contains an unsupported algorithm")
  end

  def accepted_algs!(_invalid, label),
    do: raise(ArgumentError, "#{label} requires :accepted_algs as a non-empty list")

  @doc false
  # Start the process from a validated config. `config.private` is an opaque
  # term carried on every snapshot; `AttestoClient.ResourceServer` keeps its
  # token policy there, so one call returns the keys and the policy together.
  @spec start_server(map(), keyword()) :: GenServer.on_start()
  def start_server(config, opts) when is_map(config) and is_list(opts) do
    case Keyword.fetch(opts, :name) do
      {:ok, name} -> GenServer.start_link(__MODULE__, config, name: name)
      :error -> GenServer.start_link(__MODULE__, config)
    end
  end

  @impl true
  def init(config) do
    Process.flag(:trap_exit, true)

    {:ok, %{config: config, cache: Cache.new(config), task: nil, timer: nil, waiters: []}}
  end

  @impl true
  def handle_call(:snapshot, _from, state), do: {:reply, state.cache.snapshot, state}
  def handle_call(:issuer, _from, state), do: {:reply, state.config.issuer, state}

  def handle_call(:refresh_timeout, _from, state),
    do: {:reply, state.config.refresh_timeout, state}

  def handle_call({:refresh, observed_generation, reason}, from, state) do
    case Cache.admit(state.cache, observed_generation, reason, monotonic_ms(), state.task != nil) do
      {:reply, reply} ->
        {:reply, reply, state}

      :join ->
        {:noreply, %{state | waiters: [from | state.waiters]}}

      {:fetch, cache} ->
        config = state.config
        task = Task.async(fn -> fetch(config) end)
        timer = Process.send_after(self(), {:refresh_deadline, task.ref}, config.refresh_timeout)

        {:noreply, %{state | cache: cache, task: task, timer: timer, waiters: [from]}}
    end
  end

  @impl true
  def handle_info({ref, result}, %{task: %Task{ref: ref} = task} = state) do
    Process.demonitor(task.ref, [:flush])
    cancel_timer(state.timer)
    {:noreply, finish_fetch(state, result)}
  end

  def handle_info({:DOWN, ref, :process, _pid, reason}, %{task: %Task{ref: ref}} = state) do
    cancel_timer(state.timer)
    {:noreply, finish_fetch(state, {:error, {:refresh_task_exit, reason}})}
  end

  def handle_info({:refresh_deadline, ref}, %{task: %Task{ref: ref} = task} = state) do
    _ = Task.shutdown(task, :brutal_kill)
    {:noreply, finish_fetch(state, {:error, :refresh_timeout})}
  end

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, %{task: %Task{} = task}) do
    Task.shutdown(task, :brutal_kill)
    :ok
  end

  def terminate(_reason, _state), do: :ok

  defp finish_fetch(state, result) do
    {reply, cache} = apply_fetch_result(result, state.cache)
    Enum.each(state.waiters, &GenServer.reply(&1, reply))
    %{state | cache: cache, task: nil, timer: nil, waiters: []}
  end

  defp apply_fetch_result({:ok, content}, cache) do
    {snapshot, cache} = Cache.put(cache, content, monotonic_ms())
    {{:ok, snapshot}, cache}
  end

  defp apply_fetch_result({:error, reason}, cache),
    do: {{:error, reason}, Cache.fail(cache, reason, monotonic_ms())}

  defp apply_fetch_result(other, cache), do: {{:error, {:invalid_fetch_result, other}}, cache}

  defp retry_unknown_kid(server, snapshot, token, fun, {:error, :invalid_signature} = error) do
    if Cache.unknown_kid?(snapshot, kid(token)) do
      case request_refresh(server, snapshot.generation, :unknown_kid) do
        {:ok, refreshed} -> fun.(refreshed)
        {:error, _reason} -> error
      end
    else
      error
    end
  end

  defp retry_unknown_kid(_server, _snapshot, _token, _fun, result), do: result

  defp kid(token) do
    case Verifier.peek_header(token) do
      {:ok, %{"kid" => kid}} -> kid
      _other -> nil
    end
  end

  defp request_refresh(server, generation, reason) do
    GenServer.call(server, {:refresh, generation, reason}, refresh_call_timeout(server))
  catch
    :exit, exit_reason -> {:error, call_exit_reason(exit_reason)}
  end

  defp refresh_call_timeout(server), do: GenServer.call(server, :refresh_timeout) + 1_000

  # Runs in the refresh task. The result is the content of the next snapshot.
  defp fetch(config) do
    with {:ok, metadata, jwks_uri} <- resolve_jwks_uri(config),
         {:ok, jwks} <- Discovery.fetch_jwks(jwks_uri, discovery_opts(config)),
         {:ok, keys} <- Verifier.normalize_jwks(jwks),
         :ok <- check_key_bound(keys, config.max_jwks_keys),
         :ok <- Verifier.validate_verification_keys(keys, config.accepted_algs) do
      {:ok, %{issuer: config.issuer, keys: keys, metadata: metadata, private: config.private}}
    end
  rescue
    error -> {:error, {:transport, Exception.message(error)}}
  catch
    kind, reason -> {:error, {:transport, {kind, reason}}}
  end

  defp resolve_jwks_uri(%{jwks_uri: uri, metadata: metadata}) when is_binary(uri),
    do: {:ok, metadata, uri}

  defp resolve_jwks_uri(%{metadata: %{} = metadata, issuer: issuer}) do
    with {:ok, uri} <- Discovery.jwks_uri(metadata, issuer), do: {:ok, metadata, uri}
  end

  defp resolve_jwks_uri(config) do
    with {:ok, metadata} <- Discovery.fetch(config.issuer, discovery_opts(config)),
         {:ok, uri} <- Discovery.jwks_uri(metadata, config.issuer) do
      {:ok, metadata, uri}
    end
  end

  defp discovery_opts(config) do
    [
      well_known: config.well_known,
      req_options: config.req_options,
      max_response_bytes: config.max_response_bytes,
      # The refresh timer owns the whole metadata/JWKS cycle. Keep Discovery's
      # defensive deadline outside it rather than reusing the much shorter
      # per-socket phase timeout from req_options.
      timeout: config.refresh_timeout + 1_000
    ]
  end

  defp check_key_bound(keys, max) when keys != [] and length(keys) <= max, do: :ok
  defp check_key_bound(_keys, _max), do: {:error, :invalid_jwks}

  defp required_https_issuer!(issuer, label) do
    case Discovery.validate_issuer_identifier(issuer) do
      :ok -> issuer
      {:error, _reason} -> raise ArgumentError, "#{label} requires an HTTPS :issuer"
    end
  end

  defp optional_string!(opts, key, label) do
    case Keyword.get(opts, key) do
      nil -> nil
      value when is_binary(value) and value != "" -> value
      _invalid -> raise ArgumentError, "#{label} #{inspect(key)} must be a non-empty string"
    end
  end

  defp optional_map!(opts, key, label) do
    case Keyword.get(opts, key) do
      nil -> nil
      %{} = value -> value
      _invalid -> raise ArgumentError, "#{label} #{inspect(key)} must be a map"
    end
  end

  defp req_options!(opts, refresh_timeout, label) do
    case Keyword.get(opts, :req_options, []) do
      req_options when is_list(req_options) ->
        phase_timeout = max(div(max(refresh_timeout - 1_000, 1), 4), 1)
        connect_options = connect_options!(req_options, phase_timeout, label)

        req_options
        |> Keyword.put(:retry, false)
        |> Keyword.put(:receive_timeout, phase_timeout)
        |> Keyword.put(:connect_options, connect_options)
        |> Keyword.put(:compressed, false)

      _invalid ->
        raise ArgumentError, "#{label} :req_options must be a keyword list"
    end
  end

  defp connect_options!(req_options, timeout, label) do
    case Keyword.get(req_options, :connect_options, []) do
      connect_options when is_list(connect_options) ->
        Keyword.put(connect_options, :timeout, timeout)

      _invalid ->
        raise ArgumentError, "#{label} :connect_options must be a keyword list"
    end
  end

  defp positive_integer!(opts, key, default, label) do
    case Keyword.get(opts, key, default) do
      value when is_integer(value) and value > 0 -> value
      _invalid -> raise ArgumentError, "#{label} #{inspect(key)} must be a positive integer"
    end
  end

  defp non_negative_integer!(opts, key, default, label) do
    case Keyword.get(opts, key, default) do
      value when is_integer(value) and value >= 0 ->
        value

      _invalid ->
        raise ArgumentError, "#{label} #{inspect(key)} must be a non-negative integer"
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
end
