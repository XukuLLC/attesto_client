defmodule AttestoClient.MCPAuthorization do
  @moduledoc """
  MCP authorization policy over the generic OAuth client primitives.

  This module implements the authorization requirements of MCP 2026-07-28
  without introducing an MCP authorization profile. The existing profiles
  bind OAuth security bundles such as HAIP and FAPI; MCP
  instead coordinates protected-resource discovery, authorization-server
  discovery, registration selection, scope escalation, and Bearer token use.

  `discover/2` follows an RFC 9728 `resource_metadata` challenge pointer when
  present. Otherwise it tries the path-specific Protected Resource Metadata
  URL and then the origin-root URL. It follows the advertised issuer through
  all required RFC 8414 / OpenID Connect metadata candidates, validates exact
  resource and issuer identity, and requires an explicit S256 PKCE capability.

  Client registrations remain application data. `select_registration/2`
  chooses, in order, a registration already bound to the selected issuer, a
  pre-registration for that issuer, a validated Client ID Metadata Document,
  opt-in Dynamic Client Registration, then a host prompt callback. It never
  sends credentials to an issuer other than the one they are bound to. The
  returned `Registration` is what the host persists.

  `start/4`, `callback/5`, and `refresh/6` delegate the OAuth wire operations
  to `AttestoClient.AuthorizationCode` and `AttestoClient.Token`. They pin the
  discovered issuer and metadata, send the MCP resource on authorization and
  token requests, retain requested scopes when the token response omits them,
  and accept only Bearer access tokens. This package does not implement the MCP
  JSON-RPC transport; `authorization_header/2` and `step_up/3` provide the
  transport-facing policy points.
  """

  alias Attesto.ClientIdMetadata
  alias AttestoClient.AuthorizationCode
  alias AttestoClient.Discovery
  alias AttestoClient.DynamicClientRegistration
  alias AttestoClient.MCPAuthorization.Registration
  alias AttestoClient.RefreshResult
  alias AttestoClient.Token
  alias AttestoClient.TokenSet
  alias AttestoClient.WWWAuthenticate

  @default_scope_retries 2

  @enforce_keys [
    :resource,
    :resource_metadata,
    :issuer,
    :authorization_server,
    :scopes
  ]
  @derive {Inspect, only: [:resource, :issuer, :scopes, :scope_attempts]}
  defstruct @enforce_keys ++ [scope_attempts: 0]

  @type t :: %__MODULE__{
          resource: String.t(),
          resource_metadata: map(),
          issuer: String.t(),
          authorization_server: map(),
          scopes: [String.t()],
          scope_attempts: non_neg_integer()
        }

  @type error ::
          :authorization_server_changed
          | :client_registration_required
          | :invalid_client_id_metadata
          | :invalid_client_metadata
          | :invalid_dynamic_registration
          | :invalid_offline_access
          | :invalid_pre_registered_clients
          | :invalid_prompt
          | :invalid_registration
          | :invalid_registration_response
          | :invalid_scope_retry_limit
          | :invalid_scopes
          | :missing_pkce_support
          | :not_insufficient_scope
          | :scope_retry_limit
          | :token_binding_mismatch
          | :unsupported_token_endpoint_auth_method
          | :unsupported_token_type
          | Discovery.error()
          | term()

  @doc """
  Discover and validate the authorization context for an MCP `resource`.

  Discovery and transport options are those of
  `AttestoClient.Discovery.authorization_server/2`. `:www_authenticate` may
  carry both the Protected Resource Metadata pointer and an initial `scope`.
  `offline_access: true` requests refresh-token access only when the selected
  authorization server advertises that scope; otherwise it is omitted.
  """
  @spec discover(String.t(), keyword()) :: {:ok, t()} | {:error, error()}
  def discover(resource, opts \\ [])

  def discover(resource, opts) when is_binary(resource) and is_list(opts) do
    with :ok <- AttestoClient.Outbound.validate(opts),
         opts = bearer_challenge_options(opts),
         {:ok, offline_access?} <- offline_access(opts),
         {:ok, resolution} <- discover_resolution(resource, opts),
         :ok <- validate_mcp_metadata(resolution, opts),
         {:ok, scopes} <- initial_scopes(resolution, opts, offline_access?) do
      {:ok,
       %__MODULE__{
         resource: Map.fetch!(resolution.resource, "resource"),
         resource_metadata: resolution.resource,
         issuer: resolution.issuer,
         authorization_server: resolution.authorization_server,
         scopes: scopes
       }}
    end
  end

  def discover(_resource, _opts), do: {:error, :invalid_resource}

  @doc """
  Select client registration for a discovered authorization server.

  Options:

    * `:registration` - a previously persisted `Registration`.
    * `:pre_registered` - a map keyed by exact issuer. Values carry
      `:client_id` and optional `:client_auth` (default `:none`).
    * `:client_id_metadata` - a map carrying `:client_id`, the decoded
      `:document`, and optional `:client_auth`. It is considered only when the
      server advertises `client_id_metadata_document_supported: true`.
    * `:dynamic_registration` - opt in with a keyword list or map containing
      `:client_name`, non-empty `:redirect_uris`, and `:application_type`
      (`:native`, `:web`, or the corresponding string). The registration
      endpoint is used only when advertised by the selected server.
    * `:prompt` - a two-arity callback receiving issuer and validated server
      metadata. It may return `{:ok, credentials}`, `credentials`, or `:error`.

  The priority is existing/current pre-registration, configured
  pre-registration, CIMD, dynamic registration, then prompt. Credentials are
  checked against the server's advertised token-endpoint authentication
  methods. Dynamic registration is intentionally opt-in because it creates
  state at the authorization server.
  """
  @spec select_registration(t(), keyword()) ::
          {:ok, Registration.t()} | {:error, error()}
  def select_registration(context, opts \\ [])

  def select_registration(%__MODULE__{} = context, opts) when is_list(opts) do
    previous = Keyword.get(opts, :registration)

    with :ok <- validate_optional_registration(previous),
         {:ok, pre_registered} <- pre_registered(opts),
         {:ok, result} <-
           choose_registration(context, previous, pre_registered, opts),
         :ok <- validate_auth_method(result, context.authorization_server) do
      {:ok, result}
    end
  end

  def select_registration(_context, _opts), do: {:error, :invalid_registration}

  @doc """
  Start MCP authorization with the selected registration.

  The context's resource, issuer, metadata and scopes, and the registration's
  client identity and authentication are authoritative. Remaining options are
  forwarded to `AttestoClient.AuthorizationCode.start/2`; notably the host
  supplies `:redirect_uri`, `:browser_binding`, transaction lifetime, storage,
  and transport configuration.
  """
  @spec start(t(), Registration.t(), AuthorizationCode.transaction_target(), keyword()) ::
          {:ok, map()} | {:error, term()}
  def start(%__MODULE__{} = context, %Registration{} = registration, store, opts)
      when is_list(opts) do
    with :ok <- registration_matches(context, registration),
         :ok <- validate_auth_method(registration, context.authorization_server),
         :ok <- reject_dpop_option(opts) do
      AuthorizationCode.start(store, oauth_options(context, registration, opts))
    end
  end

  def start(_context, _registration, _store, _opts), do: {:error, :invalid_registration}

  @doc """
  Complete MCP authorization and require a Bearer access token.

  Callback validation, including exact authorization-response issuer checking
  before code redemption, is performed by `AuthorizationCode.callback/3`.
  """
  @spec callback(
          t(),
          Registration.t(),
          AuthorizationCode.transaction_target(),
          map() | String.t(),
          keyword()
        ) ::
          {:ok, %{tokens: TokenSet.t(), id_token_claims: nil}} | {:error, term()}
  def callback(%__MODULE__{} = context, %Registration{} = registration, store, response, opts)
      when is_list(opts) do
    with :ok <- registration_matches(context, registration),
         :ok <- validate_auth_method(registration, context.authorization_server),
         :ok <- reject_dpop_option(opts),
         {:ok, result} <-
           AuthorizationCode.callback_bound(
             store,
             response,
             %{
               issuer: context.issuer,
               client_id: registration.client_id,
               protocol: :oauth,
               resources: [context.resource]
             },
             Keyword.put(opts, :client_auth, registration.client_auth)
           ),
         :ok <- bearer_token(result.tokens) do
      {:ok, result}
    end
  end

  def callback(_context, _registration, _store, _response, _opts),
    do: {:error, :invalid_registration}

  @doc """
  Refresh an MCP token through the generic single-flight coordinator.

  The plain OAuth mode skips OIDC subject and JWKS processing. The retained MCP
  resource is repeated, the registration stays issuer-bound, and a non-Bearer
  result is refused.
  """
  @spec refresh(t(), Registration.t(), GenServer.server(), term(), TokenSet.t(), keyword()) ::
          {:ok, RefreshResult.t()} | {:error, term()}
  def refresh(
        %__MODULE__{} = context,
        %Registration{} = registration,
        coordinator,
        key,
        %TokenSet{} = tokens,
        opts
      )
      when is_list(opts) do
    refresh_opts =
      opts
      |> Keyword.merge(
        protocol: :oauth,
        token_endpoint: context.authorization_server["token_endpoint"],
        issuer: context.issuer,
        client_id: registration.client_id,
        client_auth: registration.client_auth,
        resource: context.resource
      )

    with :ok <- registration_matches(context, registration),
         :ok <- validate_auth_method(registration, context.authorization_server),
         :ok <- token_matches(context, registration, tokens),
         :ok <- bearer_token(tokens),
         :ok <- reject_dpop_option(opts),
         {:ok, %RefreshResult{} = result} <-
           Token.refresh(coordinator, key, tokens, refresh_opts),
         :ok <- bearer_token(result.tokens) do
      {:ok, result}
    end
  end

  def refresh(_context, _registration, _coordinator, _key, _tokens, _opts),
    do: {:error, :invalid_registration}

  @doc """
  Build the only Authorization header permitted by core MCP authorization.

  The token type is compared case-insensitively as OAuth requires, while the
  emitted scheme uses the registered `Bearer` spelling. The token set must be
  retained for this context's exact issuer and sole MCP resource; this prevents
  accidentally sending one server's token to another server.
  """
  @spec authorization_header(t(), TokenSet.t()) ::
          {:ok, {String.t(), String.t()}}
          | {:error, :unsupported_token_type | :token_binding_mismatch}
  def authorization_header(%__MODULE__{} = context, %TokenSet{} = tokens) do
    with :ok <- token_matches_context(context, tokens),
         :ok <- bearer_token(tokens) do
      {:ok, {"authorization", "Bearer " <> tokens.access_token}}
    end
  end

  def authorization_header(_context, _tokens), do: {:error, :token_binding_mismatch}

  @doc """
  Apply one MCP insufficient-scope challenge to an authorization context.

  The challenged scopes are unioned with every scope previously requested.
  `:max_scope_retries` defaults to #{@default_scope_retries}; once reached, the
  result is `{:error, :scope_retry_limit}`. A challenge without
  `error="insufficient_scope"` and a valid non-empty `scope` is not acted on.
  """
  @spec step_up(t(), String.t() | [String.t()], keyword()) ::
          {:ok, t()} | {:error, error()}
  def step_up(context, www_authenticate, opts \\ [])

  def step_up(%__MODULE__{} = context, www_authenticate, opts) when is_list(opts) do
    with {:ok, limit} <- scope_retry_limit(opts),
         :ok <- below_scope_retry_limit(context.scope_attempts, limit),
         {:ok, challenged} <- insufficient_scope_challenge(www_authenticate) do
      {:ok,
       %{
         context
         | scopes: ordered_union(context.scopes, challenged),
           scope_attempts: context.scope_attempts + 1
       }}
    end
  end

  def step_up(_context, _www_authenticate, _opts), do: {:error, :invalid_scopes}

  defp discover_resolution(resource, opts) do
    opts =
      if root_fallback?(opts),
        do: Keyword.put(opts, :resource_well_known, :path_then_root),
        else: opts

    Discovery.authorization_server(resource, opts)
  end

  defp root_fallback?(opts) do
    not Keyword.has_key?(opts, :metadata_url) and
      not Keyword.has_key?(opts, :resource_well_known) and
      not challenge_metadata_pointer?(Keyword.get(opts, :www_authenticate, []), opts)
  end

  defp challenge_metadata_pointer?(headers, opts) do
    match?(
      {:ok, _url},
      WWWAuthenticate.resource_metadata(headers,
        allow_loopback_http: AttestoClient.Outbound.allow_loopback_http?(opts)
      )
    )
  end

  defp bearer_challenge_options(opts) do
    case Keyword.fetch(opts, :www_authenticate) do
      :error ->
        opts

      {:ok, headers} ->
        challenges = headers |> WWWAuthenticate.parse() |> Enum.filter(&(&1.scheme == "bearer"))
        Keyword.put(opts, :www_authenticate, challenges)
    end
  end

  defp validate_mcp_metadata(resolution, opts) do
    validation_opts =
      opts
      |> Keyword.take([:outbound])
      |> Keyword.put(:protocol, :oauth)

    with :ok <- require_s256(resolution.authorization_server),
         {:ok, _metadata} <-
           Discovery.validate_metadata(
             resolution.authorization_server,
             resolution.issuer,
             validation_opts
           ),
         do: :ok
  end

  defp require_s256(%{"code_challenge_methods_supported" => methods})
       when is_list(methods) do
    if "S256" in methods, do: :ok, else: {:error, :missing_pkce_support}
  end

  defp require_s256(_metadata), do: {:error, :missing_pkce_support}

  defp offline_access(opts) do
    case Keyword.get(opts, :offline_access, false) do
      value when is_boolean(value) -> {:ok, value}
      _invalid -> {:error, :invalid_offline_access}
    end
  end

  defp initial_scopes(resolution, opts, offline_access?) do
    with {:ok, selected} <- challenge_or_resource_scopes(resolution.resource, opts),
         {:ok, selected} <- validate_scopes(selected) do
      {:ok, maybe_offline_access(selected, resolution.authorization_server, offline_access?)}
    end
  end

  defp challenge_or_resource_scopes(resource_metadata, opts) do
    case WWWAuthenticate.bearer_scopes(Keyword.get(opts, :www_authenticate, [])) do
      {:ok, scopes} -> {:ok, scopes}
      :none -> {:ok, Map.get(resource_metadata, "scopes_supported", [])}
      {:error, :invalid_scope} -> {:error, :invalid_scopes}
    end
  end

  defp validate_scopes(scopes) when is_list(scopes) do
    if Enum.all?(scopes, &Attesto.Scope.valid_token?/1),
      do: {:ok, Enum.uniq(scopes)},
      else: {:error, :invalid_scopes}
  end

  defp validate_scopes(_invalid), do: {:error, :invalid_scopes}

  defp maybe_offline_access(scopes, _metadata, false), do: scopes

  defp maybe_offline_access(scopes, metadata, true) do
    case Map.get(metadata, "scopes_supported", []) do
      supported when is_list(supported) ->
        if "offline_access" in supported,
          do: ordered_union(scopes, ["offline_access"]),
          else: scopes

      _invalid ->
        scopes
    end
  end

  defp validate_optional_registration(nil), do: :ok
  defp validate_optional_registration(%Registration{}), do: :ok
  defp validate_optional_registration(_invalid), do: {:error, :invalid_registration}

  defp pre_registered(opts) do
    case Keyword.get(opts, :pre_registered, %{}) do
      nil -> {:ok, %{}}
      registrations when is_map(registrations) -> {:ok, registrations}
      _invalid -> {:error, :invalid_pre_registered_clients}
    end
  end

  defp choose_registration(
         context,
         %Registration{issuer: issuer, source: :client_id_metadata} = registration,
         pre_registered,
         opts
       )
       when issuer == context.issuer do
    if cimd_supported?(context.authorization_server),
      do: portable_cimd_registration(registration, context.issuer),
      else: choose_new_registration(context, registration, pre_registered, opts)
  end

  defp choose_registration(context, %Registration{issuer: issuer} = registration, _pre, _opts)
       when issuer == context.issuer do
    {:ok, registration}
  end

  defp choose_registration(context, previous, pre_registered, opts),
    do: choose_new_registration(context, previous, pre_registered, opts)

  defp choose_new_registration(context, previous, pre_registered, opts) do
    case Map.fetch(pre_registered, context.issuer) do
      {:ok, credentials} ->
        build_registration(credentials, context.issuer, :pre_registered)

      :error ->
        choose_cimd_or_dynamic_or_prompt(context, previous, opts)
    end
  end

  defp choose_cimd_or_dynamic_or_prompt(context, previous, opts) do
    cond do
      cimd_supported?(context.authorization_server) and
          match?(%Registration{source: :client_id_metadata}, previous) ->
        portable_cimd_registration(previous, context.issuer)

      cimd_supported?(context.authorization_server) and
          not is_nil(Keyword.get(opts, :client_id_metadata)) ->
        build_cimd_registration(Keyword.get(opts, :client_id_metadata), context.issuer)

      true ->
        choose_dynamic_or_prompt(context, previous, opts)
    end
  end

  defp choose_dynamic_or_prompt(context, previous, opts) do
    case Keyword.get(opts, :dynamic_registration) do
      nil ->
        choose_prompt(context, previous, opts)

      config ->
        case Map.get(context.authorization_server, "registration_endpoint") do
          endpoint when is_binary(endpoint) and endpoint != "" ->
            register_dynamic(context, endpoint, config, opts)

          _missing ->
            choose_prompt(context, previous, opts)
        end
    end
  end

  defp register_dynamic(context, endpoint, config, opts) do
    with :ok <- AttestoClient.Outbound.validate(opts),
         :ok <- AttestoClient.Outbound.check_issuer(context.issuer, opts),
         {:ok, config} <- dynamic_registration_config(config),
         {:ok, auth_method} <- dynamic_auth_method(config, context.authorization_server),
         metadata = dynamic_client_metadata(config, auth_method),
         {:ok, response} <-
           DynamicClientRegistration.register(
             endpoint,
             metadata,
             opts
             |> dynamic_transport_options()
             |> Keyword.put(:issuer, context.issuer)
           ),
         do: dynamic_registration(context.issuer, response, auth_method)
  end

  defp dynamic_registration_config(config) when is_list(config) do
    if Keyword.keyword?(config) and Enum.uniq_by(config, &elem(&1, 0)) == config,
      do: dynamic_registration_config(Map.new(config)),
      else: {:error, :invalid_dynamic_registration}
  end

  defp dynamic_registration_config(config) when is_map(config) do
    client_name = field(config, :client_name)
    redirect_uris = field(config, :redirect_uris)
    application_type = field(config, :application_type)
    requested_auth_method = field(config, :token_endpoint_auth_method)

    with true <- is_binary(client_name) and client_name != "" and String.valid?(client_name),
         {:ok, application_type} <- dynamic_application_type(application_type),
         {:ok, redirect_uris} <- dynamic_redirect_uris(redirect_uris, application_type),
         :ok <- optional_dynamic_auth_method(requested_auth_method) do
      {:ok,
       %{
         client_name: client_name,
         redirect_uris: redirect_uris,
         application_type: application_type,
         token_endpoint_auth_method: requested_auth_method
       }}
    else
      _invalid -> {:error, :invalid_dynamic_registration}
    end
  end

  defp dynamic_registration_config(_config), do: {:error, :invalid_dynamic_registration}

  defp dynamic_redirect_uris(uris, application_type) when is_list(uris) and uris != [] do
    if Enum.all?(uris, &valid_redirect_uri?(&1, application_type)),
      do: {:ok, Enum.uniq(uris)},
      else: {:error, :invalid_dynamic_registration}
  end

  defp dynamic_redirect_uris(_uris, _application_type),
    do: {:error, :invalid_dynamic_registration}

  defp valid_redirect_uri?(uri, "native"),
    do: Attesto.URI.https_identifier?(uri, allow_loopback_http: true)

  defp valid_redirect_uri?(uri, "web"), do: Attesto.URI.https_identifier?(uri)
  defp valid_redirect_uri?(_uri, _application_type), do: false

  defp dynamic_application_type(type) when type in [:native, "native"], do: {:ok, "native"}
  defp dynamic_application_type(type) when type in [:web, "web"], do: {:ok, "web"}
  defp dynamic_application_type(_type), do: {:error, :invalid_dynamic_registration}

  defp optional_dynamic_auth_method(nil), do: :ok

  defp optional_dynamic_auth_method(method)
       when method in ["none", "client_secret_basic", "client_secret_post"],
       do: :ok

  defp optional_dynamic_auth_method(_method), do: {:error, :invalid_dynamic_registration}

  defp dynamic_auth_method(%{token_endpoint_auth_method: requested}, metadata) do
    supported =
      Map.get(metadata, "token_endpoint_auth_methods_supported", ["client_secret_basic"])

    cond do
      not is_list(supported) ->
        {:error, :unsupported_token_endpoint_auth_method}

      is_binary(requested) and requested in supported ->
        {:ok, requested}

      is_binary(requested) ->
        {:error, :unsupported_token_endpoint_auth_method}

      true ->
        case Enum.find(["client_secret_basic", "client_secret_post", "none"], &(&1 in supported)) do
          nil -> {:error, :unsupported_token_endpoint_auth_method}
          method -> {:ok, method}
        end
    end
  end

  defp dynamic_client_metadata(config, auth_method) do
    %{
      "application_type" => config.application_type,
      "client_name" => config.client_name,
      "grant_types" => ["authorization_code", "refresh_token"],
      "redirect_uris" => config.redirect_uris,
      "response_types" => ["code"],
      "token_endpoint_auth_method" => auth_method
    }
  end

  defp dynamic_transport_options(opts) do
    Keyword.take(opts, [:timeout, :resolver, :outbound, :req_options])
  end

  defp dynamic_registration(issuer, %{"client_id" => client_id} = response, requested_method) do
    method = Map.get(response, "token_endpoint_auth_method", requested_method)

    with {:ok, client_auth} <- dynamic_client_auth(method, Map.get(response, "client_secret")) do
      {:ok,
       %Registration{
         issuer: issuer,
         client_id: client_id,
         client_auth: client_auth,
         source: :dynamic,
         metadata: %{"token_endpoint_auth_method" => method}
       }}
    end
  end

  defp dynamic_client_auth("none", _secret), do: {:ok, :none}

  defp dynamic_client_auth("client_secret_basic", secret)
       when is_binary(secret) and secret != "",
       do: {:ok, {:client_secret_basic, secret}}

  defp dynamic_client_auth("client_secret_post", secret)
       when is_binary(secret) and secret != "",
       do: {:ok, {:client_secret_post, secret}}

  defp dynamic_client_auth(_method, _secret), do: {:error, :invalid_registration_response}

  defp choose_prompt(context, previous, opts) do
    case Keyword.get(opts, :prompt) do
      nil ->
        if issuer_changed?(previous, context.issuer),
          do: {:error, :authorization_server_changed},
          else: {:error, :client_registration_required}

      prompt when is_function(prompt, 2) ->
        case prompt.(context.issuer, context.authorization_server) do
          {:ok, credentials} -> build_registration(credentials, context.issuer, :user)
          :error -> {:error, :client_registration_required}
          credentials -> build_registration(credentials, context.issuer, :user)
        end

      _invalid ->
        {:error, :invalid_prompt}
    end
  rescue
    _error -> {:error, :invalid_prompt}
  catch
    _kind, _reason -> {:error, :invalid_prompt}
  end

  defp issuer_changed?(%Registration{issuer: issuer}, selected), do: issuer != selected
  defp issuer_changed?(_registration, _selected), do: false

  defp build_registration(credentials, issuer, source) when is_map(credentials) do
    client_id = field(credentials, :client_id)
    client_auth = field(credentials, :client_auth, :none)

    if is_binary(client_id) and client_id != "" do
      {:ok,
       %Registration{
         issuer: issuer,
         client_id: client_id,
         client_auth: client_auth,
         source: source
       }}
    else
      {:error, :invalid_registration}
    end
  end

  defp build_registration(_credentials, _issuer, _source),
    do: {:error, :invalid_registration}

  defp build_cimd_registration(cimd, issuer) when is_map(cimd) do
    client_id = field(cimd, :client_id)
    document = field(cimd, :document)

    with true <- is_binary(client_id),
         true <- is_map(document),
         {:ok, _uri} <- ClientIdMetadata.validate_client_id(client_id),
         {:ok, metadata} <- ClientIdMetadata.validate_document(client_id, document),
         :ok <- require_cimd_client_name(metadata),
         {:ok, client_auth} <- cimd_client_auth(metadata, field(cimd, :client_auth, :none)) do
      {:ok,
       %Registration{
         issuer: issuer,
         client_id: client_id,
         client_auth: client_auth,
         source: :client_id_metadata,
         metadata: metadata
       }}
    else
      _invalid -> {:error, :invalid_client_id_metadata}
    end
  end

  defp build_cimd_registration(_cimd, _issuer), do: {:error, :invalid_client_id_metadata}

  defp portable_cimd_registration(%Registration{} = registration, issuer) do
    with true <- is_binary(registration.client_id),
         true <- is_map(registration.metadata),
         {:ok, _uri} <- ClientIdMetadata.validate_client_id(registration.client_id),
         {:ok, metadata} <-
           ClientIdMetadata.validate_document(registration.client_id, registration.metadata),
         :ok <- require_cimd_client_name(metadata),
         {:ok, client_auth} <- cimd_client_auth(metadata, registration.client_auth) do
      {:ok,
       %{
         registration
         | issuer: issuer,
           client_auth: client_auth,
           metadata: metadata
       }}
    else
      _invalid -> {:error, :invalid_client_id_metadata}
    end
  end

  defp require_cimd_client_name(%{"client_name" => name})
       when is_binary(name) and name != "",
       do: :ok

  defp require_cimd_client_name(_metadata), do: {:error, :invalid_client_id_metadata}

  defp cimd_client_auth(metadata, client_auth) do
    method = client_auth_method(client_auth)

    if method in ClientIdMetadata.auth_methods(metadata),
      do: {:ok, client_auth},
      else: {:error, :unsupported_token_endpoint_auth_method}
  end

  defp cimd_supported?(metadata),
    do: metadata["client_id_metadata_document_supported"] == true

  defp registration_matches(context, %Registration{issuer: issuer}) do
    if issuer == context.issuer,
      do: :ok,
      else: {:error, :authorization_server_changed}
  end

  defp validate_auth_method(%Registration{client_auth: client_auth}, metadata) do
    method = client_auth_method(client_auth)

    supported =
      Map.get(metadata, "token_endpoint_auth_methods_supported", ["client_secret_basic"])

    if is_binary(method) and is_list(supported) and method in supported,
      do: :ok,
      else: {:error, :unsupported_token_endpoint_auth_method}
  end

  defp client_auth_method(:none), do: "none"

  defp client_auth_method({:client_secret_basic, secret}) when is_binary(secret) and secret != "",
    do: "client_secret_basic"

  defp client_auth_method({:client_secret_post, secret}) when is_binary(secret) and secret != "",
    do: "client_secret_post"

  defp client_auth_method({:private_key_jwt, _key}), do: "private_key_jwt"

  defp client_auth_method({:private_key_jwt, _key, opts}) when is_list(opts),
    do: "private_key_jwt"

  defp client_auth_method(_invalid), do: nil

  defp field(map, key, default \\ nil) do
    Map.get(map, key, Map.get(map, Atom.to_string(key), default))
  end

  defp oauth_options(context, registration, opts) do
    Keyword.merge(opts,
      protocol: :oauth,
      issuer: context.issuer,
      metadata: context.authorization_server,
      client_id: registration.client_id,
      client_auth: registration.client_auth,
      scopes: context.scopes,
      resource: context.resource
    )
  end

  defp bearer_token(%TokenSet{access_token: token, token_type: type, dpop_jkt: nil})
       when is_binary(token) and token != "" and is_binary(type) do
    if String.valid?(type) and String.downcase(type) == "bearer",
      do: :ok,
      else: {:error, :unsupported_token_type}
  end

  defp bearer_token(_tokens), do: {:error, :unsupported_token_type}

  defp reject_dpop_option(opts) do
    if is_nil(Keyword.get(opts, :dpop)),
      do: :ok,
      else: {:error, :unsupported_token_type}
  end

  defp token_matches(context, registration, tokens) do
    if Map.get(tokens, :client_id) == registration.client_id and
         Map.get(tokens, :issuer) == context.issuer do
      token_matches_context(context, tokens)
    else
      {:error, :token_binding_mismatch}
    end
  end

  defp token_matches_context(context, tokens) do
    if Map.get(tokens, :issuer) == context.issuer and
         Map.get(tokens, :resources) == [context.resource],
       do: :ok,
       else: {:error, :token_binding_mismatch}
  end

  defp scope_retry_limit(opts) do
    case Keyword.get(opts, :max_scope_retries, @default_scope_retries) do
      limit when is_integer(limit) and limit >= 0 -> {:ok, limit}
      _invalid -> {:error, :invalid_scope_retry_limit}
    end
  end

  defp below_scope_retry_limit(attempts, limit) when attempts < limit, do: :ok
  defp below_scope_retry_limit(_attempts, _limit), do: {:error, :scope_retry_limit}

  defp insufficient_scope_challenge(headers) do
    challenge =
      headers
      |> WWWAuthenticate.parse()
      |> Enum.find(fn
        %{scheme: "bearer", params: %{"error" => "insufficient_scope", "scope" => _scope}} ->
          true

        _challenge ->
          false
      end)

    case challenge do
      nil ->
        {:error, :not_insufficient_scope}

      challenge ->
        case WWWAuthenticate.bearer_scopes([challenge]) do
          {:ok, scopes} -> {:ok, scopes}
          _invalid -> {:error, :invalid_scopes}
        end
    end
  end

  defp ordered_union(left, right) do
    Enum.reduce(right, Enum.uniq(left), fn value, acc ->
      if value in acc, do: acc, else: acc ++ [value]
    end)
  end
end
