defmodule AttestoClient.AuthorizationCode do
  @moduledoc """
  OAuth and OpenID Connect Authorization Code flows with S256 PKCE.

  `start/2` validates discovery metadata, creates high-entropy state, nonce, and
  PKCE values, stores the transaction with a finite lifetime, and returns the
  authorization URL. `callback/3` atomically consumes state, exchanges the code
  exactly once, and verifies the ID Token against the stored issuer, client,
  nonce, configured algorithm, and returned access token.

  Transactions are also bound to an opaque application-supplied browser-session
  value, preventing a response initiated in one user agent from being used in
  another. The store protects protocol correlation only. Applications remain
  responsible for deciding whether verified claims authorize a user, creating
  or retaining a session, and persisting rotated tokens.

  `protocol: :oauth` supports plain OAuth authorization without OIDC metadata
  or an ID Token. PAR and DPoP are supported in either protocol mode.
  """

  alias Attesto.SecureCompare
  alias Attesto.SigningAlg
  alias AttestoClient.AuthorizationProfile
  alias AttestoClient.AuthorizationTransaction
  alias AttestoClient.AuthorizationTransaction.Store
  alias AttestoClient.Deadline
  alias AttestoClient.IDToken
  alias AttestoClient.OpenIDMetadata
  alias AttestoClient.PKCE
  alias AttestoClient.TokenSet
  alias AttestoClient.Verifier

  @default_transaction_ttl_ms 10 * 60 * 1_000
  @default_timeout_ms 10_000
  @max_callback_bytes 1_000_000
  @reserved_params ~w(client_id redirect_uri response_type scope state nonce code_challenge code_challenge_method dpop_jkt request_uri request request_uri_method client_secret client_assertion client_assertion_type grant_type code code_verifier)

  @type store :: Store.store()

  @doc """
  Begin an authorization transaction.

  Required options are `:issuer`, `:client_id`, `:redirect_uri`, and an opaque
  `:browser_binding` retained in the initiating user agent's secure, HttpOnly
  application session. The same binding is mandatory at callback. The value is
  protocol correlation only; authorization and session policy remain
  application-owned.

  Discovery is fetched unless `:metadata` is supplied. `:scopes` defaults to
  `["openid"]` and must include `openid`. `:id_token_alg` defaults to `"RS256"`
  and must match the client's registration and the provider metadata.

  Additional request values may be supplied in `:authorization_params`, but
  protocol-bound parameters and client-authentication fields cannot be
  overridden, including bracket aliases decoded by web frameworks.

  Use `protocol: :oauth` for a plain OAuth flow, including OID4VCI issuance.
  It does not require the `openid` scope, OIDC metadata, or an ID Token; the
  callback returns `id_token_claims: nil`. The protocol is pinned in the
  transaction and cannot be changed at callback.

  `par: true` submits the request to the advertised Pushed Authorization
  Request endpoint with `:client_auth` and `:dpop`. The default `:auto` uses
  PAR when the server or selected profile requires it. `par: false` cannot
  override a required PAR policy. DPoP keys supplied at start are bound to the transaction and
  must also be supplied at callback; their thumbprint is sent as `dpop_jkt`.

  Set exactly one of `haip: true` or `fapi?: true` to select the stored profile.
  Both require authenticated PAR, the authorization response's `iss`, and a
  retained DPoP private key even when metadata omits the corresponding flags.
  This client supports the DPoP sender constraint; it does not bind mTLS
  certificate identities. FAPI requires `private_key_jwt` with a compatible
  signing algorithm. HAIP supports the existing authenticated methods, including
  client attestation according to the issuer's ecosystem policy.

  Retain the same client-authentication method and signing key at callback.
  Client attestation retains the client subject and instance key, so renewed
  attestations and refreshed challenges are allowed. HAIP's Appendix E format
  requires a bounded `x5c` certificate chain. The authorization server verifies
  its signature, certificate trust and validity; an optional attester `iss`
  claim is not part of the local instance binding.
  The transaction records public key identity or a secret digest, never private
  signing material. Callback options cannot weaken the selected profile.
  Generic flows preserve existing authentication choices, require `iss` when
  metadata advertises support, and always reject a returned issuer mismatch.
  """
  @spec start(store(), keyword()) ::
          {:ok, %{url: String.t(), state: String.t(), expires_in: pos_integer()}}
          | {:error, term()}
  def start(store, opts) when is_list(opts) do
    default_ttl_ms = @default_transaction_ttl_ms

    with {:ok, protocol} <- protocol(opts),
         {:ok, profile} <- AuthorizationProfile.select(opts),
         :ok <- profile_par_option(opts, profile != :generic),
         {:ok, issuer} <- required_string(opts, :issuer),
         {:ok, client_id} <- required_string(opts, :client_id),
         {:ok, client_auth_binding} <- AuthorizationProfile.bind(profile, client_id, issuer, opts),
         {:ok, dpop_jkt} <- dpop_thumbprint(opts),
         :ok <- AuthorizationProfile.require_dpop(profile, dpop_jkt),
         :ok <- AuthorizationProfile.dpop_policy(profile, opts),
         {:ok, browser_binding} <- required_string(opts, :browser_binding),
         {:ok, redirect_uri} <- redirect_uri(opts),
         {:ok, scopes} <- scopes(opts, protocol),
         :ok <- profile_scope(profile, scopes),
         {:ok, extra_params} <- authorization_params(opts),
         {:ok, ttl_ms} <- positive_integer(opts, :transaction_ttl_ms, default_ttl_ms),
         {:ok, requested_id_token_alg} <- protocol_id_token_alg(opts, protocol, profile),
         {:ok, metadata} <- OpenIDMetadata.resolve(issuer, opts),
         :ok <- validate_endpoint_queries(metadata),
         :ok <- AuthorizationProfile.metadata(client_auth_binding, metadata),
         {:ok, id_token_alg} <- resolved_id_token_alg(metadata, requested_id_token_alg),
         :ok <- protocol_supports_alg(metadata, id_token_alg, protocol),
         {:ok, par?} <- use_par(metadata, opts, profile != :generic),
         {:ok, max_age} <- max_age(extra_params),
         {:ok, state, transaction, deadline} <-
           store_transaction(
             store,
             %{
               issuer: issuer,
               client_id: client_id,
               redirect_uri: redirect_uri,
               metadata: metadata,
               id_token_alg: id_token_alg,
               browser_binding: browser_binding,
               max_age: max_age,
               protocol: protocol,
               dpop_jkt: dpop_jkt,
               require_response_issuer: profile != :generic,
               profile: profile,
               client_auth_binding: client_auth_binding
             },
             ttl_ms
           ) do
      params =
        Map.merge(extra_params, %{
          "client_id" => client_id,
          "redirect_uri" => redirect_uri,
          "response_type" => "code",
          "state" => state,
          "code_challenge" => code_challenge!(transaction.code_verifier),
          "code_challenge_method" => "S256"
        })
        |> put_optional("scope", if(scopes == [], do: nil, else: Enum.join(scopes, " ")))
        |> put_optional("nonce", if(protocol == :oidc, do: transaction.nonce))
        |> put_optional("dpop_jkt", dpop_jkt)

      finish_start(store, state, transaction, params, par?, deadline, opts)
    end
  end

  def start(_store, _opts), do: {:error, :invalid_options}

  @doc """
  Consume an authorization response and complete the code exchange.

  The second argument may be either the original callback URI (or raw
  `application/x-www-form-urlencoded` response body) or a string-keyed callback
  parameter map. Prefer the encoded form: it is inspected before conversion to
  a map and rejects repeated parameter names, including percent-encoded aliases
  such as `co%64e` plus `code`. A framework-produced map cannot reveal names
  that its parser already collapsed; reject duplicates at that parser or pass
  the original URI/body here.

  State is consumed before any token request, so replay and concurrent duplicate
  callbacks fail. A malformed or ambiguous encoded response is rejected before
  state is consumed.
  `:browser_binding` is required and must equal the opaque value supplied to
  `start/2`; a mismatch consumes state and fails before token exchange. The
  client authentication option is forwarded as `:client_auth`; supported forms
  are `:none`, `{:client_secret_basic, secret}`,
  `{:client_secret_post, secret}`, and `{:private_key_jwt, jwk}`.
  The three-element form `{:private_key_jwt, jwk, assertion_opts}` accepts
  `:alg`, `:kid`, `:audience`, `:lifetime`, `:now`, and `:jti` for registrations
  whose client assertion differs from the defaults; `:client_id` is always
  pinned to the stored transaction.

  A timeout leaves the remote outcome unknown and the transaction consumed; do
  not retry an authorization code.
  """
  @spec callback(store(), map() | String.t(), keyword()) ::
          {:ok, %{tokens: TokenSet.t(), id_token_claims: map() | nil}} | {:error, term()}
  def callback(store, response, opts \\ [])

  def callback(store, response, opts) when is_binary(response) and is_list(opts) do
    with {:ok, params} <- decode_callback_response(response) do
      callback(store, params, opts)
    end
  end

  def callback(store, params, opts) when is_map(params) and is_list(opts) do
    with {:ok, state} <- callback_state(params),
         {:ok, transaction} <- take_transaction(store, state),
         :ok <- check_browser_binding(transaction, opts),
         :ok <-
           AuthorizationProfile.check(
             transaction_profile(transaction),
             Map.get(transaction, :client_auth_binding),
             transaction.client_id,
             transaction.issuer,
             opts
           ),
         :ok <- check_dpop_binding(transaction, opts),
         :ok <- AuthorizationProfile.dpop_policy(transaction_profile(transaction), opts),
         :ok <- check_response_issuer(params, transaction),
         {:ok, code} <- callback_code(params),
         {:ok, timeout_ms} <- positive_integer(opts, :timeout, @default_timeout_ms) do
      Deadline.run(fn -> exchange_and_verify(transaction, code, opts) end, timeout_ms)
    end
  end

  def callback(_store, _params, _opts), do: {:error, :invalid_callback}

  defp decode_callback_response(response) when byte_size(response) <= @max_callback_bytes do
    with {:ok, query} <- callback_query(response),
         {:ok, pairs} <- unique_callback_pairs(query) do
      {:ok, Map.new(pairs)}
    end
  end

  defp decode_callback_response(_response), do: {:error, :invalid_callback}

  # Browser redirects supply an absolute or relative URI. OIDC `form_post`
  # integrations can instead pass the original URL-encoded body; accepting both
  # lets callers retain duplicate detection before their web framework builds a
  # map. Code-flow responses never use the URI fragment.
  defp callback_query(response) do
    cond do
      Regex.match?(~r/\A[^&=?#\/:]+=/, response) ->
        {:ok, response}

      String.contains?(response, "?") ->
        case URI.new(response) do
          {:ok, %URI{query: query, fragment: nil}} when is_binary(query) -> {:ok, query}
          _ -> {:error, :invalid_callback}
        end

      String.contains?(response, ["://", "#"]) ->
        {:error, :invalid_callback}

      true ->
        {:ok, response}
    end
  end

  defp unique_callback_pairs(query) do
    query
    |> URI.query_decoder()
    |> Enum.reduce_while({MapSet.new(), []}, fn {key, value}, {seen, pairs} ->
      logical_key = parameter_root(key)

      if MapSet.member?(seen, logical_key) do
        {:halt, {:error, {:duplicate_callback_parameter, logical_key}}}
      else
        {:cont, {MapSet.put(seen, logical_key), [{key, value} | pairs]}}
      end
    end)
    |> case do
      {:error, _reason} = error -> error
      {_seen, pairs} -> {:ok, Enum.reverse(pairs)}
    end
  rescue
    ArgumentError -> {:error, :invalid_callback}
  end

  defp parameter_root(key) do
    case :binary.match(key, "[") do
      {position, _length} -> binary_part(key, 0, position)
      :nomatch -> key
    end
  end

  defp store_transaction(store, context, ttl_ms) do
    Enum.reduce_while(1..3, {:error, :state_collision}, fn _attempt, _acc ->
      state = random_value()

      transaction =
        struct!(
          AuthorizationTransaction,
          Map.merge(context, %{
            state: state,
            nonce: random_value(),
            code_verifier: PKCE.code_verifier()
          })
        )

      deadline = System.monotonic_time(:millisecond) + ttl_ms

      case Store.put_new(store, state, transaction, ttl_ms) do
        :ok -> {:halt, {:ok, state, transaction, deadline}}
        {:error, :already_exists} -> {:cont, {:error, :state_collision}}
        {:error, reason} -> {:halt, {:error, {:transaction_store, reason}}}
      end
    end)
  end

  defp take_transaction(store, state) do
    case Store.take(store, state) do
      {:ok, %AuthorizationTransaction{} = transaction} -> {:ok, transaction}
      {:error, reason} -> {:error, {:invalid_state, reason}}
    end
  end

  defp exchange_and_verify(transaction, code, opts) do
    form = %{
      "grant_type" => "authorization_code",
      "code" => code,
      "redirect_uri" => transaction.redirect_uri,
      "code_verifier" => transaction.code_verifier
    }

    http_opts = http_options(transaction, opts)

    with {:ok, jwks} <- verification_keys(transaction, opts),
         {:ok, response} <-
           AttestoClient.OAuthHTTP.post_form(
             transaction.metadata["token_endpoint"],
             form,
             http_opts
           ),
         {:ok, tokens} <- TokenSet.from_response(response, nil),
         {:ok, tokens} <- bind_token_dpop(tokens, opts),
         {:ok, tokens} <- bind_token_profile(tokens, transaction),
         {:ok, claims} <- protocol_claims(tokens, transaction, jwks, code) do
      {:ok, %{tokens: tokens, id_token_claims: claims}}
    end
  end

  defp verification_keys(%AuthorizationTransaction{protocol: :oauth}, _opts), do: {:ok, nil}

  defp verification_keys(transaction, opts) do
    Verifier.resolve_jwks(
      [metadata: transaction.metadata, req_options: Keyword.get(opts, :req_options, [])],
      transaction.issuer
    )
  end

  defp protocol_claims(_tokens, %AuthorizationTransaction{protocol: :oauth}, _jwks, _code),
    do: {:ok, nil}

  defp protocol_claims(tokens, transaction, jwks, code) do
    with {:ok, id_token} <- require_id_token(tokens),
         do: verify_id_token(id_token, tokens, transaction, jwks, code)
  end

  defp bind_token_dpop(tokens, opts) do
    with {:ok, jkt} <- dpop_thumbprint(opts), do: TokenSet.bind_dpop(tokens, jkt)
  end

  defp bind_token_profile(tokens, transaction) do
    {:ok,
     %{
       tokens
       | profile: transaction_profile(transaction),
         client_auth_binding: Map.get(transaction, :client_auth_binding),
         client_id: transaction.client_id,
         issuer: transaction.issuer,
         id_token_alg: transaction.id_token_alg
     }}
  end

  defp http_options(transaction, opts) do
    opts
    |> Keyword.take([
      :client_auth,
      :req_options,
      :timeout,
      :resolver,
      :dpop,
      :dpop_nonce,
      :attestation_challenge_received
    ])
    |> Keyword.put(:client_id, transaction.client_id)
    |> Keyword.put(:issuer, transaction.issuer)
  end

  defp finish_start(store, state, transaction, params, par?, deadline, opts) do
    result =
      with {:ok, remaining} <- remaining_lifetime(deadline),
           {:ok, url, par_lifetime} <-
             bounded_authorization_url(transaction, params, par?, remaining, opts),
           {:ok, remaining} <- remaining_lifetime(deadline) do
        ttl_ms = if par_lifetime, do: min(remaining, par_lifetime), else: remaining
        {:ok, %{url: url, state: state, expires_in: div(ttl_ms + 999, 1_000)}}
      end

    case result do
      {:ok, _started} -> result
      {:error, _reason} -> discard_start(store, state, deadline, result)
    end
  end

  defp discard_start(store, state, deadline, error) do
    Store.take(store, state)

    if System.monotonic_time(:millisecond) >= deadline,
      do: {:error, :authorization_transaction_expired},
      else: error
  end

  defp remaining_lifetime(deadline) do
    case deadline - System.monotonic_time(:millisecond) do
      remaining when remaining > 0 -> {:ok, remaining}
      _expired -> {:error, :authorization_transaction_expired}
    end
  end

  defp bounded_authorization_url(transaction, params, false, _remaining, opts),
    do: authorization_url(transaction, params, false, opts)

  defp bounded_authorization_url(transaction, params, true, remaining, opts) do
    with {:ok, timeout} <- positive_integer(opts, :timeout, @default_timeout_ms) do
      budget = min(timeout, remaining)
      bounded_opts = Keyword.put(opts, :timeout, budget)
      Deadline.run(fn -> authorization_url(transaction, params, true, bounded_opts) end, budget)
    end
  end

  defp authorization_url(transaction, params, false, _opts),
    do: {:ok, put_query(transaction.metadata["authorization_endpoint"], params), nil}

  defp authorization_url(transaction, params, true, opts) do
    endpoint = transaction.metadata["pushed_authorization_request_endpoint"]

    http_opts = http_options(transaction, opts) |> Keyword.put(:expected_status, 201)

    with {:ok, response} <-
           AttestoClient.OAuthHTTP.post_form(endpoint, params, http_opts),
         %{"request_uri" => request_uri, "expires_in" => lifetime}
         when is_binary(request_uri) and request_uri != "" and is_integer(lifetime) and
                lifetime > 0 <- response do
      {:ok,
       put_query(transaction.metadata["authorization_endpoint"], %{
         "client_id" => transaction.client_id,
         "request_uri" => request_uri
       }), lifetime * 1_000}
    else
      {:error, _reason} = error -> error
      _other -> {:error, :invalid_par_response}
    end
  end

  defp use_par(metadata, opts, profile_required?) do
    advertised = Map.get(metadata, "require_pushed_authorization_requests", false)

    if is_boolean(advertised),
      do: par_setting(metadata, Keyword.get(opts, :par, :auto), advertised or profile_required?),
      else: {:error, :invalid_metadata}
  end

  defp par_setting(_metadata, false, true), do: {:error, :par_required}

  defp par_setting(metadata, option, required?) when option in [true, false, :auto] do
    enabled = option == true or required?

    if enabled and not is_binary(metadata["pushed_authorization_request_endpoint"]),
      do: {:error, :missing_par_endpoint},
      else: {:ok, enabled}
  end

  defp par_setting(_metadata, _option, _required), do: {:error, :invalid_par_option}

  defp profile_par_option(opts, required?) do
    case Keyword.get(opts, :par, :auto) do
      false when required? -> {:error, :par_required}
      option when option in [true, false, :auto] -> :ok
      _invalid -> {:error, :invalid_par_option}
    end
  end

  defp dpop_thumbprint(opts), do: TokenSet.dpop_thumbprint(opts)

  defp check_dpop_binding(%AuthorizationTransaction{dpop_jkt: nil}, opts) do
    with {:ok, _jkt} <- dpop_thumbprint(opts), do: :ok
  end

  defp check_dpop_binding(transaction, opts) do
    with {:ok, presented} when is_binary(presented) <- dpop_thumbprint(opts),
         true <- SecureCompare.equal?(transaction.dpop_jkt, presented) do
      :ok
    else
      _other -> {:error, :dpop_key_mismatch}
    end
  end

  defp protocol(opts) do
    case Keyword.get(opts, :protocol, :oidc) do
      value when value in [:oidc, :oauth] -> {:ok, value}
      _other -> {:error, :invalid_protocol}
    end
  end

  defp verify_id_token(id_token, tokens, transaction, jwks, code) do
    verify_opts = [
      issuer: transaction.issuer,
      client_id: transaction.client_id,
      jwks: jwks,
      nonce: transaction.nonce,
      access_token: tokens.access_token,
      code: code,
      require_c_hash: false,
      max_age: transaction.max_age,
      accepted_algs: [transaction.id_token_alg],
      enforce_fapi_alg_policy: transaction_profile(transaction) == :fapi
    ]

    IDToken.verify(id_token, verify_opts)
  end

  defp require_id_token(%TokenSet{id_token: token}) when is_binary(token), do: {:ok, token}
  defp require_id_token(_tokens), do: {:error, :missing_id_token}

  defp callback_state(%{"state" => state}) when is_binary(state) and state != "", do: {:ok, state}
  defp callback_state(_params), do: {:error, :missing_state}

  defp callback_code(%{"code" => code} = params) when is_binary(code) and code != "" do
    if Map.has_key?(params, "error"),
      do: {:error, :mixed_authorization_response},
      else: {:ok, code}
  end

  defp callback_code(%{"error" => error} = params) when is_binary(error) and error != "" do
    {:error, {:authorization_error, error, Map.get(params, "error_description")}}
  end

  defp callback_code(_params), do: {:error, :missing_code}

  defp check_response_issuer(params, transaction) do
    required? =
      Map.get(transaction, :require_response_issuer, false) or
        transaction.metadata["authorization_response_iss_parameter_supported"] == true

    case Map.fetch(params, "iss") do
      {:ok, issuer} when issuer == transaction.issuer -> :ok
      {:ok, _wrong} -> {:error, :issuer_mismatch}
      :error when required? -> {:error, :missing_response_issuer}
      :error -> :ok
    end
  end

  defp check_browser_binding(transaction, opts) do
    case Keyword.get(opts, :browser_binding) do
      binding when is_binary(binding) and binding != "" ->
        if SecureCompare.equal?(binding, transaction.browser_binding),
          do: :ok,
          else: {:error, :browser_binding_mismatch}

      _missing ->
        {:error, :missing_browser_binding}
    end
  end

  defp transaction_profile(transaction) do
    case Map.fetch(transaction, :profile) do
      {:ok, profile} ->
        profile

      :error ->
        if Map.get(transaction, :require_response_issuer, false),
          do: :legacy_profile,
          else: :generic
    end
  end

  defp scopes(opts, protocol) do
    default = if protocol == :oidc, do: ["openid"], else: []

    case Keyword.get(opts, :scopes, default) do
      scopes when is_list(scopes) ->
        if Enum.all?(scopes, &(is_binary(&1) and &1 != "")) and
             (protocol == :oauth or "openid" in scopes),
           do: {:ok, Enum.uniq(scopes)},
           else: {:error, :invalid_scopes}

      _invalid ->
        {:error, :invalid_scopes}
    end
  end

  defp authorization_params(opts) do
    case Keyword.get(opts, :authorization_params, %{}) do
      %{} = params ->
        valid? =
          Enum.all?(params, fn {key, value} ->
            is_binary(key) and parameter_root(key) not in @reserved_params and
              scalar_authorization_value?(value)
          end)

        if valid?, do: {:ok, params}, else: {:error, :invalid_authorization_params}

      _invalid ->
        {:error, :invalid_authorization_params}
    end
  end

  defp redirect_uri(opts) do
    with {:ok, value} <- required_string(opts, :redirect_uri) do
      case URI.parse(value) do
        %URI{scheme: "https", host: host, userinfo: nil, fragment: nil}
        when is_binary(host) and host != "" ->
          {:ok, value}

        %URI{scheme: "http", host: host, userinfo: nil, fragment: nil}
        when is_binary(host) and host != "" ->
          validate_http_redirect(value, host)

        _invalid ->
          {:error, :invalid_redirect_uri}
      end
    end
  end

  defp validate_http_redirect(value, host) do
    if loopback_host?(host), do: {:ok, value}, else: {:error, :invalid_redirect_uri}
  end

  defp loopback_host?(host) do
    case String.downcase(host) do
      "localhost" -> true
      "::1" -> true
      host -> ipv4_loopback?(host)
    end
  end

  defp ipv4_loopback?(host) do
    case :inet.parse_ipv4_address(String.to_charlist(host)) do
      {:ok, {127, _, _, _}} -> true
      _other -> false
    end
  end

  defp id_token_alg(opts) do
    alg = Keyword.get(opts, :id_token_alg, "RS256")
    if alg in SigningAlg.allowed(), do: {:ok, alg}, else: {:error, :unsupported_alg}
  end

  defp protocol_id_token_alg(_opts, :oauth, _profile), do: {:ok, nil}

  defp protocol_id_token_alg(opts, :oidc, :fapi) do
    case Keyword.fetch(opts, :id_token_alg) do
      :error ->
        {:ok, :fapi_default}

      {:ok, alg} ->
        if alg in SigningAlg.fapi_algs(), do: {:ok, alg}, else: {:error, :unsupported_alg}
    end
  end

  defp protocol_id_token_alg(opts, :oidc, _profile), do: id_token_alg(opts)

  defp resolved_id_token_alg(metadata, :fapi_default) do
    supported = metadata["id_token_signing_alg_values_supported"]
    alg = Enum.find(~w(ES256 PS256 Ed25519 EdDSA), &(&1 in supported))
    if alg, do: {:ok, alg}, else: {:error, :unsupported_alg}
  end

  defp resolved_id_token_alg(_metadata, alg), do: {:ok, alg}

  defp profile_scope(:haip, []), do: {:error, :profile_scope_required}
  defp profile_scope(_profile, _scopes), do: :ok

  defp protocol_supports_alg(_metadata, _alg, :oauth), do: :ok
  defp protocol_supports_alg(metadata, alg, :oidc), do: metadata_supports_alg(metadata, alg)

  defp metadata_supports_alg(metadata, alg) do
    if alg in metadata["id_token_signing_alg_values_supported"],
      do: :ok,
      else: {:error, :unsupported_alg}
  end

  defp required_string(opts, key) do
    case Keyword.get(opts, key) do
      value when is_binary(value) and value != "" -> {:ok, value}
      _invalid -> {:error, missing_error(key)}
    end
  end

  defp positive_integer(opts, key, default) do
    case Keyword.get(opts, key, default) do
      value when is_integer(value) and value > 0 -> {:ok, value}
      _invalid -> {:error, invalid_error(key)}
    end
  end

  defp missing_error(:issuer), do: :missing_issuer
  defp missing_error(:client_id), do: :missing_client_id
  defp missing_error(:browser_binding), do: :missing_browser_binding
  defp missing_error(:redirect_uri), do: :missing_redirect_uri

  defp invalid_error(:transaction_ttl_ms), do: :invalid_transaction_ttl_ms
  defp invalid_error(:timeout), do: :invalid_timeout

  defp scalar_authorization_value?(value) when is_binary(value), do: true
  defp scalar_authorization_value?(value) when is_integer(value), do: true
  defp scalar_authorization_value?(_value), do: false

  defp max_age(params) do
    case Map.get(params, "max_age") do
      nil -> {:ok, nil}
      age when is_integer(age) and age >= 0 -> {:ok, age}
      age when is_binary(age) -> parse_max_age(age)
      _invalid -> {:error, :invalid_max_age}
    end
  end

  defp parse_max_age(age) do
    case Integer.parse(age) do
      {parsed, ""} when parsed >= 0 -> {:ok, parsed}
      _invalid -> {:error, :invalid_max_age}
    end
  end

  defp random_value, do: :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)

  defp code_challenge!(verifier) do
    {:ok, challenge} = PKCE.code_challenge(verifier)
    challenge
  end

  defp put_optional(params, _key, nil), do: params
  defp put_optional(params, key, value), do: Map.put(params, key, value)

  defp put_query(endpoint, params) do
    uri = URI.parse(endpoint)
    existing = if uri.query, do: URI.decode_query(uri.query), else: %{}
    %{uri | query: URI.encode_query(Map.merge(existing, params))} |> URI.to_string()
  end

  defp validate_endpoint_queries(metadata) do
    Enum.reduce_while(
      ~w(authorization_endpoint pushed_authorization_request_endpoint token_endpoint),
      :ok,
      fn name, :ok ->
        case validate_endpoint_query(metadata[name]) do
          :ok -> {:cont, :ok}
          error -> {:halt, error}
        end
      end
    )
  end

  defp validate_endpoint_query(nil), do: :ok

  defp validate_endpoint_query(endpoint),
    do: AttestoClient.OAuthHTTP.validate_endpoint_query(endpoint, @reserved_params)
end
