defmodule AttestoClient.AuthorizationCode do
  @moduledoc """
  OAuth and OpenID Connect Authorization Code flows with S256 PKCE.

  `start/2` validates discovery metadata, creates high-entropy state, nonce, and
  PKCE values, stores the transaction with a finite lifetime, and returns the
  authorization URL. `callback/3` atomically consumes state, exchanges the code
  exactly once, and verifies the ID Token against the stored issuer, client,
  nonce, configured algorithm, and returned access token.

  `start/2` can also return the transaction for the application to keep, with
  no store; see "Keeping the transaction yourself" there. `exchange/2` is the
  token request alone, for an application that ran the authorization request
  itself.

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
  alias AttestoClient.HTTPPolicy
  alias AttestoClient.IDToken
  alias AttestoClient.Issuer
  alias AttestoClient.OpenIDMetadata
  alias AttestoClient.Outbound
  alias AttestoClient.PKCE
  alias AttestoClient.ProtocolParams
  alias AttestoClient.TokenSet
  alias AttestoClient.Verifier

  @default_transaction_ttl_ms 10 * 60 * 1_000
  @max_callback_bytes 1_000_000

  @type store :: Store.store()

  @typedoc """
  Where `start/2` keeps the transaction: a store, or `:return` to hand it back
  to the caller.
  """
  @type transaction_target :: store() | :return

  @doc """
  Begin an authorization transaction.

  Required options are `:issuer`, `:client_id`, `:redirect_uri`, and an opaque
  `:browser_binding` retained in the initiating user agent's secure, HttpOnly
  application session. The same binding is mandatory at callback. The value is
  protocol correlation only; authorization and session policy remain
  application-owned.

  `:issuer` is the issuer identifier, or `{AttestoClient.Issuer, name}` to
  take the identifier and the discovery metadata from a running cache. The
  transaction pins the identifier and the metadata either way.

  Discovery is fetched unless `:metadata` is supplied. `:scopes` defaults to
  `["openid"]` and must include `openid`. `:id_token_alg` defaults to `"RS256"`
  and must match the client's registration and the provider metadata.

  Additional request values may be supplied in `:authorization_params`, but
  protocol-bound parameters and client-authentication fields cannot be
  overridden, including bracket aliases decoded by web frameworks.

  `:resource` names the protected resource(s) the token is for (RFC 8707
  Resource Indicators): one absolute URI without a fragment, or a list of
  them. Each is sent as a `resource` parameter on the authorization request
  (or the pushed request), pinned in the transaction, and repeated on the
  token request; `callback/3` may narrow the token request to a subset. A
  `"resource"` entry in `:authorization_params` is treated the same way;
  supplying both is `{:error, :invalid_authorization_params}`.

  `:issuer_aliases` lists extra exact strings accepted as the ID Token's `iss`
  for a provider that issues more than one value. It is an opt-in workaround
  that deviates from OIDC Core §3.1.3.7; see `AttestoClient.IDToken`. The
  aliases are pinned in the transaction. Discovery and the RFC 9207
  authorization-response `iss` check stay pinned to `:issuer`.

  `:outbound` names deliberate exceptions to the HTTPS and public-address
  rules for the issuer and the endpoints in its metadata: an issuer at a
  private address (`allowed_cidrs`), or a loopback `http` identity provider
  in development (`allow_loopback_http`). See `AttestoClient.Outbound`. It is
  not stored in the transaction, so pass the same value to `callback/3`; a
  callback that does not pass it applies the default rules to the endpoints
  the transaction recorded.

  Use `protocol: :oauth` for a plain OAuth flow, including OID4VCI issuance.
  It does not require the `openid` scope, OIDC metadata, or an ID Token; the
  callback returns `id_token_claims: nil`. The protocol is pinned in the
  transaction and cannot be changed at callback.

  `par: true` submits the request to the advertised Pushed Authorization
  Request endpoint with `:client_auth` and `:dpop`. The default `:auto` uses
  PAR when the server or selected profile requires it. `par: false` cannot
  override a required PAR policy. DPoP keys supplied at start are bound to the transaction and
  must also be supplied at callback; their thumbprint is sent as `dpop_jkt`.
  `:alg`, `:kid`, and `:now` configure the DPoP proofs and must remain
  compatible with the retained key and selected profile.

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

  `require_response_issuer: true` additionally requires metadata to advertise
  `authorization_response_iss_parameter_supported: true` before any transaction
  is stored or authorization request is sent (RFC 9207 §2.4, §3). Otherwise
  `start/2` returns `{:error, :response_issuer_not_supported}`. This boolean
  defaults to `false`; an invalid value is `:invalid_require_response_issuer`.
  The requirement is retained in the transaction: a callback without `iss`
  returns `:missing_response_issuer`, and callback options cannot disable it.

  ## Keeping the transaction yourself

  Pass `:return` in place of a store and nothing is stored: the result carries
  the `AttestoClient.AuthorizationTransaction` under `:transaction` for the
  application to keep, and `callback/3` takes it back as `transaction:`. Every
  callback check runs the same way on it, including its deadline
  (`:expires_at`).

  Two properties a store provides become the application's job:

    * **Confidentiality.** The transaction holds the PKCE verifier and the
      browser binding. Encrypt it before it leaves the server, for example in
      an encrypted cookie; a signed but readable value exposes the verifier.
    * **Single use.** A store deletes the transaction when it is taken. A
      returned transaction can be presented to `callback/3` again until it
      expires unless the application invalidates it, for example by deleting
      the cookie that holds it when the callback arrives. The authorization
      server still redeems a code only once.
  """
  @spec start(transaction_target(), keyword()) ::
          {:ok,
           %{
             required(:url) => String.t(),
             required(:state) => String.t(),
             required(:expires_in) => pos_integer(),
             optional(:transaction) => AuthorizationTransaction.t()
           }}
          | {:error, term()}
  def start(store, opts) when is_list(opts) do
    default_ttl_ms = @default_transaction_ttl_ms

    with {:ok, opts} <- Issuer.expand_option(opts),
         :ok <-
           AttestoClient.InputValidation.boolean_option(
             opts,
             :require_response_issuer,
             :invalid_require_response_issuer
           ),
         {:ok, protocol} <- protocol(opts),
         {:ok, profile} <- AuthorizationProfile.select(opts),
         :ok <- profile_par_option(opts, profile != :generic),
         {:ok, issuer} <- required_string(opts, :issuer),
         {:ok, issuer_aliases} <- IDToken.issuer_aliases(opts),
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
         {:ok, resources, extra_params} <- resources(opts, extra_params),
         {:ok, ttl_ms} <- positive_integer(opts, :transaction_ttl_ms, default_ttl_ms),
         {:ok, requested_id_token_alg} <- protocol_id_token_alg(opts, protocol, profile),
         {:ok, metadata} <- OpenIDMetadata.resolve(issuer, opts),
         :ok <- require_response_issuer_support(metadata, opts),
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
               require_response_issuer:
                 profile != :generic or Keyword.get(opts, :require_response_issuer, false),
               profile: profile,
               client_auth_binding: client_auth_binding,
               resources: resources,
               issuer_aliases: issuer_aliases
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
        |> Attesto.MapParams.put_optional(
          "scope",
          if(scopes == [], do: nil, else: Enum.join(scopes, " "))
        )
        |> Attesto.MapParams.put_optional("nonce", if(protocol == :oidc, do: transaction.nonce))
        |> Attesto.MapParams.put_optional("dpop_jkt", dpop_jkt)
        |> Attesto.MapParams.put_optional(
          "resource",
          if(resources == [], do: nil, else: resources)
        )

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

  `:resource` narrows the token request to a subset of the resource indicators
  the transaction was started with (RFC 8707 §2.2); by default every pinned
  indicator is repeated. A value outside that set fails with
  `{:error, :invalid_resource}` after state is consumed.

  `:clock_skew_seconds` and `:expiry_leeway_seconds` set the ID Token's clock
  tolerances, as in `AttestoClient.IDToken.verify/2`.

  The ID Token's keys are fetched from the transaction's `jwks_uri` on each
  callback. Pass `issuer: {AttestoClient.Issuer, name}` to use that cache's
  keys instead. The cache must be the one for the issuer the transaction was
  started with; any other fails with `{:error, :issuer_mismatch}` after state
  is consumed and before token exchange.

  `:max_token_age_seconds` and `require_auth_time: true` tighten the ID Token
  checks, as in `AttestoClient.IDToken.verify/2`. The latter treats non-positive
  integer `auth_time` as missing. `require_typ: true` requires a JOSE `typ` of
  `JWT` or `application/jwt`, case-insensitively; it defaults to `false`.

  `:now` accepts integer Unix seconds or a zero-arity function returning them.
  It applies to the transaction deadline, DPoP proofs, and all ID Token time
  checks. ID Token verification reads the function after signature verification,
  including any key refresh. A function is also read after the initial key
  lookup to check the transaction deadline before spending the code. Store TTLs
  and network timeouts still use elapsed time. Invalid `:now` or `:require_typ`
  options fail before taking state, with `:invalid_time` or
  `:invalid_require_typ`; a non-integer function result is `:invalid_time`.

  `:trusted_audiences` lists the audiences, other than this client, that the
  ID Token's `aud` may name, as in `AttestoClient.IDToken.verify/2`. It is
  empty by default, so an ID Token with any additional audience is rejected.

  `:outbound` is the exception `start/2` was given, passed again
  (`AttestoClient.Outbound`). The transaction does not carry it: without it
  the token request and key fetch are held to the default HTTPS and
  public-address rules, and with `allow_loopback_http: true` the transaction's
  issuer must be a loopback host or the result is `{:error, :invalid_outbound}`.
  A malformed value is refused before the transaction is taken.

  `transaction:` supplies a transaction that `start/2` returned (see "Keeping
  the transaction yourself"). The store argument is then not consulted and may
  be `:return`. The response's `state` must equal the transaction's, and the
  transaction must not be past its `:expires_at`; either failure is
  `{:error, {:invalid_state, reason}}`, as with a store. Nothing here makes
  the transaction single use.

  A timeout leaves the remote outcome unknown and the transaction consumed; do
  not retry an authorization code.
  """
  @spec callback(transaction_target(), map() | String.t(), keyword()) ::
          {:ok, %{tokens: TokenSet.t(), id_token_claims: map() | nil}} | {:error, term()}
  def callback(store, response, opts \\ [])

  def callback(store, response, opts) when is_binary(response) and is_list(opts) do
    with {:ok, params} <- decode_callback_response(response) do
      callback(store, params, opts)
    end
  end

  def callback(store, params, opts) when is_map(params) and is_list(opts) do
    with :ok <- Verifier.validate_now_option(opts),
         :ok <- IDToken.validate_require_typ(opts),
         {:ok, opts} <- Issuer.expand_option(opts),
         # Checked before the transaction is taken, so a malformed option does
         # not spend it.
         :ok <- Outbound.validate(opts),
         {:ok, state} <- callback_state(params),
         {:ok, transaction} <- take_transaction(store, state, opts),
         :ok <- check_initial_transaction_deadline(transaction, opts),
         :ok <- Outbound.check_issuer(transaction.issuer, opts),
         :ok <- check_issuer_cache(transaction, opts),
         :ok <- check_browser_binding(transaction, opts),
         :ok <-
           AuthorizationProfile.check(
             transaction_profile(transaction),
             Map.get(transaction, :client_auth_binding),
             transaction.client_id,
             transaction.issuer,
             opts
           ),
         {:ok, dpop_jkt} <- TokenSet.dpop_thumbprint(opts),
         :ok <- check_dpop_binding(transaction, dpop_jkt),
         :ok <- AuthorizationProfile.dpop_policy(transaction_profile(transaction), opts),
         :ok <- check_response_issuer(params, transaction),
         {:ok, code} <- callback_code(params),
         {:ok, resources} <- token_resources(transaction, opts),
         {:ok, _timeout_ms} <- HTTPPolicy.timeout(opts) do
      exchange_and_verify(transaction, code, dpop_jkt, resources, opts)
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

  defp parameter_root(key), do: ProtocolParams.root(key)

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
      transaction = %{transaction | expires_at: System.system_time(:millisecond) + ttl_ms}

      case put_transaction(store, state, transaction, ttl_ms) do
        :ok -> {:halt, {:ok, state, transaction, deadline}}
        {:error, :already_exists} -> {:cont, {:error, :state_collision}}
        {:error, reason} -> {:halt, {:error, {:transaction_store, reason}}}
      end
    end)
  end

  # `:return` keeps nothing: the caller receives the transaction from
  # `start/2` and hands it back to `callback/3`.
  defp put_transaction(:return, _state, _transaction, _ttl_ms), do: :ok

  defp put_transaction(store, state, transaction, ttl_ms),
    do: Store.put_new(store, state, transaction, ttl_ms)

  defp discard_transaction(:return, _state), do: :ok
  defp discard_transaction(store, state), do: Store.take(store, state)

  # The transaction comes from the store, or from the caller when it kept the
  # transaction itself. A caller-kept transaction is matched to the response by
  # its own `state`; every later check is the same for both.
  defp take_transaction(store, state, opts) do
    case Keyword.fetch(opts, :transaction) do
      :error -> take_stored_transaction(store, state)
      {:ok, transaction} -> match_returned_transaction(transaction, state)
    end
  end

  defp take_stored_transaction(:return, _state), do: {:error, :missing_transaction}

  defp take_stored_transaction(store, state) do
    case Store.take(store, state) do
      {:ok, %AuthorizationTransaction{} = transaction} -> {:ok, transaction}
      {:error, reason} -> {:error, {:invalid_state, reason}}
    end
  end

  defp match_returned_transaction(%AuthorizationTransaction{state: expected} = transaction, state)
       when is_binary(expected) do
    if SecureCompare.equal?(expected, state),
      do: {:ok, transaction},
      else: {:error, {:invalid_state, :not_found}}
  end

  defp match_returned_transaction(_transaction, _state), do: {:error, :invalid_transaction}

  # A store enforces the lifetime itself; this is the same deadline carried on
  # the transaction, so one kept by the caller expires too. A transaction
  # stored by an earlier version has no deadline of its own.
  defp check_initial_transaction_deadline(transaction, opts) do
    if is_function(Keyword.get(opts, :now), 0),
      do: :ok,
      else: check_transaction_deadline(transaction, opts)
  end

  defp check_transaction_deadline(transaction, opts) do
    case Map.get(transaction, :expires_at) do
      nil ->
        :ok

      expires_at when is_integer(expires_at) ->
        with {:ok, now} <- transaction_now(opts) do
          transaction_not_expired(now, expires_at)
        end

      _invalid ->
        {:error, :invalid_transaction}
    end
  end

  defp transaction_not_expired(now, expires_at) when now < expires_at, do: :ok
  defp transaction_not_expired(_now, _expires_at), do: {:error, {:invalid_state, :expired}}

  defp transaction_now(opts) do
    if Keyword.has_key?(opts, :now) do
      with {:ok, now} <- Verifier.read_now(opts), do: {:ok, now * 1_000}
    else
      {:ok, System.system_time(:millisecond)}
    end
  end

  @doc """
  Exchange an authorization code for tokens (RFC 6749 §4.1.3, RFC 7636 §4.5).

  This is the token request `callback/3` makes, on its own, for an application
  that ran the authorization request itself and holds the code, the
  `redirect_uri` it used, and its PKCE verifier. It sends
  `grant_type=authorization_code` with the code, `redirect_uri`,
  `code_verifier` and client authentication, and returns the validated token
  response as an `AttestoClient.TokenSet`.

  Required options:

    * `:token_endpoint` - the authorization server's token endpoint.
    * `:issuer` - the authorization server's issuer identifier.
    * `:client_id` - this client.
    * `:redirect_uri` - the value sent on the authorization request.
    * `:code_verifier` - the PKCE verifier whose challenge was sent.

  `:client_auth`, `:dpop` (with `:dpop_nonce`, `:alg`, `:kid`, `:now`),
  `:attestation_challenge_received`, `:req_options`, `:resolver`, `:outbound`
  and `:timeout` mean what they mean to `callback/3`. With `:dpop` the returned token set is
  bound to that key's thumbprint. `:resource` adds RFC 8707 resource
  indicators to the request.

  The caller is responsible for everything `callback/3` does around the
  request: matching `state`, the RFC 9207 `iss` check, and verifying a returned
  ID Token with `AttestoClient.IDToken.verify/2` (nonce, `at_hash`, issuer).
  This function verifies none of those. A code is single use; do not retry
  after a timeout.
  """
  @spec exchange(String.t(), keyword()) :: {:ok, TokenSet.t()} | {:error, term()}
  def exchange(code, opts) when is_binary(code) and code != "" and is_list(opts) do
    with {:ok, token_endpoint} <- required_string(opts, :token_endpoint),
         :ok <- validate_endpoint_query(token_endpoint),
         {:ok, issuer} <- required_string(opts, :issuer),
         :ok <- Outbound.validate(opts),
         :ok <- Outbound.check_issuer(issuer, opts),
         {:ok, client_id} <- required_string(opts, :client_id),
         {:ok, redirect_uri} <- required_string(opts, :redirect_uri),
         {:ok, code_verifier} <- required_string(opts, :code_verifier),
         {:ok, resources} <- exchange_resources(opts),
         {:ok, dpop_jkt} <- TokenSet.dpop_thumbprint(opts),
         {:ok, _timeout_ms} <- HTTPPolicy.timeout(opts) do
      request_tokens(
        %{
          token_endpoint: token_endpoint,
          issuer: issuer,
          client_id: client_id,
          redirect_uri: redirect_uri,
          code_verifier: code_verifier
        },
        code,
        dpop_jkt,
        resources,
        opts
      )
    end
  end

  def exchange(_code, opts) when is_list(opts), do: {:error, :missing_code}
  def exchange(_code, _opts), do: {:error, :invalid_options}

  defp exchange_resources(opts) do
    case Keyword.get(opts, :resource) do
      nil -> {:ok, []}
      value -> validate_resources(value)
    end
  end

  # The one authorization-code token request, behind both `exchange/2` and
  # `callback/3`.
  defp request_tokens(grant, code, dpop_jkt, resources, opts) do
    form =
      %{
        "grant_type" => "authorization_code",
        "code" => code,
        "redirect_uri" => grant.redirect_uri,
        "code_verifier" => grant.code_verifier
      }
      |> Attesto.MapParams.put_optional("resource", if(resources == [], do: nil, else: resources))

    with {:ok, response} <-
           AttestoClient.OAuthHTTP.post_form(
             grant.token_endpoint,
             form,
             http_options(grant, opts)
           ),
         {:ok, tokens} <- TokenSet.from_response(response, nil) do
      TokenSet.bind_dpop(tokens, dpop_jkt)
    end
  end

  defp exchange_and_verify(transaction, code, dpop_jkt, resources, opts) do
    grant = %{
      token_endpoint: transaction.metadata["token_endpoint"],
      issuer: transaction.issuer,
      client_id: transaction.client_id,
      redirect_uri: transaction.redirect_uri,
      code_verifier: transaction.code_verifier
    }

    with {:ok, jwks} <- verification_keys(transaction, opts),
         :ok <- check_transaction_deadline(transaction, opts),
         {:ok, tokens} <- request_tokens(grant, code, dpop_jkt, resources, opts),
         {:ok, tokens} <- bind_token_profile(tokens, transaction),
         {:ok, claims} <- protocol_claims(tokens, transaction, jwks, code, opts) do
      {:ok, %{tokens: tokens, id_token_claims: claims}}
    end
  end

  defp verification_keys(%AuthorizationTransaction{protocol: :oauth}, _opts), do: {:ok, nil}

  # Resolved before the code is spent, so a JWKS that cannot be obtained fails
  # the callback while the code is still unused. With an issuer cache this
  # only confirms the cache holds usable keys; the ID Token is then verified
  # through the cache, which can refresh on an unknown `kid`.
  defp verification_keys(transaction, opts) do
    verify_opts =
      opts
      |> Keyword.take([
        :req_options,
        :resolver,
        :outbound,
        :max_response_bytes,
        :timeout,
        :issuer_cache
      ])
      |> Keyword.put(:metadata, transaction.metadata)

    Issuer.resolve_jwks(verify_opts, transaction.issuer)
  end

  # A callback that names an issuer cache must name the cache of the issuer
  # the transaction was started with; its keys verify the ID Token.
  defp check_issuer_cache(transaction, opts) do
    if Keyword.has_key?(opts, :issuer_cache) and Keyword.get(opts, :issuer) != transaction.issuer,
      do: {:error, :issuer_mismatch},
      else: :ok
  end

  defp protocol_claims(_tokens, %AuthorizationTransaction{protocol: :oauth}, _jwks, _code, _opts),
    do: {:ok, nil}

  defp protocol_claims(tokens, transaction, jwks, code, opts) do
    with {:ok, id_token} <- require_id_token(tokens),
         do: verify_id_token(id_token, tokens, transaction, jwks, code, opts)
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
      :outbound,
      :dpop,
      :dpop_nonce,
      :alg,
      :kid,
      :now,
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

        {:ok,
         returned_transaction(
           %{url: url, state: state, expires_in: div(ttl_ms + 999, 1_000)},
           store,
           transaction,
           ttl_ms
         )}
      end

    case result do
      {:ok, _started} -> result
      {:error, _reason} -> discard_start(store, state, deadline, result)
    end
  end

  # The caller keeps the transaction, so it carries the lifetime `start/2`
  # reports, including a shorter pushed-request lifetime.
  defp returned_transaction(started, :return, transaction, ttl_ms) do
    expires_at = min(transaction.expires_at, System.system_time(:millisecond) + ttl_ms)
    Map.put(started, :transaction, %{transaction | expires_at: expires_at})
  end

  defp returned_transaction(started, _store, _transaction, _ttl_ms), do: started

  defp discard_start(store, state, deadline, error) do
    discard_transaction(store, state)

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
    with {:ok, timeout} <- HTTPPolicy.timeout(opts) do
      budget = min(timeout, remaining)
      bounded_opts = Keyword.put(opts, :timeout, budget)
      authorization_url(transaction, params, true, bounded_opts)
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

  defp require_response_issuer_support(metadata, opts) do
    if Keyword.get(opts, :require_response_issuer, false) and
         metadata["authorization_response_iss_parameter_supported"] != true,
       do: {:error, :response_issuer_not_supported},
       else: :ok
  end

  defp check_dpop_binding(%AuthorizationTransaction{dpop_jkt: nil}, _presented), do: :ok

  defp check_dpop_binding(transaction, presented) when is_binary(presented) do
    if SecureCompare.equal?(transaction.dpop_jkt, presented) do
      :ok
    else
      {:error, :dpop_key_mismatch}
    end
  end

  defp check_dpop_binding(_transaction, _presented), do: {:error, :dpop_key_mismatch}

  defp protocol(opts) do
    case Keyword.get(opts, :protocol, :oidc) do
      value when value in [:oidc, :oauth] -> {:ok, value}
      _other -> {:error, :invalid_protocol}
    end
  end

  # The issuer and its aliases come from the transaction, pinned at start; the
  # clock tolerances are the caller's at callback time. A transaction stored by
  # an earlier version has no `:issuer_aliases`.
  defp verify_id_token(id_token, tokens, transaction, jwks, code, opts) do
    verify_opts =
      [
        issuer: Issuer.option(opts, transaction.issuer),
        issuer_aliases: Map.get(transaction, :issuer_aliases, []),
        clock_skew_seconds: Keyword.get(opts, :clock_skew_seconds),
        expiry_leeway_seconds: Keyword.get(opts, :expiry_leeway_seconds),
        max_token_age_seconds: Keyword.get(opts, :max_token_age_seconds),
        require_auth_time: Keyword.get(opts, :require_auth_time, false),
        require_typ: Keyword.get(opts, :require_typ, false),
        trusted_audiences: Keyword.get(opts, :trusted_audiences),
        client_id: transaction.client_id,
        nonce: transaction.nonce,
        access_token: tokens.access_token,
        code: code,
        require_c_hash: false,
        max_age: transaction.max_age,
        accepted_algs: [transaction.id_token_alg],
        enforce_fapi_alg_policy: transaction_profile(transaction) == :fapi
      ] ++ Keyword.take(opts, [:now])

    # With an issuer cache the keys come from it, so an unknown `kid` can
    # refresh them; otherwise the keys resolved before the exchange are used.
    verify_opts =
      if Keyword.has_key?(opts, :issuer_cache),
        do: verify_opts,
        else: Keyword.put(verify_opts, :jwks, jwks)

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

  # RFC 8707 §2.1: one or more absolute URIs without a fragment, de-duplicated.
  # A present but empty value fails closed rather than meaning "none".
  # A `"resource"` authorization parameter predates the option and is read as
  # the same indicator, so it is pinned and repeated on the token request too.
  # It leaves the extra parameters either way: the validated list is added back
  # as the request's only `resource` values.
  defp resources(opts, extra_params) do
    {legacy, extra_params} = Map.pop(extra_params, "resource")

    case {Keyword.get(opts, :resource), legacy} do
      {nil, nil} -> {:ok, [], extra_params}
      {nil, value} -> with_params(validate_resources(value), extra_params)
      {value, nil} -> with_params(validate_resources(value), extra_params)
      {_option, _param} -> {:error, :invalid_authorization_params}
    end
  end

  defp with_params({:ok, resources}, extra_params), do: {:ok, resources, extra_params}
  defp with_params(error, _extra_params), do: error

  defp validate_resources(value) do
    case Attesto.ResourceIndicator.validate(value) do
      {:ok, resources} -> {:ok, resources}
      {:error, :invalid_target} -> {:error, :invalid_resource}
    end
  end

  # RFC 8707 §2.2: the token request names the resource(s) the token is for.
  # By default it repeats what the authorization request asked; `:resource`
  # narrows that to a subset, since a token cannot be minted for a resource the
  # user never authorized. A transaction stored before this field existed
  # carries none.
  defp token_resources(transaction, opts) do
    pinned = Map.get(transaction, :resources, [])

    case Keyword.get(opts, :resource) do
      nil ->
        {:ok, pinned}

      value ->
        with {:ok, requested} <- validate_resources(value) do
          authorize_resources(requested, pinned)
        end
    end
  end

  defp authorize_resources(requested, pinned) do
    case Attesto.ResourceIndicator.authorize(requested, pinned) do
      {:ok, resources} -> {:ok, resources}
      {:error, :invalid_target} -> {:error, :invalid_resource}
    end
  end

  defp authorization_params(opts) do
    case Keyword.get(opts, :authorization_params, %{}) do
      %{} = params ->
        valid? =
          Enum.all?(params, fn {key, value} ->
            is_binary(key) and parameter_root(key) not in ProtocolParams.protected() and
              scalar_authorization_value?(value)
          end)

        if valid?, do: {:ok, params}, else: {:error, :invalid_authorization_params}

      _invalid ->
        {:error, :invalid_authorization_params}
    end
  end

  defp redirect_uri(opts) do
    with {:ok, value} <- required_string(opts, :redirect_uri) do
      cond do
        Attesto.URI.https_identifier?(value) ->
          {:ok, value}

        Attesto.URI.https_identifier?(value, allow_http: true) ->
          validate_http_redirect(value, URI.parse(value).host)

        true ->
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
    AttestoClient.InputValidation.required_string(opts, key, missing_error(key))
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
  defp missing_error(:token_endpoint), do: :missing_token_endpoint
  defp missing_error(:code_verifier), do: :missing_code_verifier

  defp invalid_error(:transaction_ttl_ms), do: :invalid_transaction_ttl_ms

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

  defp random_value, do: Attesto.Secret.generate()

  defp code_challenge!(verifier) do
    {:ok, challenge} = PKCE.code_challenge(verifier)
    challenge
  end

  defp put_query(endpoint, params) do
    uri = URI.parse(endpoint)
    existing = if uri.query, do: URI.decode_query(uri.query), else: %{}

    pairs =
      (Map.to_list(Map.drop(existing, Map.keys(params))) ++ query_pairs(params))
      |> Enum.sort_by(&elem(&1, 0))

    %{uri | query: URI.encode_query(pairs)} |> URI.to_string()
  end

  # A multi-valued parameter (RFC 8707 `resource`) is repeated once per value;
  # a map cannot hold a repeated key, so the query is built from pairs.
  defp query_pairs(params) do
    Enum.flat_map(params, fn
      {key, values} when is_list(values) -> Enum.map(values, &{key, &1})
      {key, value} -> [{key, value}]
    end)
  end

  defp validate_endpoint_query(endpoint),
    do: AttestoClient.OAuthHTTP.validate_endpoint_query(endpoint, ProtocolParams.protected())
end
