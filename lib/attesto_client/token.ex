defmodule AttestoClient.Token do
  @moduledoc """
  Obtain, refresh, and revoke OAuth tokens.

  Connections are retried up to three times, within the request deadline, only
  before any HTTP request can have been sent. Each connect has a three-second
  cap (overridden by `:req_options`' `:connect_options` `:timeout`). No transport
  failure after the request starts triggers a retry.

  `{:error, :not_sent}` means no state-changing request was written during the
  call (excluding a refused authentication attempt that is retried), including a deadline ending
  during connect. `{:error, :transport_error}` and `{:error, :timeout}` mean the
  remote outcome may be unknown; do not blindly retry a token operation. Refresh-token rotation is available
  through `refresh/4`, which uses `AttestoClient.RefreshCoordinator` to prevent
  concurrent reuse for the same application record.

  Returned tokens are not persisted by this library. Applications must perform
  any compare-and-swap update and choose their own token/session retention
  policy.
  """

  alias Attesto.SecureCompare
  alias Attesto.SigningAlg
  alias AttestoClient.AuthorizationProfile
  alias AttestoClient.HTTPPolicy
  alias AttestoClient.IDToken
  alias AttestoClient.Issuer
  alias AttestoClient.OAuthHTTP
  alias AttestoClient.RefreshCoordinator
  alias AttestoClient.RefreshResult
  alias AttestoClient.TokenSet
  alias AttestoClient.Verifier

  @pre_authorized_code_grant_type "urn:ietf:params:oauth:grant-type:pre-authorized_code"
  @verification_options [
    :now,
    :require_typ,
    :require_kid,
    :require_auth_time,
    :protocol,
    :issuer_aliases,
    :trusted_audiences,
    :subject,
    :clock_skew_seconds,
    :expiry_leeway_seconds,
    :max_token_age_seconds
  ]

  @doc """
  Obtain a token with the OAuth client-credentials grant.

  Required options: `:token_endpoint`, `:client_id`, and `:client_auth`.
  Authentication uses the same methods as `refresh/4`; `:none` is refused
  with `:invalid_client_auth` because this grant requires an authenticated
  confidential client. For private-key JWT, supply the trusted `:issuer`
  (or an explicit assertion audience), as with the other token operations.

  `:scopes` is a list of scope tokens (default `[]`); `:resource` is an
  absolute resource URI or list of URIs. Invalid values return
  `:invalid_scopes` or `:invalid_target`. `:dpop`, `:dpop_nonce`, `:alg`,
  `:kid`, `:now`, `:outbound`, `:req_options`, and
  `:timeout` have the same meanings as for the other token requests. A
  `:profile` applies its client-authentication and DPoP requirements too.
  Response bodies have the same fixed 2,000,000-byte limit as other grants.

  Returns `{:ok, token_set}`, with unknown response members in
  `AttestoClient.TokenSet`'s `:extra`. Any ID Token is returned unverified:
  this grant establishes no end-user identity. A DPoP response without a key
  returns `:missing_dpop_key`; a Bearer response with a key returns
  `:invalid_token_type`. Access-token contents are never inspected.

  Connect failures may retry before a request is written. A transport failure
  after writing never retries; see the module's `:not_sent` contract.
  """
  @spec client_credentials(keyword()) :: {:ok, TokenSet.t()} | {:error, term()}
  def client_credentials(opts) when is_list(opts) do
    with :ok <- AttestoClient.Outbound.validate(opts),
         {:ok, endpoint} <- required_string(opts, :token_endpoint),
         :ok <- AttestoClient.Outbound.check_issuer(Keyword.get(opts, :issuer, endpoint), opts),
         {:ok, _client_id} <- required_string(opts, :client_id),
         :ok <- require_client_auth(opts),
         {:ok, scopes} <- credential_scopes(opts),
         {:ok, resources} <- Attesto.ResourceIndicator.validate(Keyword.get(opts, :resource)),
         {:ok, profile} <- new_profile(opts),
         {:ok, dpop_jkt} <- TokenSet.dpop_thumbprint(opts),
         :ok <- AuthorizationProfile.require_dpop(profile.profile, dpop_jkt),
         :ok <- AuthorizationProfile.dpop_policy(profile.profile, opts) do
      form =
        %{"grant_type" => "client_credentials"}
        |> maybe_put("scope", if(scopes == [], do: nil, else: Enum.join(scopes, " ")))
        |> maybe_put("resource", if(resources == [], do: nil, else: resources))

      with {:ok, response} <- OAuthHTTP.post_form(endpoint, form, opts),
           {:ok, tokens} <- TokenSet.from_response(response, nil),
           {:ok, tokens} <- TokenSet.bind_dpop(tokens, dpop_jkt) do
        {:ok, tokens |> Map.merge(profile) |> Map.put(:resources, resources)}
      end
    end
  end

  def client_credentials(_opts), do: {:error, :invalid_options}

  defp require_client_auth(opts) do
    if Keyword.get(opts, :client_auth, :none) == :none,
      do: {:error, :invalid_client_auth},
      else: :ok
  end

  defp credential_scopes(opts) do
    scopes = Keyword.get(opts, :scopes, [])

    if is_list(scopes) and Enum.all?(scopes, &Attesto.Scope.valid_token?/1),
      do: {:ok, Enum.uniq(scopes)},
      else: {:error, :invalid_scopes}
  end

  @doc """
  Exchange an OID4VCI pre-authorized code for an access token
  (`urn:ietf:params:oauth:grant-type:pre-authorized_code`,
  `OpenID4VCI 1.0 Final` §6.1/§6.2) - the wallet-holder token step
  ahead of `AttestoClient.Wallet.request_credential/3`.

  Required option: `:token_endpoint`. Private-key JWT authentication also
  requires `:issuer` from trusted discovery: it is the assertion's audience
  (RFC 10070 §4), and without it the call returns
  `{:error, {:client_assertion, :invalid_audience}}`. `:client_id` may
  be omitted only with `client_auth: :none`, as permitted for anonymous
  pre-authorized-code flows; authenticated methods still require it.
  `:client_auth` and `:req_options` otherwise behave as for `refresh/4`.
  `:alg`, `:kid`, and `:now` configure DPoP proofs when `:dpop` is supplied. Pass
  `:tx_code` when the offer's grant carried a `tx_code` object, i.e. the end
  user must key in the transaction code the issuer displayed out of band.

  `:outbound` applies to the token request; see `AttestoClient.Outbound`. A
  malformed value is `{:error, :invalid_outbound}`.

  Returns `{:ok, token_set}`; the ID Token, if any, is returned unverified
  since OID4VCI defines no binding claims for it here.
  """
  @spec exchange_pre_authorized_code(String.t(), keyword()) ::
          {:ok, TokenSet.t()} | {:error, term()}
  def exchange_pre_authorized_code(pre_authorized_code, opts)
      when is_binary(pre_authorized_code) and pre_authorized_code != "" and is_list(opts) do
    with :ok <- AttestoClient.Outbound.validate(opts),
         {:ok, endpoint} <- required_string(opts, :token_endpoint),
         :ok <- AttestoClient.Outbound.check_issuer(Keyword.get(opts, :issuer, endpoint), opts),
         {:ok, profile} <- new_profile(opts),
         {:ok, dpop_jkt} <- TokenSet.dpop_thumbprint(opts),
         :ok <- AuthorizationProfile.require_dpop(profile.profile, dpop_jkt),
         :ok <- AuthorizationProfile.dpop_policy(profile.profile, opts) do
      form =
        %{
          "grant_type" => @pre_authorized_code_grant_type,
          "pre-authorized_code" => pre_authorized_code
        }
        |> maybe_put("tx_code", Keyword.get(opts, :tx_code))

      with {:ok, response} <- OAuthHTTP.post_form(endpoint, form, opts),
           {:ok, tokens} <- TokenSet.from_response(response, nil),
           {:ok, tokens} <- TokenSet.bind_dpop(tokens, dpop_jkt) do
        {:ok, Map.merge(tokens, profile)}
      end
    end
  end

  def exchange_pre_authorized_code(_pre_authorized_code, _opts),
    do: {:error, :invalid_pre_authorized_code}

  @doc """
  Refresh a token set through a single-flight coordinator.

  Required options are `:token_endpoint`, `:issuer`, and `:client_id`.
  With the default `protocol: :oidc`, the `:subject` from the previously
  verified ID Token is required too; `protocol: :oauth` omits ID Token and
  JWKS processing for a plain OAuth grant. `:client_auth` and
  `:req_options` match
  `AttestoClient.AuthorizationCode.callback/3`. The issuer is validated before
  the request so an ID Token returned with a rotated refresh token can always
  be verified rather than losing the rotation result after the response.

  `:resource` names the protected resource(s) the new access token is for
  (RFC 8707 §2.2): one absolute URI without a fragment, or a list of them.
  Each is sent as a `resource` parameter on the refresh request. Omitted, the
  locally retained `tokens.resources` are repeated. An explicit value must be
  a subset of that grant when it is known. A malformed or out-of-grant value
  returns `{:error, :invalid_resource}` before any request. A token set
  persisted before resources were retained has `resources: nil`; omission
  sends none, while an explicit valid value is accepted and checked by the
  authorization server.

  `:scopes` optionally narrows the new access token to a list of RFC 6749 scope
  tokens. Omitted or empty, no `scope` parameter is sent and the authorization
  server treats the request as the original grant's scope. An invalid list
  returns `{:error, :invalid_scopes}` before any request. When the response
  omits `scope`, the token set retains the explicitly requested value.

  One refresh request serves every concurrent caller for a key, and that
  request names one set of resources and scopes. A caller that joins a refresh
  running with different request parameters gets
  `{:error, :refresh_request_mismatch}` and no tokens: its own request was not
  sent, and the shared access token has another audience or permission set.
  Where the server rotates refresh tokens the stored token set has been
  replaced by then, so read it again before refreshing.

  `:client_auth` also accepts
  `{:private_key_jwt, jwk, assertion_opts}` for an explicitly registered
  assertion algorithm, key id, audience, lifetime, time, or JWT id.

  `:issuer` is the issuer identifier, or `{AttestoClient.Issuer, name}` to
  take the identifier and the ID Token verification keys from a running cache.

  `:issuer_aliases`, `:clock_skew_seconds`, `:expiry_leeway_seconds`,
  `:max_token_age_seconds`, `:require_auth_time`, `:require_typ`, `:require_kid`, and `:trusted_audiences` apply
  to an ID Token returned with the refresh, as in
  `AttestoClient.IDToken.verify/2`. A token set does not retain the aliases
  given to `AttestoClient.AuthorizationCode.start/2`, so pass them again here.

  `require_auth_time: true` treats non-positive integer `auth_time` as missing.
  `require_typ: true` requires `JWT` or `application/jwt`, case-insensitively,
  and defaults to `false`. `:now` accepts integer Unix seconds or a zero-arity
  function returning them. It supplies every ID Token time check, read after
  key resolution and signature verification, and each DPoP proof. Invalid
  options fail before refresh with `:invalid_time` or `:invalid_require_typ`;
  an invalid clock result returns `:invalid_time`. Network timeouts and
  coordinator deadlines still use elapsed time.
  Concurrent callers sharing a refresh result must still meet their own
  verification options; a caller with different options re-verifies the ID
  Token without repeating the refresh request.

  `:outbound` names deliberate exceptions to the HTTPS and public-address
  rules for the issuer, its key fetch and the token request
  (`AttestoClient.Outbound`). A token set does not retain it either.

  A prior DPoP token set requires `:dpop` signing material before any network
  request. Persisted `tokens.dpop_jkt` must match that key; a missing or changed
  key is rejected locally. A requested or prior DPoP token cannot accept a
  Bearer response. Shared results are also checked against each caller's key
  before adoption. Legacy token sets without a thumbprint require a key, but
  their historical key continuity cannot be checked; a successful DPoP response
  records the supplied key for subsequent refreshes.

  `:alg`, `:kid`, and `:now` configure each DPoP proof and are retained across
  the one permitted nonce retry.

  The locally retained `tokens.id_token_alg` selects the ID Token verification
  algorithm. An explicit `:id_token_alg` must match it; mismatches fail before
  HTTP. The algorithm survives refreshes even when the response omits an ID
  Token, and shared results must match each caller's policy. Legacy token sets
  without this field use the explicit option or the existing default (PS256 for
  FAPI, RS256 otherwise), then retain that selection for subsequent refreshes.
  """
  @spec refresh(GenServer.server(), term(), TokenSet.t(), keyword()) ::
          {:ok, RefreshResult.t()} | {:error, term()}
  def refresh(coordinator, key, %TokenSet{refresh_token: refresh_token} = tokens, opts)
      when is_binary(refresh_token) and refresh_token != "" and is_list(opts) do
    with :ok <- Verifier.validate_now_option(opts),
         :ok <- IDToken.validate_require_typ(opts),
         :ok <- IDToken.validate_require_kid(opts),
         {:ok, opts} <- Issuer.expand_option(opts),
         {:ok, timeout_ms} <- HTTPPolicy.timeout(opts),
         {:ok, endpoint} <- required_string(opts, :token_endpoint),
         {:ok, issuer} <- required_string(opts, :issuer),
         :ok <- AttestoClient.Discovery.validate_issuer_identifier(issuer, opts),
         {:ok, client_id} <- required_string(opts, :client_id),
         {:ok, protocol} <- refresh_protocol(opts),
         :ok <- require_refresh_subject(protocol, opts),
         {:ok, resources} <- refresh_resources(tokens, opts),
         {:ok, scopes} <- refresh_scopes(opts),
         {:ok, profile} <- refresh_profile(tokens, opts),
         opts = Keyword.put(opts, :retained_authorization_profile, profile.profile),
         {:ok, id_token_alg} <- refresh_id_token_alg(protocol, tokens, opts),
         opts = Keyword.put(opts, :id_token_alg, id_token_alg),
         opts = Keyword.put(opts, :protocol, protocol),
         {:ok, dpop_jkt} <- refresh_dpop_binding(tokens, opts),
         :ok <- AuthorizationProfile.require_dpop(profile.profile, dpop_jkt),
         :ok <- AuthorizationProfile.dpop_policy(profile.profile, opts) do
      request = %{
        token_endpoint: endpoint,
        issuer: issuer,
        client_id: client_id,
        protocol: protocol,
        resources: resources,
        scopes: scopes
      }

      RefreshCoordinator.run_with_context(
        coordinator,
        key,
        fn context ->
          opts = Keyword.put(opts, :attesto_context, context)

          {:verified_refresh, do_refresh(tokens, dpop_jkt, profile, request, opts),
           verification_options(opts), request}
        end,
        timeout_ms,
        opts
      )
      |> adopt_refresh(request, dpop_jkt, profile, id_token_alg, opts)
    end
  end

  def refresh(_coordinator, _key, %TokenSet{}, _opts), do: {:error, :missing_refresh_token}
  def refresh(_coordinator, _key, _tokens, _opts), do: {:error, :invalid_token_set}

  # The result may come from another caller's request. It is adopted only when
  # that request named this caller's resources and scopes, and its tokens match
  # this caller's DPoP key, client authentication and ID Token algorithm.
  defp adopt_refresh(
         {:verified_refresh, result, verified_opts, requested},
         request,
         dpop_jkt,
         profile,
         alg,
         opts
       ) do
    with :ok <- same_refresh_request(requested, request),
         {:ok, result} <-
           result
           |> check_refresh_result_binding(dpop_jkt)
           |> check_refresh_profile(profile)
           |> check_refresh_id_token_alg(alg) do
      reverify_shared(result, verified_opts, opts)
    end
  end

  defp adopt_refresh(error, _request, _dpop_jkt, _profile, _alg, _opts), do: error

  # RFC 8707 §2.2: a refresh request may name the resource(s) the new access
  # token is for. Checked before the coordinator runs, so a malformed value is
  # this caller's error and never a result shared with the others.
  defp refresh_resources(tokens, opts) do
    retained = Map.get(tokens, :resources)

    with {:ok, retained_resources} <- validate_retained_resources(retained) do
      requested_refresh_resources(Keyword.get(opts, :resource), retained, retained_resources)
    end
  end

  defp requested_refresh_resources(nil, _retained, retained_resources),
    do: {:ok, retained_resources}

  defp requested_refresh_resources(value, retained, _retained_resources) do
    with {:ok, resources} <- validate_refresh_resources(value),
         :ok <- authorize_refresh_resources(resources, retained) do
      {:ok, resources}
    end
  end

  defp validate_retained_resources(nil), do: {:ok, []}
  defp validate_retained_resources([]), do: {:ok, []}

  defp validate_retained_resources(resources) do
    case Attesto.ResourceIndicator.validate(resources) do
      {:ok, resources} -> {:ok, resources}
      {:error, :invalid_target} -> {:error, :invalid_token_set}
    end
  end

  defp validate_refresh_resources(value) do
    case Attesto.ResourceIndicator.validate(value) do
      {:ok, resources} -> {:ok, resources}
      {:error, :invalid_target} -> {:error, :invalid_resource}
    end
  end

  # A legacy or application-assembled token set cannot prove the original
  # resource grant, so the server remains the authority for an explicit value.
  defp authorize_refresh_resources(_requested, nil), do: :ok

  defp authorize_refresh_resources(requested, retained) do
    case Attesto.ResourceIndicator.authorize(requested, retained) do
      {:ok, _resources} -> :ok
      {:error, :invalid_target} -> {:error, :invalid_resource}
    end
  end

  defp refresh_scopes(opts) do
    case Keyword.get(opts, :scopes) do
      nil ->
        {:ok, nil}

      scopes when is_list(scopes) ->
        if Enum.all?(scopes, &Attesto.Scope.valid_token?/1),
          do: {:ok, scopes |> Enum.uniq() |> empty_to_nil()},
          else: {:error, :invalid_scopes}

      _invalid ->
        {:error, :invalid_scopes}
    end
  end

  defp empty_to_nil([]), do: nil
  defp empty_to_nil(values), do: values

  # Resource and scope lists are sets; their order carries no meaning. This
  # holds whatever the shared request returned: a caller asking for different
  # access learns nothing about its own request from that outcome.
  defp same_refresh_request(requested, request) do
    if same_set?(requested.resources, request.resources) and
         same_optional_set?(requested.scopes, request.scopes) and
         same_refresh_identity?(requested, request),
       do: :ok,
       else: {:error, :refresh_request_mismatch}
  end

  defp same_refresh_identity?(left, right) do
    fields = [
      :token_endpoint,
      :issuer,
      :client_id,
      :protocol
    ]

    Map.take(left, fields) == Map.take(right, fields)
  end

  defp same_set?(left, right), do: MapSet.new(left) == MapSet.new(right)
  defp same_optional_set?(nil, nil), do: true

  defp same_optional_set?(left, right) when is_list(left) and is_list(right),
    do: same_set?(left, right)

  defp same_optional_set?(_left, _right), do: false

  defp reverify_shared(result, verified_opts, opts) do
    if verified_opts == verification_options(opts) do
      {:ok, result}
    else
      with {:ok, claims} <- verify_refresh_id_token(result.tokens, opts),
           do: {:ok, %{result | id_token_claims: claims}}
    end
  end

  defp verification_options(opts), do: opts |> Keyword.take(@verification_options) |> Enum.sort()

  @doc """
  Revoke a token according to RFC 7009.

  A successful 2xx response is `:ok`, including when the server did not know
  the token. Required options: `:revocation_endpoint`, `:client_id`; optional
  `:token_type_hint`, `:client_auth`, `:req_options`, `:timeout`, and
  `:outbound` (see `AttestoClient.Outbound`).
  With `private_key_jwt`, pass `:issuer` from trusted discovery; it is the
  assertion's audience (RFC 10070 §4). An explicit `:audience` in the assertion
  options takes its place. With neither, the call returns
  `{:error, {:client_assertion, :invalid_audience}}`; the endpoint URL is never
  used as the audience.
  """
  @spec revoke(String.t(), keyword()) :: :ok | {:error, term()}
  def revoke(token, opts) when is_binary(token) and token != "" and is_list(opts) do
    with :ok <- AttestoClient.Outbound.validate(opts),
         {:ok, endpoint} <- required_string(opts, :revocation_endpoint),
         :ok <- AttestoClient.Outbound.check_issuer(Keyword.get(opts, :issuer, endpoint), opts),
         {:ok, _client_id} <- required_string(opts, :client_id),
         {:ok, hint} <- token_type_hint(opts) do
      form = %{"token" => token} |> maybe_put("token_type_hint", hint)
      OAuthHTTP.post_form_unit(endpoint, form, opts)
    end
  end

  def revoke(_token, _opts), do: {:error, :invalid_token}

  defp do_refresh(
         %TokenSet{refresh_token: refresh_token, scope: old_scope} = old_tokens,
         dpop_jkt,
         profile,
         request,
         opts
       ) do
    form =
      %{"grant_type" => "refresh_token", "refresh_token" => refresh_token}
      |> maybe_put("scope", requested_scope(request.scopes))
      |> maybe_put("resource", if(request.resources == [], do: nil, else: request.resources))

    default_scope = requested_scope(request.scopes) || old_scope

    with {:ok, endpoint} <- required_string(opts, :token_endpoint),
         {:ok, issuer} <- required_string(opts, :issuer),
         {:ok, jwks} <- refresh_jwks(opts, issuer),
         {:ok, response} <- OAuthHTTP.post_form(endpoint, form, opts),
         {:ok, tokens} <- TokenSet.from_response(response, refresh_token, default_scope),
         {:ok, tokens} <- TokenSet.bind_dpop(tokens, dpop_jkt),
         {:ok, claims} <- verify_refresh_id_token(tokens, put_resolved_jwks(opts, jwks)) do
      tokens =
        tokens
        |> Map.merge(profile)
        |> Map.put(:id_token_alg, Keyword.fetch!(opts, :id_token_alg))
        |> Map.put(:resources, Map.get(old_tokens, :resources))

      {:ok, %RefreshResult{tokens: tokens, id_token_claims: claims}}
    end
  end

  defp requested_scope(nil), do: nil
  defp requested_scope(scopes), do: Enum.join(scopes, " ")

  defp refresh_protocol(opts) do
    case Keyword.get(opts, :protocol, :oidc) do
      protocol when protocol in [:oauth, :oidc] -> {:ok, protocol}
      _invalid -> {:error, :invalid_protocol}
    end
  end

  defp require_refresh_subject(:oauth, _opts), do: :ok

  defp require_refresh_subject(:oidc, opts) do
    case required_string(opts, :subject) do
      {:ok, _subject} -> :ok
      {:error, _reason} = error -> error
    end
  end

  defp refresh_jwks(opts, issuer) do
    if Keyword.get(opts, :protocol, :oidc) == :oauth,
      do: {:ok, nil},
      else: Issuer.resolve_jwks(opts, issuer)
  end

  defp new_profile(opts) do
    with {:ok, profile} <- AuthorizationProfile.select(opts) do
      profile_binding(profile, opts)
    end
  end

  defp profile_binding(:generic, opts) do
    {:ok,
     %{
       profile: :generic,
       client_auth_binding: nil,
       client_id: Keyword.get(opts, :client_id),
       issuer: Keyword.get(opts, :issuer)
     }}
  end

  defp profile_binding(profile, opts) do
    with {:ok, client_id} <- required_string(opts, :client_id),
         {:ok, issuer} <- required_string(opts, :issuer),
         :ok <- AttestoClient.Discovery.validate_issuer_identifier(issuer, opts),
         {:ok, binding} <- AuthorizationProfile.bind(profile, client_id, issuer, opts) do
      {:ok,
       %{profile: profile, client_auth_binding: binding, client_id: client_id, issuer: issuer}}
    end
  end

  defp refresh_profile(tokens, opts) do
    stored = Map.get(tokens, :profile, :generic)

    with {:ok, profile} <- AuthorizationProfile.reconcile(stored, opts) do
      retained_profile(stored, profile, tokens, opts)
    end
  end

  defp retained_profile(:generic, selected, _tokens, opts), do: profile_binding(selected, opts)

  defp retained_profile(stored, _selected, tokens, opts) do
    with :ok <-
           AuthorizationProfile.check(
             stored,
             tokens.client_auth_binding,
             tokens.client_id,
             tokens.issuer,
             opts
           ) do
      {:ok, Map.take(tokens, [:profile, :client_auth_binding, :client_id, :issuer])}
    end
  end

  defp check_refresh_profile({:ok, %RefreshResult{tokens: tokens}} = result, profile) do
    if Map.take(tokens, Map.keys(profile)) == profile,
      do: result,
      else: {:error, :client_auth_mismatch}
  end

  defp check_refresh_profile(error, _profile), do: error

  defp refresh_dpop_binding(tokens, opts) do
    stored_jkt = Map.get(tokens, :dpop_jkt)
    required? = TokenSet.dpop?(tokens.token_type) or not is_nil(stored_jkt)

    with {:ok, presented_jkt} <- TokenSet.dpop_thumbprint(opts),
         :ok <- require_dpop_key(required?, presented_jkt),
         :ok <- same_dpop_key(stored_jkt, presented_jkt) do
      {:ok, presented_jkt}
    end
  end

  defp require_dpop_key(true, nil), do: {:error, :missing_dpop_key}
  defp require_dpop_key(_required, _presented), do: :ok

  defp same_dpop_key(nil, _presented), do: :ok

  defp same_dpop_key(stored, presented) when is_binary(stored) and is_binary(presented) do
    if SecureCompare.equal?(stored, presented), do: :ok, else: {:error, :dpop_key_mismatch}
  end

  defp same_dpop_key(_stored, _presented), do: {:error, :dpop_key_mismatch}

  defp check_refresh_result_binding({:ok, %RefreshResult{tokens: tokens}} = result, presented) do
    with :ok <- same_result_dpop_key(presented, Map.get(tokens, :dpop_jkt)), do: result
  end

  defp check_refresh_result_binding(error, _presented), do: error

  defp same_result_dpop_key(nil, nil), do: :ok

  defp same_result_dpop_key(presented, returned)
       when is_binary(presented) and is_binary(returned) do
    same_dpop_key(presented, returned)
  end

  defp same_result_dpop_key(_presented, _returned), do: {:error, :dpop_key_mismatch}

  defp verify_refresh_id_token(tokens, opts) when is_list(opts) do
    if Keyword.get(opts, :protocol, :oidc) == :oauth,
      do: {:ok, nil},
      else: verify_oidc_refresh_id_token(tokens, opts)
  end

  defp verify_oidc_refresh_id_token(%TokenSet{id_token: nil}, _opts), do: {:ok, nil}

  defp verify_oidc_refresh_id_token(%TokenSet{id_token: id_token} = tokens, opts) do
    with {:ok, issuer} <- required_string(opts, :issuer),
         {:ok, client_id} <- required_string(opts, :client_id),
         {:ok, id_token_alg} <- id_token_alg(opts) do
      verify_opts =
        [
          issuer: Issuer.option(opts, issuer),
          issuer_aliases: Keyword.get(opts, :issuer_aliases),
          clock_skew_seconds: Keyword.get(opts, :clock_skew_seconds),
          expiry_leeway_seconds: Keyword.get(opts, :expiry_leeway_seconds),
          max_token_age_seconds: Keyword.get(opts, :max_token_age_seconds),
          require_auth_time: Keyword.get(opts, :require_auth_time),
          require_typ: Keyword.get(opts, :require_typ, false),
          require_kid: Keyword.get(opts, :require_kid, false),
          trusted_audiences: Keyword.get(opts, :trusted_audiences),
          client_id: client_id,
          subject: Keyword.get(opts, :subject),
          metadata: Keyword.get(opts, :metadata),
          jwks: Keyword.get(opts, :jwks),
          access_token: tokens.access_token,
          accepted_algs: [id_token_alg],
          enforce_fapi_alg_policy: Keyword.get(opts, :retained_authorization_profile) == :fapi,
          req_options: Keyword.get(opts, :req_options, [])
        ]
        |> Enum.reject(fn {_key, value} -> is_nil(value) end)
        |> Keyword.merge(
          Keyword.take(opts, [
            :attesto_context,
            :now,
            :jwks_uri,
            :well_known,
            :resolver,
            :outbound,
            :timeout,
            :max_response_bytes
          ])
        )

      IDToken.verify(id_token, verify_opts)
    end
  end

  # The keys resolved before the request verify the returned ID Token. With an
  # issuer cache they are left to the cache, so an unknown `kid` can refresh
  # them; a caller-supplied `:jwks` is already in `opts`.
  defp put_resolved_jwks(opts, jwks) do
    cond do
      is_nil(jwks) -> opts
      Keyword.has_key?(opts, :issuer_cache) and not Keyword.has_key?(opts, :jwks) -> opts
      true -> Keyword.put(opts, :jwks, jwks)
    end
  end

  defp id_token_alg(opts) do
    fapi = Keyword.get(opts, :retained_authorization_profile) == :fapi
    alg = Keyword.get(opts, :id_token_alg, if(fapi, do: "PS256", else: "RS256"))
    allowed = if fapi, do: SigningAlg.fapi_algs(), else: SigningAlg.allowed()
    if alg in allowed, do: {:ok, alg}, else: {:error, :unsupported_alg}
  end

  defp retained_id_token_alg(tokens, opts) do
    case Map.get(tokens, :id_token_alg) do
      nil ->
        id_token_alg(opts)

      retained ->
        case Keyword.fetch(opts, :id_token_alg) do
          {:ok, requested} when requested != retained ->
            {:error, :id_token_alg_mismatch}

          _matching_or_omitted ->
            id_token_alg(Keyword.put(opts, :id_token_alg, retained))
        end
    end
  end

  defp refresh_id_token_alg(:oauth, _tokens, _opts), do: {:ok, nil}

  defp refresh_id_token_alg(:oidc, tokens, opts), do: retained_id_token_alg(tokens, opts)

  defp check_refresh_id_token_alg({:ok, %RefreshResult{tokens: tokens}} = result, expected) do
    if Map.get(tokens, :id_token_alg) == expected,
      do: result,
      else: {:error, :id_token_alg_mismatch}
  end

  defp check_refresh_id_token_alg(error, _expected), do: error

  defp token_type_hint(opts) do
    case Keyword.get(opts, :token_type_hint) do
      nil -> {:ok, nil}
      hint when hint in ["access_token", "refresh_token"] -> {:ok, hint}
      _invalid -> {:error, :invalid_token_type_hint}
    end
  end

  defp required_string(opts, key) do
    AttestoClient.InputValidation.required_string(opts, key, missing_error(key))
  end

  defp missing_error(:token_endpoint), do: :missing_token_endpoint
  defp missing_error(:revocation_endpoint), do: :missing_revocation_endpoint
  defp missing_error(:issuer), do: :missing_issuer
  defp missing_error(:client_id), do: :missing_client_id
  defp missing_error(:subject), do: :missing_subject

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)
end
