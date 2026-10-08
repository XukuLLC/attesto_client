defmodule AttestoClient.Token do
  @moduledoc """
  Refresh and revoke OAuth tokens.

  Network operations are deadline-bound and are never retried because a timeout
  can leave the remote outcome unknown. Refresh-token rotation is available
  through `refresh/4`, which uses `AttestoClient.RefreshCoordinator` to prevent
  concurrent reuse for the same application record.

  Returned tokens are not persisted by this library. Applications must perform
  any compare-and-swap update and choose their own token/session retention
  policy.
  """

  alias Attesto.SecureCompare
  alias Attesto.SigningAlg
  alias AttestoClient.AuthorizationProfile
  alias AttestoClient.IDToken
  alias AttestoClient.OAuthHTTP
  alias AttestoClient.RefreshCoordinator
  alias AttestoClient.RefreshResult
  alias AttestoClient.TokenSet
  alias AttestoClient.Verifier

  @default_timeout_ms 10_000
  @pre_authorized_code_grant_type "urn:ietf:params:oauth:grant-type:pre-authorized_code"

  @doc """
  Exchange an OID4VCI pre-authorized code for an access token
  (`urn:ietf:params:oauth:grant-type:pre-authorized_code`,
  `OpenID4VCI 1.0 Final` §6.1/§6.2) - the wallet-holder token step
  ahead of `AttestoClient.Wallet.request_credential/3`.

  Required option: `:token_endpoint`. Private-key JWT authentication also
  uses `:issuer` from trusted discovery when supplied. An omitted issuer
  retains the deprecated endpoint-audience fallback in 2.x. `:client_id`, `:client_auth`, and
  `:req_options` behave as for `refresh/4` - the pre-authorized_code grant
  still authenticates the wallet the same way any other grant does. Pass
  `:tx_code` when the offer's grant carried a `tx_code` object, i.e. the end
  user must key in the transaction code the issuer displayed out of band.

  Returns `{:ok, token_set}`; the ID Token, if any, is returned unverified
  since OID4VCI defines no binding claims for it here.
  """
  @spec exchange_pre_authorized_code(String.t(), keyword()) ::
          {:ok, TokenSet.t()} | {:error, term()}
  def exchange_pre_authorized_code(pre_authorized_code, opts)
      when is_binary(pre_authorized_code) and pre_authorized_code != "" and is_list(opts) do
    with {:ok, endpoint} <- required_string(opts, :token_endpoint),
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

  Required options are `:token_endpoint`, `:issuer`, `:client_id`, and the
  `:subject` from the previously verified ID Token; `:client_auth` and
  `:req_options` match
  `AttestoClient.AuthorizationCode.callback/3`. The issuer is validated before
  the request so an ID Token returned with a rotated refresh token can always
  be verified rather than losing the rotation result after the response.

  `:client_auth` also accepts
  `{:private_key_jwt, jwk, assertion_opts}` for an explicitly registered
  assertion algorithm, key id, audience, lifetime, time, or JWT id.

  A prior DPoP token set requires `:dpop` signing material before any network
  request. Persisted `tokens.dpop_jkt` must match that key; a missing or changed
  key is rejected locally. A requested or prior DPoP token cannot accept a
  Bearer response. Shared results are also checked against each caller's key
  before adoption. Legacy token sets without a thumbprint require a key, but
  their historical key continuity cannot be checked; a successful DPoP response
  records the supplied key for subsequent refreshes.

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
    with {:ok, timeout_ms} <- timeout(opts),
         {:ok, _endpoint} <- required_string(opts, :token_endpoint),
         {:ok, issuer} <- required_string(opts, :issuer),
         :ok <- AttestoClient.Discovery.validate_issuer_identifier(issuer),
         {:ok, _client_id} <- required_string(opts, :client_id),
         {:ok, _subject} <- required_string(opts, :subject),
         {:ok, profile} <- refresh_profile(tokens, opts),
         opts = Keyword.put(opts, :retained_authorization_profile, profile.profile),
         {:ok, id_token_alg} <- retained_id_token_alg(tokens, opts),
         opts = Keyword.put(opts, :id_token_alg, id_token_alg),
         {:ok, dpop_jkt} <- refresh_dpop_binding(tokens, opts),
         :ok <- AuthorizationProfile.require_dpop(profile.profile, dpop_jkt),
         :ok <- AuthorizationProfile.dpop_policy(profile.profile, opts) do
      RefreshCoordinator.run(
        coordinator,
        key,
        fn -> do_refresh(tokens, dpop_jkt, profile, opts) end,
        timeout_ms
      )
      |> check_refresh_result_binding(dpop_jkt)
      |> check_refresh_profile(profile)
      |> check_refresh_id_token_alg(id_token_alg)
    end
  end

  def refresh(_coordinator, _key, %TokenSet{}, _opts), do: {:error, :missing_refresh_token}
  def refresh(_coordinator, _key, _tokens, _opts), do: {:error, :invalid_token_set}

  @doc """
  Revoke a token according to RFC 7009.

  A successful 2xx response is `:ok`, including when the server did not know
  the token. Required options: `:revocation_endpoint`, `:client_id`; optional
  `:token_type_hint`, `:client_auth`, `:req_options`, and `:timeout`.
  With `private_key_jwt`, pass `:issuer` from trusted discovery, or an explicit
  registered audience in the assertion options for a legacy server. Omitting
  both retains the deprecated endpoint-audience fallback in 2.x.
  """
  @spec revoke(String.t(), keyword()) :: :ok | {:error, term()}
  def revoke(token, opts) when is_binary(token) and token != "" and is_list(opts) do
    with {:ok, endpoint} <- required_string(opts, :revocation_endpoint),
         {:ok, hint} <- token_type_hint(opts) do
      form = %{"token" => token} |> maybe_put("token_type_hint", hint)
      OAuthHTTP.post_form_unit(endpoint, form, opts)
    end
  end

  def revoke(_token, _opts), do: {:error, :invalid_token}

  defp do_refresh(
         %TokenSet{refresh_token: refresh_token, scope: old_scope},
         dpop_jkt,
         profile,
         opts
       ) do
    with {:ok, endpoint} <- required_string(opts, :token_endpoint),
         {:ok, issuer} <- required_string(opts, :issuer),
         {:ok, jwks} <- Verifier.resolve_jwks(opts, issuer),
         {:ok, response} <-
           OAuthHTTP.post_form(
             endpoint,
             %{"grant_type" => "refresh_token", "refresh_token" => refresh_token},
             opts
           ),
         {:ok, tokens} <- TokenSet.from_response(response, refresh_token, old_scope),
         {:ok, tokens} <- TokenSet.bind_dpop(tokens, dpop_jkt),
         {:ok, claims} <- verify_refresh_id_token(tokens, Keyword.put(opts, :jwks, jwks)) do
      tokens =
        tokens
        |> Map.merge(profile)
        |> Map.put(:id_token_alg, Keyword.fetch!(opts, :id_token_alg))

      {:ok, %RefreshResult{tokens: tokens, id_token_claims: claims}}
    end
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
         :ok <- AttestoClient.Discovery.validate_issuer_identifier(issuer),
         {:ok, binding} <- AuthorizationProfile.bind(profile, client_id, issuer, opts) do
      {:ok,
       %{profile: profile, client_auth_binding: binding, client_id: client_id, issuer: issuer}}
    end
  end

  defp refresh_profile(tokens, opts) do
    stored = Map.get(tokens, :profile, :generic)

    with {:ok, selected} <- AuthorizationProfile.select(opts),
         true <- stored in [:generic, :haip, :fapi],
         true <- stored == :generic or selected in [:generic, stored] do
      retained_profile(stored, selected, tokens, opts)
    else
      false -> {:error, :profile_mismatch}
      error -> error
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

  defp verify_refresh_id_token(%TokenSet{id_token: nil}, _opts), do: {:ok, nil}

  defp verify_refresh_id_token(%TokenSet{id_token: id_token} = tokens, opts) do
    with {:ok, issuer} <- required_string(opts, :issuer),
         {:ok, client_id} <- required_string(opts, :client_id),
         {:ok, id_token_alg} <- id_token_alg(opts) do
      verify_opts =
        [
          issuer: issuer,
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

      IDToken.verify(id_token, verify_opts)
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

  defp check_refresh_id_token_alg({:ok, %RefreshResult{tokens: tokens}} = result, expected) do
    if Map.get(tokens, :id_token_alg) == expected,
      do: result,
      else: {:error, :id_token_alg_mismatch}
  end

  defp check_refresh_id_token_alg(error, _expected), do: error

  defp timeout(opts) do
    case Keyword.get(opts, :timeout, @default_timeout_ms) do
      timeout when is_integer(timeout) and timeout > 0 -> {:ok, timeout}
      _invalid -> {:error, :invalid_timeout}
    end
  end

  defp token_type_hint(opts) do
    case Keyword.get(opts, :token_type_hint) do
      nil -> {:ok, nil}
      hint when hint in ["access_token", "refresh_token"] -> {:ok, hint}
      _invalid -> {:error, :invalid_token_type_hint}
    end
  end

  defp required_string(opts, key) do
    case Keyword.get(opts, key) do
      value when is_binary(value) and value != "" -> {:ok, value}
      _invalid -> {:error, missing_error(key)}
    end
  end

  defp missing_error(:token_endpoint), do: :missing_token_endpoint
  defp missing_error(:revocation_endpoint), do: :missing_revocation_endpoint
  defp missing_error(:issuer), do: :missing_issuer
  defp missing_error(:client_id), do: :missing_client_id
  defp missing_error(:subject), do: :missing_subject

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)
end
