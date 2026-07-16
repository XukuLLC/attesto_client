defmodule AttestoClient.AuthorizationCode do
  @moduledoc """
  OpenID Connect Authorization Code flow with S256 PKCE.

  `start/2` validates discovery metadata, creates high-entropy state, nonce, and
  PKCE values, stores the transaction with a finite lifetime, and returns the
  authorization URL. `callback/3` atomically consumes state, exchanges the code
  exactly once, and verifies the ID Token against the stored issuer, client,
  nonce, configured algorithm, and returned access token.

  The store protects protocol correlation only. Applications remain
  responsible for deciding whether verified claims authorize a user, creating
  or retaining a session, and persisting rotated tokens.
  """

  alias Attesto.SigningAlg
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
  @reserved_params ~w(client_id redirect_uri response_type scope state nonce code_challenge code_challenge_method)

  @type store :: Store.store()

  @doc """
  Begin an authorization transaction.

  Required options are `:issuer`, `:client_id`, and `:redirect_uri`. Discovery
  is fetched unless `:metadata` is supplied. `:scopes` defaults to `["openid"]`
  and must include `openid`. `:id_token_alg` defaults to `"RS256"` and must
  match the client's registration and the provider metadata.

  Additional request values may be supplied in `:authorization_params`, but
  protocol-bound parameters cannot be overridden.
  """
  @spec start(store(), keyword()) ::
          {:ok, %{url: String.t(), state: String.t(), expires_in: pos_integer()}}
          | {:error, term()}
  def start(store, opts) when is_list(opts) do
    default_ttl_ms = @default_transaction_ttl_ms

    with {:ok, issuer} <- required_string(opts, :issuer),
         {:ok, client_id} <- required_string(opts, :client_id),
         {:ok, redirect_uri} <- redirect_uri(opts),
         {:ok, scopes} <- scopes(opts),
         {:ok, extra_params} <- authorization_params(opts),
         {:ok, ttl_ms} <- positive_integer(opts, :transaction_ttl_ms, default_ttl_ms),
         {:ok, id_token_alg} <- id_token_alg(opts),
         {:ok, metadata} <- OpenIDMetadata.resolve(issuer, opts),
         :ok <- metadata_supports_alg(metadata, id_token_alg),
         {:ok, state, transaction} <-
           store_transaction(
             store,
             issuer,
             client_id,
             redirect_uri,
             metadata,
             id_token_alg,
             ttl_ms
           ) do
      params =
        Map.merge(extra_params, %{
          "client_id" => client_id,
          "redirect_uri" => redirect_uri,
          "response_type" => "code",
          "scope" => Enum.join(scopes, " "),
          "state" => state,
          "nonce" => transaction.nonce,
          "code_challenge" => code_challenge!(transaction.code_verifier),
          "code_challenge_method" => "S256"
        })

      {:ok,
       %{
         url: put_query(metadata["authorization_endpoint"], params),
         state: state,
         expires_in: div(ttl_ms + 999, 1_000)
       }}
    end
  end

  def start(_store, _opts), do: {:error, :invalid_options}

  @doc """
  Consume an authorization response and complete the code exchange.

  `params` is the string-keyed callback parameter map. State is consumed before
  any token request, so replay and concurrent duplicate callbacks fail. The
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
  @spec callback(store(), map(), keyword()) ::
          {:ok, %{tokens: TokenSet.t(), id_token_claims: map()}} | {:error, term()}
  def callback(store, params, opts \\ [])

  def callback(store, params, opts) when is_map(params) and is_list(opts) do
    with {:ok, state} <- callback_state(params),
         {:ok, transaction} <- take_transaction(store, state),
         :ok <- check_response_issuer(params, transaction),
         {:ok, code} <- callback_code(params),
         {:ok, timeout_ms} <- positive_integer(opts, :timeout, @default_timeout_ms) do
      Deadline.run(fn -> exchange_and_verify(transaction, code, opts) end, timeout_ms)
    end
  end

  def callback(_store, _params, _opts), do: {:error, :invalid_callback}

  defp store_transaction(store, issuer, client_id, redirect_uri, metadata, id_token_alg, ttl_ms) do
    Enum.reduce_while(1..3, {:error, :state_collision}, fn _attempt, _acc ->
      state = random_value()

      transaction = %AuthorizationTransaction{
        state: state,
        nonce: random_value(),
        code_verifier: PKCE.code_verifier(),
        issuer: issuer,
        client_id: client_id,
        redirect_uri: redirect_uri,
        metadata: metadata,
        id_token_alg: id_token_alg
      }

      case Store.put_new(store, state, transaction, ttl_ms) do
        :ok -> {:halt, {:ok, state, transaction}}
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

    http_opts =
      opts
      |> Keyword.take([:client_auth, :req_options, :timeout])
      |> Keyword.put(:client_id, transaction.client_id)

    with {:ok, jwks} <-
           Verifier.resolve_jwks(
             [metadata: transaction.metadata, req_options: Keyword.get(opts, :req_options, [])],
             transaction.issuer
           ),
         {:ok, response} <-
           AttestoClient.OAuthHTTP.post_form(
             transaction.metadata["token_endpoint"],
             form,
             http_opts
           ),
         {:ok, tokens} <- TokenSet.from_response(response, nil),
         {:ok, id_token} <- require_id_token(tokens),
         {:ok, claims} <- verify_id_token(id_token, tokens, transaction, jwks, code) do
      {:ok, %{tokens: tokens, id_token_claims: claims}}
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
      accepted_algs: [transaction.id_token_alg]
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
    required? = transaction.metadata["authorization_response_iss_parameter_supported"] == true

    case Map.fetch(params, "iss") do
      {:ok, issuer} when issuer == transaction.issuer -> :ok
      {:ok, _wrong} -> {:error, :issuer_mismatch}
      :error when required? -> {:error, :missing_response_issuer}
      :error -> :ok
    end
  end

  defp scopes(opts) do
    case Keyword.get(opts, :scopes, ["openid"]) do
      scopes when is_list(scopes) and scopes != [] ->
        if Enum.all?(scopes, &(is_binary(&1) and &1 != "")) and "openid" in scopes,
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
            is_binary(key) and key not in @reserved_params and scalar_or_string_list?(value)
          end)

        if valid?, do: {:ok, params}, else: {:error, :invalid_authorization_params}

      _invalid ->
        {:error, :invalid_authorization_params}
    end
  end

  defp redirect_uri(opts) do
    with {:ok, value} <- required_string(opts, :redirect_uri) do
      case URI.parse(value) do
        %URI{scheme: scheme, host: host, userinfo: nil, fragment: nil}
        when scheme in ["https", "http"] and is_binary(host) and host != "" ->
          {:ok, value}

        _invalid ->
          {:error, :invalid_redirect_uri}
      end
    end
  end

  defp id_token_alg(opts) do
    alg = Keyword.get(opts, :id_token_alg, "RS256")
    if alg in SigningAlg.allowed(), do: {:ok, alg}, else: {:error, :unsupported_alg}
  end

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
  defp missing_error(:redirect_uri), do: :missing_redirect_uri

  defp invalid_error(:transaction_ttl_ms), do: :invalid_transaction_ttl_ms
  defp invalid_error(:timeout), do: :invalid_timeout

  defp scalar_or_string_list?(value) when is_binary(value), do: true
  defp scalar_or_string_list?(value) when is_integer(value), do: true

  defp scalar_or_string_list?(_value), do: false

  defp random_value, do: :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)

  defp code_challenge!(verifier) do
    {:ok, challenge} = PKCE.code_challenge(verifier)
    challenge
  end

  defp put_query(endpoint, params) do
    uri = URI.parse(endpoint)
    existing = if uri.query, do: URI.decode_query(uri.query), else: %{}
    %{uri | query: URI.encode_query(Map.merge(existing, params))} |> URI.to_string()
  end
end
