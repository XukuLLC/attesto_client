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

  alias Attesto.SigningAlg
  alias AttestoClient.IDToken
  alias AttestoClient.OAuthHTTP
  alias AttestoClient.RefreshCoordinator
  alias AttestoClient.RefreshResult
  alias AttestoClient.TokenSet
  alias AttestoClient.Verifier

  @default_timeout_ms 10_000

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
         {:ok, _id_token_alg} <- id_token_alg(opts) do
      RefreshCoordinator.run(
        coordinator,
        key,
        fn -> do_refresh(tokens, opts) end,
        timeout_ms
      )
    end
  end

  def refresh(_coordinator, _key, %TokenSet{}, _opts), do: {:error, :missing_refresh_token}
  def refresh(_coordinator, _key, _tokens, _opts), do: {:error, :invalid_token_set}

  @doc """
  Revoke a token according to RFC 7009.

  A successful 2xx response is `:ok`, including when the server did not know
  the token. Required options: `:revocation_endpoint`, `:client_id`; optional
  `:token_type_hint`, `:client_auth`, `:req_options`, and `:timeout`.
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

  defp do_refresh(%TokenSet{refresh_token: refresh_token, scope: old_scope}, opts) do
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
         {:ok, claims} <- verify_refresh_id_token(tokens, Keyword.put(opts, :jwks, jwks)) do
      {:ok, %RefreshResult{tokens: tokens, id_token_claims: claims}}
    end
  end

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
          req_options: Keyword.get(opts, :req_options, [])
        ]
        |> Enum.reject(fn {_key, value} -> is_nil(value) end)

      IDToken.verify(id_token, verify_opts)
    end
  end

  defp id_token_alg(opts) do
    alg = Keyword.get(opts, :id_token_alg, "RS256")
    if alg in SigningAlg.allowed(), do: {:ok, alg}, else: {:error, :unsupported_alg}
  end

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
