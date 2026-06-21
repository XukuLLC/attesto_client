defmodule AttestoClient.UserInfo do
  @moduledoc """
  Verify signed OpenID Connect UserInfo responses.

  This verifier covers OIDC Core §5.3.2 signed UserInfo responses: it verifies
  the authorization server signature, requires `iss` and `aud` to identify the
  issuer and relying party, and returns the string-keyed claims. When the caller
  supplies `:id_token_sub`, the UserInfo `sub` must match the ID Token subject.
  """

  alias Attesto.SigningAlg
  alias AttestoClient.Verifier

  @clock_skew_seconds 60

  @type verify_opt ::
          {:issuer, String.t()}
          | {:client_id, String.t()}
          | {:id_token_sub, String.t()}
          | {:jwks, Verifier.jwks()}
          | {:metadata, map()}
          | {:jwks_uri, String.t()}
          | {:accepted_algs, [SigningAlg.alg()]}
          | {:now, integer() | DateTime.t()}
          | {:req_options, keyword()}
          | {:well_known, AttestoClient.Discovery.well_known()}

  @type error ::
          :missing_issuer
          | :missing_client_id
          | :invalid_jwks
          | :invalid_metadata
          | :issuer_mismatch
          | :unsupported_alg
          | :invalid_token
          | :invalid_signature
          | :unsupported_critical_header
          | :unexpected_typ
          | :invalid_issuer
          | :invalid_audience
          | :invalid_claims
          | :sub_mismatch
          | :expired
          | :invalid_iat
          | :not_yet_valid
          | AttestoClient.Discovery.error()

  @doc """
  Verify a signed UserInfo JWT.

  Required options: `:issuer` and `:client_id`. Pass `:id_token_sub` to bind the
  UserInfo response back to a previously verified ID Token.
  """
  @spec verify(String.t(), [verify_opt()]) :: {:ok, map()} | {:error, error()}
  def verify(jwt, opts) when is_binary(jwt) and is_list(opts) do
    now = Verifier.now(opts)

    with {:ok, issuer} <- Verifier.require_string(opts, :issuer, :missing_issuer),
         {:ok, client_id} <- Verifier.require_string(opts, :client_id, :missing_client_id),
         {:ok, jwks} <- Verifier.resolve_jwks(opts, issuer),
         {:ok, algs} <- Verifier.accepted_algs(opts),
         {:ok, claims, header} <- Verifier.verify_signature(jwt, jwks, algs),
         :ok <- check_typ(header),
         :ok <- check_issuer(claims, issuer),
         :ok <- check_audience(claims, client_id),
         :ok <- check_subject(claims, Keyword.get(opts, :id_token_sub)),
         :ok <- check_expiry(claims, now),
         :ok <- check_issued_at(claims, now) do
      {:ok, claims}
    end
  end

  def verify(_jwt, _opts), do: {:error, :invalid_token}

  defp check_typ(%{"typ" => "JWT"}), do: :ok
  defp check_typ(%{"typ" => _other}), do: {:error, :unexpected_typ}
  defp check_typ(_header), do: :ok

  defp check_issuer(%{"iss" => iss}, issuer) when is_binary(iss) do
    if iss == issuer, do: :ok, else: {:error, :invalid_issuer}
  end

  defp check_issuer(_claims, _issuer), do: {:error, :invalid_issuer}

  defp check_audience(%{"aud" => aud}, client_id) when is_binary(aud) do
    if aud == client_id, do: :ok, else: {:error, :invalid_audience}
  end

  defp check_audience(%{"aud" => auds}, client_id) when is_list(auds) do
    if Enum.all?(auds, &is_binary/1) and client_id in auds,
      do: :ok,
      else: {:error, :invalid_audience}
  end

  defp check_audience(_claims, _client_id), do: {:error, :invalid_audience}

  defp check_subject(%{"sub" => sub}, nil) when is_binary(sub) and sub != "", do: :ok

  defp check_subject(%{"sub" => sub}, expected) when is_binary(sub) and is_binary(expected) do
    if sub == expected, do: :ok, else: {:error, :sub_mismatch}
  end

  defp check_subject(_claims, _expected), do: {:error, :invalid_claims}

  defp check_expiry(%{"exp" => exp}, now) when is_integer(exp) do
    if exp > now, do: :ok, else: {:error, :expired}
  end

  defp check_expiry(%{"exp" => _bad}, _now), do: {:error, :expired}
  defp check_expiry(_claims, _now), do: :ok

  defp check_issued_at(%{"iat" => iat}, now) when is_integer(iat) and iat >= 0 do
    if iat <= now + @clock_skew_seconds, do: :ok, else: {:error, :not_yet_valid}
  end

  defp check_issued_at(%{"iat" => _bad}, _now), do: {:error, :invalid_iat}
  defp check_issued_at(_claims, _now), do: :ok
end
