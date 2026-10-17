defmodule AttestoClient.UserInfo do
  @moduledoc """
  Verify signed OpenID Connect UserInfo responses.

  This verifier covers OIDC Core §5.3.2 signed UserInfo responses: it verifies
  the authorization server signature, requires `iss` and `aud` to identify the
  issuer and relying party, and returns the string-keyed claims. When the caller
  supplies `:id_token_sub`, the UserInfo `sub` must match the ID Token subject.
  """

  alias Attesto.SigningAlg
  alias AttestoClient.{ClaimValidation, Verifier}

  @clock_skew_seconds 60

  @type jwks :: %{optional(String.t()) => term()} | [map()] | map()

  @type verify_opt ::
          {:issuer, String.t()}
          | {:client_id, String.t()}
          | {:id_token_sub, String.t()}
          | {:jwks, jwks()}
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
          | :ambiguous_key
          | :weak_key
          | :unsupported_critical_header
          | :unexpected_typ
          | :invalid_issuer
          | :invalid_audience
          | :invalid_claims
          | :sub_mismatch
          | :expired
          | :invalid_iat
          | :invalid_nbf
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
         {:ok, claims, header, _verified_jwk} <- Verifier.verify_signature(jwt, jwks, algs),
         :ok <- check_typ(header),
         :ok <- check_issuer(claims, issuer),
         :ok <- ClaimValidation.audience(claims, client_id, :invalid_audience),
         :ok <- check_subject(claims, Keyword.get(opts, :id_token_sub)),
         :ok <-
           ClaimValidation.expiration(claims, now,
             invalid_error: :expired,
             expired_error: :expired
           ),
         :ok <-
           ClaimValidation.issued_at(claims, now,
             invalid_error: :invalid_iat,
             future_error: :not_yet_valid,
             skew: @clock_skew_seconds
           ),
         :ok <-
           ClaimValidation.not_before(claims, now,
             invalid_error: :invalid_nbf,
             future_error: :not_yet_valid,
             skew: @clock_skew_seconds
           ) do
      {:ok, claims}
    end
  end

  def verify(_jwt, _opts), do: {:error, :invalid_token}

  defp check_typ(%{"typ" => typ}) when is_binary(typ) do
    if String.downcase(typ) == "jwt", do: :ok, else: {:error, :unexpected_typ}
  end

  defp check_typ(%{"typ" => _other}), do: {:error, :unexpected_typ}
  defp check_typ(_header), do: :ok

  defp check_issuer(%{"iss" => iss}, issuer) when is_binary(iss) do
    if iss == issuer, do: :ok, else: {:error, :invalid_issuer}
  end

  defp check_issuer(_claims, _issuer), do: {:error, :invalid_issuer}

  defp check_subject(%{"sub" => sub}, nil) when is_binary(sub) and sub != "", do: :ok

  defp check_subject(%{"sub" => sub}, expected) when is_binary(sub) and is_binary(expected) do
    if sub == expected, do: :ok, else: {:error, :sub_mismatch}
  end

  defp check_subject(_claims, _expected), do: {:error, :invalid_claims}
end
