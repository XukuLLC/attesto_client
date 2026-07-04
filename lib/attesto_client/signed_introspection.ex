defmodule AttestoClient.SignedIntrospection do
  @moduledoc """
  Verify RFC 9701 signed token introspection responses.

  This is the client-side mirror of `Attesto.SignedIntrospection.response_jwt/4`.
  A resource server that requests `application/token-introspection+jwt` receives
  a signed JWT wrapping the RFC 7662 response in `token_introspection`; this
  module verifies the authorization server signature and registered claims.
  """

  alias Attesto.SigningAlg
  alias AttestoClient.Verifier

  @clock_skew_seconds 60
  @typ "token-introspection+jwt"

  @type jwks :: %{optional(String.t()) => term()} | [map()] | map()

  @type verify_opt ::
          {:issuer, String.t()}
          | {:audience, String.t()}
          | {:jwks, jwks()}
          | {:metadata, map()}
          | {:jwks_uri, String.t()}
          | {:accepted_algs, [SigningAlg.alg()]}
          | {:now, integer() | DateTime.t()}
          | {:req_options, keyword()}
          | {:well_known, AttestoClient.Discovery.well_known()}

  @type error ::
          :missing_issuer
          | :missing_audience
          | :invalid_jwks
          | :invalid_metadata
          | :issuer_mismatch
          | :unsupported_alg
          | :invalid_token
          | :invalid_signature
          | :unsupported_critical_header
          | :invalid_typ
          | :invalid_issuer
          | :invalid_audience
          | :invalid_claims
          | :invalid_iat
          | :not_yet_valid
          | :expired
          | AttestoClient.Discovery.error()

  @doc """
  Verify a signed introspection response JWT.

  Required options: `:issuer` and `:audience` (the introspecting client or
  resource server). JWKS may be supplied through `:jwks`, `:metadata`,
  `:jwks_uri`, or fetched through discovery from `:issuer`.
  """
  @spec verify(String.t(), [verify_opt()]) :: {:ok, map()} | {:error, error()}
  def verify(jwt, opts) when is_binary(jwt) and is_list(opts) do
    now = Verifier.now(opts)

    with {:ok, issuer} <- Verifier.require_string(opts, :issuer, :missing_issuer),
         {:ok, audience} <- Verifier.require_string(opts, :audience, :missing_audience),
         {:ok, jwks} <- Verifier.resolve_jwks(opts, issuer),
         {:ok, algs} <- Verifier.accepted_algs(opts),
         {:ok, claims, header} <- Verifier.verify_signature(jwt, jwks, algs),
         :ok <- check_typ(header),
         :ok <- check_issuer(claims, issuer),
         :ok <- check_audience(claims, audience),
         :ok <- check_claims(claims),
         :ok <- check_iat(claims, now),
         :ok <- check_expiry(claims, now) do
      {:ok, claims}
    end
  end

  def verify(_jwt, _opts), do: {:error, :invalid_token}

  defp check_typ(%{"typ" => typ}) when is_binary(typ) do
    if String.downcase(typ) == @typ, do: :ok, else: {:error, :invalid_typ}
  end

  defp check_typ(_header), do: {:error, :invalid_typ}

  defp check_issuer(%{"iss" => iss}, issuer) when is_binary(iss) do
    if iss == issuer, do: :ok, else: {:error, :invalid_issuer}
  end

  defp check_issuer(_claims, _issuer), do: {:error, :invalid_issuer}

  defp check_audience(%{"aud" => aud}, audience) when is_binary(aud) do
    if aud == audience, do: :ok, else: {:error, :invalid_audience}
  end

  defp check_audience(%{"aud" => auds}, audience) when is_list(auds) do
    if Enum.all?(auds, &is_binary/1) and audience in auds,
      do: :ok,
      else: {:error, :invalid_audience}
  end

  defp check_audience(_claims, _audience), do: {:error, :invalid_audience}

  defp check_claims(%{"token_introspection" => %{"active" => active}}) when is_boolean(active),
    do: :ok

  defp check_claims(_claims), do: {:error, :invalid_claims}

  defp check_iat(%{"iat" => iat}, now) when is_integer(iat) and iat >= 0 do
    if iat <= now + @clock_skew_seconds, do: :ok, else: {:error, :not_yet_valid}
  end

  defp check_iat(_claims, _now), do: {:error, :invalid_iat}

  defp check_expiry(%{"exp" => exp}, now) when is_integer(exp) do
    if exp > now, do: :ok, else: {:error, :expired}
  end

  defp check_expiry(%{"exp" => _bad}, _now), do: {:error, :expired}
  defp check_expiry(_claims, _now), do: :ok
end
