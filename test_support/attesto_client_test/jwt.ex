defmodule AttestoClient.Test.JWT do
  @moduledoc false

  @spec public_jwk(JOSE.JWK.t(), map()) :: map()
  def public_jwk(jwk, overrides \\ %{}) when is_map(overrides) do
    {_metadata, public} = JOSE.JWK.to_public_map(jwk)
    Map.merge(public, overrides)
  end

  @spec sign_compact(JOSE.JWK.t(), map(), map()) :: String.t()
  def sign_compact(jwk, claims, header) when is_map(claims) and is_map(header) do
    {_jws, compact} = jwk |> JOSE.JWT.sign(header, claims) |> JOSE.JWS.compact()
    compact
  end
end
