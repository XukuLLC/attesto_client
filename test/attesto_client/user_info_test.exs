defmodule AttestoClient.UserInfoTest do
  use ExUnit.Case, async: true

  alias AttestoClient.UserInfo

  @issuer "https://op.example.com"
  @client_id "client-abc"
  @subject "usr_1"
  @now 1_700_000_000

  defmodule Keystore do
    @moduledoc false
    @behaviour Attesto.Keystore

    @pem JOSE.JWK.generate_key({:rsa, 2048}) |> JOSE.JWK.to_pem() |> elem(1)

    @impl true
    def signing_pem, do: @pem

    @impl true
    def verification_pems, do: [@pem]
  end

  defp jwks, do: Attesto.JWKS.from_keystore(Keystore)

  defp claims(overrides \\ %{}) do
    Map.merge(
      %{
        "iss" => @issuer,
        "aud" => @client_id,
        "sub" => @subject,
        "iat" => @now,
        "exp" => @now + 600,
        "email" => "user@example.com"
      },
      overrides
    )
  end

  defp sign(claims, header_overrides \\ %{}) do
    pem = Keystore.signing_pem()
    jwk = Attesto.Key.signing_jwk(pem)

    header =
      %{"alg" => "RS256", "kid" => Attesto.Key.kid(pem), "typ" => "JWT"}
      |> Map.merge(header_overrides)

    {_, jwt} = jwk |> JOSE.JWS.sign(JSON.encode!(claims), header) |> JOSE.JWS.compact()
    jwt
  end

  defp verify(jwt, opts \\ []) do
    UserInfo.verify(
      jwt,
      Keyword.merge([issuer: @issuer, client_id: @client_id, jwks: jwks(), now: @now], opts)
    )
  end

  describe "verify/2" do
    test "returns claims for a valid signed UserInfo response" do
      jwt = sign(claims())

      assert {:ok, verified} = verify(jwt, id_token_sub: @subject)
      assert verified["sub"] == @subject
      assert verified["email"] == "user@example.com"
    end

    test "accepts an audience array containing the client_id" do
      jwt = sign(claims(%{"aud" => ["other", @client_id]}))

      assert {:ok, _claims} = verify(jwt)
    end

    test "rejects wrong issuer, audience, subject, typ, and time" do
      assert {:error, :invalid_issuer} = verify(sign(claims(%{"iss" => "https://evil.example"})))
      assert {:error, :invalid_audience} = verify(sign(claims(%{"aud" => "other"})))
      assert {:error, :sub_mismatch} = verify(sign(claims()), id_token_sub: "other-sub")
      assert {:error, :unexpected_typ} = verify(sign(claims(), %{"typ" => "userinfo+jwt"}))
      assert {:error, :expired} = verify(sign(claims(%{"exp" => @now - 1})))
      assert {:error, :not_yet_valid} = verify(sign(claims(%{"iat" => @now + 120})))
    end

    test "rejects missing sub, bad signature, and missing options" do
      assert {:error, :invalid_claims} = verify(sign(Map.delete(claims(), "sub")))

      other = JOSE.JWK.generate_key({:rsa, 2048})
      {_, jwt} = other |> JOSE.JWT.sign(%{"alg" => "RS256"}, claims()) |> JOSE.JWS.compact()

      assert {:error, :invalid_signature} = verify(jwt)
      assert {:error, :missing_issuer} = UserInfo.verify(jwt, client_id: @client_id, jwks: jwks())
      assert {:error, :missing_client_id} = UserInfo.verify(jwt, issuer: @issuer, jwks: jwks())
    end
  end
end
