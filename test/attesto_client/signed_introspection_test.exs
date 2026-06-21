defmodule AttestoClient.SignedIntrospectionTest do
  use ExUnit.Case, async: true

  alias AttestoClient.SignedIntrospection

  @issuer "https://op.example.com"
  @audience "rs-1"
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

  defp config do
    Attesto.Config.new(
      issuer: @issuer,
      audience: @issuer,
      keystore: Keystore,
      principal_kinds: [Attesto.PrincipalKind.new("client", "oc_")]
    )
  end

  defp jwks, do: Attesto.JWKS.from_keystore(Keystore)

  defp verify(jwt, opts \\ []) do
    SignedIntrospection.verify(
      jwt,
      Keyword.merge([issuer: @issuer, audience: @audience, jwks: jwks(), now: @now], opts)
    )
  end

  defp sign(claims, header_overrides \\ %{}) do
    pem = Keystore.signing_pem()
    jwk = Attesto.Key.signing_jwk(pem)

    header =
      %{"alg" => "RS256", "kid" => Attesto.Key.kid(pem), "typ" => "token-introspection+jwt"}
      |> Map.merge(header_overrides)

    {_, jwt} = jwk |> JOSE.JWS.sign(JSON.encode!(claims), header) |> JOSE.JWS.compact()
    jwt
  end

  defp claims(overrides \\ %{}) do
    Map.merge(
      %{
        "iss" => @issuer,
        "aud" => @audience,
        "iat" => @now,
        "token_introspection" => %{"active" => true, "sub" => "usr_1"}
      },
      overrides
    )
  end

  describe "verify/2" do
    test "verifies a response signed by attesto's server-side builder" do
      response = %{"active" => true, "scope" => "read"}

      {:ok, jwt} =
        Attesto.SignedIntrospection.response_jwt(config(), @audience, response,
          now: @now,
          lifetime: 60
        )

      assert {:ok, verified} = verify(jwt)
      assert verified["iss"] == @issuer
      assert verified["aud"] == @audience
      assert verified["token_introspection"] == response
    end

    test "accepts a response without exp and with aud array" do
      jwt = sign(claims(%{"aud" => ["other", @audience]}))

      assert {:ok, _claims} = verify(jwt)
    end

    test "compares the media-type typ case-insensitively" do
      jwt = sign(claims(), %{"typ" => "Token-Introspection+JWT"})

      assert {:ok, _claims} = verify(jwt)
    end

    test "rejects bad registered claims and typ" do
      assert {:error, :invalid_typ} = verify(sign(claims(), %{"typ" => "JWT"}))
      assert {:error, :invalid_issuer} = verify(sign(claims(%{"iss" => "https://evil.example"})))
      assert {:error, :invalid_audience} = verify(sign(claims(%{"aud" => "other"})))

      assert {:error, :invalid_claims} =
               verify(sign(claims(%{"token_introspection" => "active"})))

      assert {:error, :invalid_claims} =
               verify(sign(claims(%{"token_introspection" => %{"sub" => "usr_1"}})))

      assert {:error, :invalid_claims} =
               verify(sign(claims(%{"token_introspection" => %{"active" => "true"}})))

      assert {:error, :not_yet_valid} = verify(sign(claims(%{"iat" => @now + 120})))
      assert {:error, :expired} = verify(sign(claims(%{"exp" => @now - 1})))
    end

    test "rejects signature and missing options" do
      other = JOSE.JWK.generate_key({:rsa, 2048})
      {_, jwt} = other |> JOSE.JWT.sign(%{"alg" => "RS256"}, claims()) |> JOSE.JWS.compact()

      assert {:error, :invalid_signature} = verify(jwt)

      assert {:error, :missing_issuer} =
               SignedIntrospection.verify(jwt, audience: @audience, jwks: jwks())

      assert {:error, :missing_audience} =
               SignedIntrospection.verify(jwt, issuer: @issuer, jwks: jwks())
    end
  end
end
