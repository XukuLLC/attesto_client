defmodule AttestoClient.IdentityAssertionTest do
  use ExUnit.Case, async: true

  alias AttestoClient.IdentityAssertion

  @issuer "https://idp.example.com"
  @audience "https://as.example.com"
  @client_id "client-abc"
  @subject "user-123"
  @now 1_700_000_000

  defp rsa_key, do: JOSE.JWK.generate_key({:rsa, 2048})
  defp ec_key, do: JOSE.JWK.generate_key({:ec, "P-256"})

  defp public_jwks(jwk, alg) do
    {_kty, map} = JOSE.JWK.to_public_map(jwk)
    %{"keys" => [Map.merge(map, %{"kid" => JOSE.JWK.thumbprint(jwk), "alg" => alg})]}
  end

  defp header(jwt), do: jwt |> JOSE.JWS.peek_protected() |> JSON.decode!()
  defp claims(jwt), do: jwt |> JOSE.JWS.peek_payload() |> JSON.decode!()

  defp base_opts(extra \\ []) do
    Keyword.merge(
      [
        issuer: @issuer,
        audience: @audience,
        client_id: @client_id,
        subject: @subject,
        now: @now,
        jti: "jti-123",
        kid: nil
      ],
      extra
    )
    |> Keyword.reject(fn {_key, value} -> is_nil(value) end)
  end

  describe "build/2" do
    test "builds the ID-JAG registered claims and typ header" do
      key = rsa_key()

      assert {:ok, jwt} =
               IdentityAssertion.build(
                 key,
                 base_opts(kid: JOSE.JWK.thumbprint(key), alg: "RS256")
               )

      assert header(jwt)["typ"] == "oauth-id-jag+jwt"
      assert header(jwt)["alg"] == "RS256"
      assert header(jwt)["kid"] == JOSE.JWK.thumbprint(key)

      c = claims(jwt)
      assert c["iss"] == @issuer
      assert c["sub"] == @subject
      assert c["aud"] == @audience
      assert c["client_id"] == @client_id
      assert c["jti"] == "jti-123"
      assert c["iat"] == @now
      assert c["exp"] == @now + 300
    end

    test "carries optional string-keyed claims and nbf" do
      key = ec_key()

      assert {:ok, jwt} =
               IdentityAssertion.build(
                 key,
                 base_opts(
                   claims: %{"scope" => "mcp:read", "email" => "user@example.com"},
                   nbf: @now,
                   alg: "ES256"
                 )
               )

      c = claims(jwt)
      assert c["scope"] == "mcp:read"
      assert c["email"] == "user@example.com"
      assert c["nbf"] == @now
    end
  end

  describe "interop" do
    test "attesto's server-side verifier accepts an RS256 assertion" do
      key = rsa_key()

      assert {:ok, jwt} =
               IdentityAssertion.build(
                 key,
                 base_opts(kid: JOSE.JWK.thumbprint(key), alg: "RS256")
               )

      assert {:ok, verified} =
               Attesto.IdentityAssertion.verify(
                 jwt,
                 public_jwks(key, "RS256"),
                 issuer: @issuer,
                 audience: @audience,
                 client_id: @client_id,
                 now: @now
               )

      assert verified["sub"] == @subject
    end

    test "attesto's server-side verifier accepts an ES256 assertion" do
      key = ec_key()

      assert {:ok, jwt} =
               IdentityAssertion.build(
                 key,
                 base_opts(kid: JOSE.JWK.thumbprint(key), alg: "ES256")
               )

      assert {:ok, _verified} =
               Attesto.IdentityAssertion.verify(
                 jwt,
                 public_jwks(key, "ES256"),
                 issuer: @issuer,
                 audience: @audience,
                 client_id: @client_id,
                 now: @now
               )
    end
  end

  describe "build/2 rejects invalid input" do
    test "required strings, claims, lifetime, nbf, and algorithms" do
      key = rsa_key()

      assert {:error, :invalid_issuer} = IdentityAssertion.build(key, base_opts(issuer: ""))
      assert {:error, :invalid_audience} = IdentityAssertion.build(key, base_opts(audience: ""))
      assert {:error, :invalid_client_id} = IdentityAssertion.build(key, base_opts(client_id: ""))
      assert {:error, :invalid_subject} = IdentityAssertion.build(key, base_opts(subject: ""))

      assert {:error, :invalid_claims} =
               IdentityAssertion.build(key, base_opts(claims: %{scope: "read"}))

      assert {:error, :reserved_claim_conflict} =
               IdentityAssertion.build(key, base_opts(claims: %{"iss" => "shadow"}))

      assert {:error, :invalid_lifetime} = IdentityAssertion.build(key, base_opts(lifetime: 0))
      assert {:error, :invalid_time} = IdentityAssertion.build(key, base_opts(now: -1))
      assert {:error, :invalid_time} = IdentityAssertion.build(key, base_opts(nbf: -1))
      assert {:error, :invalid_jti} = IdentityAssertion.build(key, base_opts(jti: ""))
      assert {:error, :unsupported_alg} = IdentityAssertion.build(key, base_opts(alg: "none"))

      assert {:error, :unsupported_key} =
               IdentityAssertion.build(JOSE.JWK.generate_key({:oct, 32}), base_opts())
    end
  end
end
