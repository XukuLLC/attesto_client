defmodule AttestoClient.Wallet.ProofTest do
  use ExUnit.Case, async: true

  alias AttestoClient.Wallet.Proof

  @credential_issuer "https://issuer.example.com"
  @client_id "wallet-client"

  defp es256_key, do: JOSE.JWK.generate_key({:ec, "P-256"})

  defp claims(jwt), do: jwt |> JOSE.JWS.peek_payload() |> JSON.decode!()
  defp header(jwt), do: jwt |> JOSE.JWS.peek_protected() |> JSON.decode!()

  describe "build/2" do
    test "produces a typed proof carrying the holder's public jwk and aud/iat" do
      key = es256_key()
      now = 1_700_000_000

      assert {:ok, jwt} = Proof.build(key, credential_issuer: @credential_issuer, now: now)

      h = header(jwt)
      assert h["typ"] == "openid4vci-proof+jwt"
      assert h["alg"] == "ES256"
      assert is_map(h["jwk"])
      refute Map.has_key?(h["jwk"], "d")

      {_type, expected_public} = JOSE.JWK.to_public_map(key)
      assert h["jwk"] == expected_public

      c = claims(jwt)
      assert c["aud"] == @credential_issuer
      assert c["iat"] == now
      refute Map.has_key?(c, "nonce")
      refute Map.has_key?(c, "iss")
    end

    test "carries the c_nonce and client_id (authorization_code flow) when supplied" do
      key = es256_key()

      assert {:ok, jwt} =
               Proof.build(key,
                 credential_issuer: @credential_issuer,
                 nonce: "server-nonce-1",
                 client_id: @client_id
               )

      c = claims(jwt)
      assert c["nonce"] == "server-nonce-1"
      assert c["iss"] == @client_id
    end
  end

  describe "build/2 rejects invalid input (fail fast)" do
    test "bad credential_issuer, time, alg, and key type" do
      key = es256_key()

      assert {:error, :invalid_credential_issuer} = Proof.build(key, credential_issuer: "")

      assert {:error, :invalid_time} =
               Proof.build(key, credential_issuer: @credential_issuer, now: -1)

      assert {:error, :unsupported_alg} =
               Proof.build(key, credential_issuer: @credential_issuer, alg: "none")

      assert {:error, :unsupported_key} =
               Proof.build(JOSE.JWK.generate_key({:oct, 32}),
                 credential_issuer: @credential_issuer
               )

      assert {:error, :invalid_key} =
               Proof.build(%{"kty" => "bogus"}, credential_issuer: @credential_issuer)
    end
  end

  describe "interop with Attesto.CredentialProof.verify_jwt/2" do
    test "a built proof verifies and yields the holder's jwk and thumbprint" do
      key = es256_key()

      assert {:ok, jwt} =
               Proof.build(key,
                 credential_issuer: @credential_issuer,
                 nonce: "server-nonce-1",
                 client_id: @client_id
               )

      assert {:ok, %{jwk: jwk, jkt: jkt, key_attestation: nil}} =
               Attesto.CredentialProof.verify_jwt(jwt,
                 issuer: @credential_issuer,
                 nonce: "server-nonce-1",
                 client_id: @client_id
               )

      {_type, expected_public} = JOSE.JWK.to_public_map(key)
      assert jwk == expected_public
      assert is_binary(jkt) and jkt != ""
    end

    test "verification fails on a wrong audience, nonce, or client_id" do
      key = es256_key()

      assert {:ok, jwt} =
               Proof.build(key, credential_issuer: @credential_issuer, nonce: "server-nonce-1")

      assert {:error, :invalid_audience} =
               Attesto.CredentialProof.verify_jwt(jwt,
                 issuer: "https://other.example.com",
                 nonce: "server-nonce-1"
               )

      assert {:error, :invalid_nonce} =
               Attesto.CredentialProof.verify_jwt(jwt,
                 issuer: @credential_issuer,
                 nonce: "wrong-nonce"
               )
    end
  end
end
