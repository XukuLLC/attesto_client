defmodule AttestoClient.KeyAttestationTest do
  use ExUnit.Case, async: true

  alias AttestoClient.KeyAttestation
  alias AttestoClient.Wallet.Proof

  @credential_issuer "https://issuer.example.com"
  @client_id "wallet-client"

  defp es256_key, do: JOSE.JWK.generate_key({:ec, "P-256"})
  defp public_map(key), do: key |> JOSE.JWK.to_public_map() |> elem(1)

  defp claims(jwt), do: jwt |> JOSE.JWS.peek_payload() |> JSON.decode!()
  defp header(jwt), do: jwt |> JOSE.JWS.peek_protected() |> JSON.decode!()

  describe "build/2" do
    test "vouches for the attested keys with assurance claims and iat/exp" do
      provider = es256_key()
      holder = es256_key()
      now = 1_700_000_000

      assert {:ok, jwt} =
               KeyAttestation.build(provider,
                 attested_keys: [holder],
                 key_storage: ["iso_18045_high"],
                 user_authentication: ["iso_18045_moderate"],
                 certification: "https://certs.example/wallet",
                 now: now,
                 lifetime: 300
               )

      assert header(jwt)["typ"] == "key-attestation+jwt"

      c = claims(jwt)
      assert c["iat"] == now
      assert c["exp"] == now + 300
      assert c["attested_keys"] == [public_map(holder)]
      assert c["key_storage"] == ["iso_18045_high"]
      assert c["user_authentication"] == ["iso_18045_moderate"]
      assert c["certification"] == "https://certs.example/wallet"
      refute Enum.any?(c["attested_keys"], &Map.has_key?(&1, "d"))
    end

    test "fails fast on missing or invalid attested keys" do
      assert {:error, :invalid_attested_keys} = KeyAttestation.build(es256_key(), [])

      assert {:error, :invalid_attested_keys} =
               KeyAttestation.build(es256_key(), attested_keys: [])

      assert {:error, :invalid_attested_keys} =
               KeyAttestation.build(es256_key(), attested_keys: [%{"kty" => "bogus"}])

      assert {:error, :invalid_attested_keys} =
               KeyAttestation.build(es256_key(),
                 attested_keys: [JOSE.JWK.generate_key({:oct, 32})]
               )
    end

    test "rejects malformed optional claims and protected-header values" do
      provider = es256_key()
      base = [attested_keys: [es256_key()]]

      for value <- [[], [""], [42], "secure"] do
        assert {:error, :invalid_key_storage} =
                 KeyAttestation.build(provider, base ++ [key_storage: value])

        assert {:error, :invalid_user_authentication} =
                 KeyAttestation.build(provider, base ++ [user_authentication: value])
      end

      for value <- [
            "",
            "relative",
            "https:///certificate",
            "https://user@certs.example/wallet",
            "https://certs.example/wallet#fragment",
            "https://certs.example/%ZZ",
            42
          ] do
        assert {:error, :invalid_certification} =
                 KeyAttestation.build(provider, base ++ [certification: value])
      end

      for value <- ["", 42, []] do
        assert {:error, :invalid_nonce} =
                 KeyAttestation.build(provider, base ++ [nonce: value])
      end

      for value <- [[], [""], [42], "certificate"] do
        assert {:error, :invalid_x5c} = KeyAttestation.build(provider, base ++ [x5c: value])
      end

      for value <- ["", 42, []] do
        assert {:error, :invalid_kid} = KeyAttestation.build(provider, base ++ [kid: value])
      end
    end

    test "accepts only HTTP(S) certification URLs" do
      provider = es256_key()
      base = [attested_keys: [es256_key()]]

      for certification <- ["http://certs.example/wallet", "https://certs.example/wallet"] do
        assert {:ok, jwt} =
                 KeyAttestation.build(provider, base ++ [certification: certification])

        assert claims(jwt)["certification"] == certification
      end

      for certification <- [
            "ftp://certs.example/wallet",
            "urn:example:certification",
            "mailto:certs@example.com"
          ] do
        assert {:error, :invalid_certification} =
                 KeyAttestation.build(provider, base ++ [certification: certification])
      end
    end
  end

  describe "interop with Attesto.KeyAttestation.verify/2" do
    test "a built attestation verifies and returns its attested keys" do
      provider = es256_key()
      holder = es256_key()
      now = 1_700_000_000

      assert {:ok, jwt} =
               KeyAttestation.build(provider,
                 attested_keys: [holder],
                 nonce: "c-nonce-1",
                 now: now
               )

      assert {:ok, %{attested_keys: attested_keys, key_storage: nil}} =
               Attesto.KeyAttestation.verify(jwt,
                 trusted_jwks: public_map(provider),
                 nonce: "c-nonce-1",
                 now: now
               )

      assert attested_keys == [public_map(holder)]
    end
  end

  describe "carried in a credential proof header" do
    test "CredentialProof.verify_jwt accepts a proof whose key the attestation vouches for" do
      provider = es256_key()
      holder = es256_key()
      now = 1_700_000_000

      assert {:ok, attestation} =
               KeyAttestation.build(provider,
                 attested_keys: [holder],
                 nonce: "c-nonce-1",
                 now: now
               )

      assert {:ok, proof} =
               Proof.build(holder,
                 credential_issuer: @credential_issuer,
                 nonce: "c-nonce-1",
                 client_id: @client_id,
                 key_attestation: attestation,
                 now: now
               )

      assert header(proof)["key_attestation"] == attestation

      assert {:ok, %{jwk: jwk, key_attestation: %{attested_keys: attested_keys}}} =
               Attesto.CredentialProof.verify_jwt(proof,
                 issuer: @credential_issuer,
                 nonce: "c-nonce-1",
                 client_id: @client_id,
                 key_attestation_trusted_jwks: public_map(provider),
                 require_key_attestation: true,
                 now: now
               )

      assert jwk == public_map(holder)
      assert attested_keys == [public_map(holder)]
    end

    test "verify rejects a proof whose key is not among the attested keys" do
      provider = es256_key()
      holder = es256_key()
      other = es256_key()
      now = 1_700_000_000

      # Attestation vouches for `other`, but the proof is signed by `holder`.
      assert {:ok, attestation} =
               KeyAttestation.build(provider,
                 attested_keys: [other],
                 nonce: "c-nonce-1",
                 now: now
               )

      assert {:ok, proof} =
               Proof.build(holder,
                 credential_issuer: @credential_issuer,
                 nonce: "c-nonce-1",
                 client_id: @client_id,
                 key_attestation: attestation,
                 now: now
               )

      assert {:error, _} =
               Attesto.CredentialProof.verify_jwt(proof,
                 issuer: @credential_issuer,
                 nonce: "c-nonce-1",
                 client_id: @client_id,
                 key_attestation_trusted_jwks: public_map(provider),
                 require_key_attestation: true,
                 now: now
               )
    end
  end
end
