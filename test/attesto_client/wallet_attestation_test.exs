defmodule AttestoClient.WalletAttestationTest do
  use ExUnit.Case, async: true

  alias AttestoClient.WalletAttestation

  @client_id "wallet-instance-1"
  @audience "https://as.example.com"

  defp es256_key, do: JOSE.JWK.generate_key({:ec, "P-256"})
  defp public_map(key), do: key |> JOSE.JWK.to_public_map() |> elem(1)

  defp claims(jwt), do: jwt |> JOSE.JWS.peek_payload() |> JSON.decode!()
  defp header(jwt), do: jwt |> JOSE.JWS.peek_protected() |> JSON.decode!()

  describe "attestation/2" do
    test "binds the instance key into cnf and names the client_id in sub" do
      provider = es256_key()
      instance = es256_key()
      now = 1_700_000_000

      assert {:ok, jwt} =
               WalletAttestation.attestation(provider,
                 client_id: @client_id,
                 instance_key: instance,
                 now: now,
                 lifetime: 3600
               )

      assert header(jwt)["typ"] == "oauth-client-attestation+jwt"
      assert header(jwt)["alg"] == "ES256"

      c = claims(jwt)
      assert c["sub"] == @client_id
      assert c["iat"] == now
      assert c["exp"] == now + 3600
      assert c["cnf"]["jwk"] == public_map(instance)
      refute Map.has_key?(c["cnf"]["jwk"], "d")
    end

    test "embeds an x5c header when supplied" do
      assert {:ok, jwt} =
               WalletAttestation.attestation(es256_key(),
                 client_id: @client_id,
                 instance_key: es256_key(),
                 x5c: ["MIIBcert"]
               )

      assert header(jwt)["x5c"] == ["MIIBcert"]
    end

    test "fails fast on missing client_id or instance key" do
      assert {:error, :invalid_client_id} =
               WalletAttestation.attestation(es256_key(), instance_key: es256_key())

      assert {:error, :invalid_instance_key} =
               WalletAttestation.attestation(es256_key(), client_id: @client_id)

      assert {:error, :invalid_instance_key} =
               WalletAttestation.attestation(es256_key(),
                 client_id: @client_id,
                 instance_key: %{"kty" => "bogus"}
               )
    end
  end

  describe "pop/2" do
    test "targets one audience, carries iss/jti/iat/exp and an optional challenge" do
      instance = es256_key()
      now = 1_700_000_000

      assert {:ok, jwt} =
               WalletAttestation.pop(instance,
                 client_id: @client_id,
                 audience: @audience,
                 challenge: "srv-challenge-1",
                 jti: "pop-1",
                 now: now,
                 lifetime: 120
               )

      assert header(jwt)["typ"] == "oauth-client-attestation-pop+jwt"

      c = claims(jwt)
      assert c["iss"] == @client_id
      assert c["aud"] == @audience
      assert c["jti"] == "pop-1"
      assert c["iat"] == now
      assert c["exp"] == now + 120
      assert c["challenge"] == "srv-challenge-1"
    end

    test "fails fast on missing client_id or audience" do
      instance = es256_key()
      assert {:error, :invalid_client_id} = WalletAttestation.pop(instance, audience: @audience)
      assert {:error, :invalid_audience} = WalletAttestation.pop(instance, client_id: @client_id)
    end
  end

  describe "interop with Attesto.WalletAttestation.verify/3" do
    test "a built attestation + PoP pair verifies and yields the instance key" do
      provider = es256_key()
      instance = es256_key()
      now = 1_700_000_000

      assert {:ok, attestation} =
               WalletAttestation.attestation(provider,
                 client_id: @client_id,
                 instance_key: instance,
                 now: now
               )

      assert {:ok, pop} =
               WalletAttestation.pop(instance,
                 client_id: @client_id,
                 audience: @audience,
                 challenge: "srv-challenge-1",
                 now: now
               )

      assert {:ok, %{instance_key: %{jwk: jwk}, pop_claims: pop_claims}} =
               Attesto.WalletAttestation.verify(attestation, pop,
                 trusted_wallet_provider_jwks: public_map(provider),
                 audience: @audience,
                 client_id: @client_id,
                 expected_challenge: "srv-challenge-1",
                 now: now
               )

      assert jwk == public_map(instance)
      assert pop_claims["jti"]
    end

    test "verification fails when the PoP is signed by a non-cnf key" do
      provider = es256_key()
      instance = es256_key()
      wrong = es256_key()
      now = 1_700_000_000

      assert {:ok, attestation} =
               WalletAttestation.attestation(provider,
                 client_id: @client_id,
                 instance_key: instance,
                 now: now
               )

      # PoP signed by a different key than the attestation's cnf.
      assert {:ok, pop} =
               WalletAttestation.pop(wrong, client_id: @client_id, audience: @audience, now: now)

      assert {:error, :invalid_pop_signature} =
               Attesto.WalletAttestation.verify(attestation, pop,
                 trusted_wallet_provider_jwks: public_map(provider),
                 audience: @audience,
                 now: now
               )
    end

    test "verification fails against an untrusted wallet provider" do
      provider = es256_key()
      instance = es256_key()
      now = 1_700_000_000

      assert {:ok, attestation} =
               WalletAttestation.attestation(provider,
                 client_id: @client_id,
                 instance_key: instance,
                 now: now
               )

      assert {:ok, pop} =
               WalletAttestation.pop(instance,
                 client_id: @client_id,
                 audience: @audience,
                 now: now
               )

      assert {:error, _} =
               Attesto.WalletAttestation.verify(attestation, pop,
                 trusted_wallet_provider_jwks: public_map(es256_key()),
                 audience: @audience,
                 now: now
               )
    end
  end
end
