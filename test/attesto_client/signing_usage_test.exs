defmodule AttestoClient.SigningUsageTest do
  use ExUnit.Case, async: true

  alias AttestoClient.Wallet.Proof

  @issuer "https://issuer.example"

  defp builders(key) do
    opts = [client_id: "client", audience: @issuer, issuer: @issuer, subject: "subject"]

    [
      dpop: fn -> AttestoClient.DPoP.proof(key, "POST", @issuer <> "/token") end,
      client_assertion: fn -> AttestoClient.ClientAssertion.build(key, opts) end,
      request_object: fn -> AttestoClient.RequestObject.build(key, opts) end,
      identity_assertion: fn -> AttestoClient.IdentityAssertion.build(key, opts) end,
      wallet_proof: fn -> Proof.build(key, credential_issuer: @issuer) end,
      wallet_attestation: fn ->
        AttestoClient.WalletAttestation.attestation(key, opts ++ [instance_key: key])
      end,
      wallet_pop: fn -> AttestoClient.WalletAttestation.pop(key, opts) end,
      key_attestation: fn -> AttestoClient.KeyAttestation.build(key, attested_keys: [key]) end
    ]
  end

  test "every artifact builder accepts signing operations and publishes a verifiable public half" do
    {_, fields} = JOSE.JWK.generate_key({:ec, "P-256"}) |> JOSE.JWK.to_map()
    key = Map.put(fields, "key_ops", ["sign"])
    public = Attesto.Key.public_map(key)
    assert {:ok, verification_key} = Attesto.Key.verification_jwk(public, alg: "ES256")

    for {name, build} <- builders(key) do
      assert {:ok, jwt} = build.(), "#{name} refused a signing key"
      assert {true, _, _} = JOSE.JWS.verify_strict(verification_key, ["ES256"], jwt)
      {:ok, header} = Attesto.JWS.peek_json(jwt, :protected)
      {:ok, claims} = Attesto.JWS.peek_json(jwt, :payload)

      embedded =
        List.wrap(header["jwk"]) ++
          List.wrap(get_in(claims, ["cnf", "jwk"])) ++ Map.get(claims, "attested_keys", [])

      for jwk <- embedded do
        refute Map.has_key?(jwk, "key_ops")
        assert {:ok, _} = Attesto.Key.verification_jwk(jwk, alg: "ES256")
      end
    end
  end

  test "every artifact builder refuses a private key restricted to verification" do
    {_, fields} = JOSE.JWK.generate_key({:ec, "P-256"}) |> JOSE.JWK.to_map()

    for {name, build} <- builders(Map.put(fields, "key_ops", ["verify"])) do
      assert {:error, _} = build.(), "#{name} signed despite verification-only operations"
    end
  end
end
