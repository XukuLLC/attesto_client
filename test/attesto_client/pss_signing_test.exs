defmodule AttestoClient.PSSSigningTest do
  use ExUnit.Case, async: true

  alias AttestoClient.{Builder, ClientAssertion, DPoP, RequestObject}

  @algorithms [{"PS256", :sha256, 32}, {"PS384", :sha384, 48}, {"PS512", :sha512, 64}]

  setup_all do
    %{key: JOSE.JWK.generate_key({:rsa, 2048})}
  end

  test "PS256 client assertions pin exact PSS parameters while preserving omitted typ", %{
    key: key
  } do
    for typ <- [nil, "JWT", "client-authentication+jwt"] do
      assert {:ok, jwt} =
               ClientAssertion.build(key,
                 alg: "PS256",
                 typ: typ,
                 client_id: "synthetic-client",
                 audience: "https://issuer.example"
               )

      assert {:ok, header} = Attesto.JWS.peek_json(jwt, :protected)
      assert header["typ"] == typ
      if is_nil(typ), do: refute(Map.has_key?(header, "typ"))
      assert_exact_pss(jwt, key, :sha256, 32)
    end
  end

  test "PS256 DPoP proofs pin exact PSS parameters", %{key: key} do
    assert {:ok, jwt} =
             DPoP.proof(key, "POST", "https://issuer.example/token", alg: "PS256")

    assert {:ok, %{"typ" => "dpop+jwt", "alg" => "PS256"}} =
             Attesto.JWS.peek_json(jwt, :protected)

    assert_exact_pss(jwt, key, :sha256, 32)
  end

  test "PS256 JAR request objects pin exact PSS parameters", %{key: key} do
    assert {:ok, jwt} =
             RequestObject.build(key,
               alg: "PS256",
               client_id: "synthetic-client",
               audience: "https://issuer.example"
             )

    assert {:ok, %{"typ" => "oauth-authz-req+jwt", "alg" => "PS256"}} =
             Attesto.JWS.peek_json(jwt, :protected)

    assert_exact_pss(jwt, key, :sha256, 32)
  end

  test "shared signer pins every PSS size without widening public algorithm policy", %{key: key} do
    for {algorithm, hash, salt_bytes} <- @algorithms do
      assert {:ok, jwt} = Builder.sign(key, %{"alg" => algorithm}, %{"sub" => "synthetic"})

      assert {:ok, %{"typ" => "JWT", "alg" => ^algorithm}} =
               Attesto.JWS.peek_json(jwt, :protected)

      assert_exact_pss(jwt, key, hash, salt_bytes)
    end

    {_jws, original} =
      key |> JOSE.JWT.sign(%{"alg" => "PS256"}, %{"sub" => "synthetic"}) |> JOSE.JWS.compact()

    assert {:ok, %{"typ" => "JWT"}} = Attesto.JWS.peek_json(original, :protected)

    for algorithm <- ["PS384", "PS512"] do
      assert {:error, :unsupported_alg} =
               ClientAssertion.build(key,
                 alg: algorithm,
                 client_id: "synthetic-client",
                 audience: "https://issuer.example"
               )
    end
  end

  defp assert_exact_pss(jwt, key, hash, salt_bytes) do
    [header, payload, encoded_signature] = String.split(jwt, ".")
    {:ok, signature} = Base.url_decode64(encoded_signature, padding: false)
    {_type, public_key} = key |> JOSE.JWK.to_public() |> JOSE.JWK.to_key()
    data = header <> "." <> payload

    assert :public_key.verify(data, hash, signature, public_key,
             rsa_padding: :rsa_pkcs1_pss_padding,
             rsa_pss_saltlen: salt_bytes,
             rsa_mgf1_md: hash
           )

    refute :public_key.verify(data, hash, signature, public_key,
             rsa_padding: :rsa_pkcs1_pss_padding,
             rsa_pss_saltlen: salt_bytes + 1,
             rsa_mgf1_md: hash
           )
  end
end
