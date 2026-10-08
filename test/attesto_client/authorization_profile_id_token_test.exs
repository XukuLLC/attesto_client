defmodule AttestoClient.AuthorizationProfileIDTokenTest do
  use ExUnit.Case, async: false

  setup_all do
    previous = JOSE.crypto_fallback()
    JOSE.crypto_fallback(true)
    on_exit(fn -> JOSE.crypto_fallback(previous) end)
    :ok
  end

  test "FAPI ID Token policy reaches verified-key curve checks" do
    key = JOSE.JWK.generate_key({:okp, :Ed448})
    {_, public} = JOSE.JWK.to_public_map(key)
    now = System.system_time(:second)

    {:ok, jwt} =
      AttestoClient.Builder.sign(key, %{"alg" => "EdDSA", "typ" => "JWT"}, %{
        "iss" => "https://issuer.example",
        "sub" => "subject",
        "aud" => "client",
        "iat" => now,
        "exp" => now + 60
      })

    opts = [
      issuer: "https://issuer.example",
      client_id: "client",
      jwks: %{"keys" => [public]},
      accepted_algs: ["EdDSA"]
    ]

    assert {:ok, _claims} = AttestoClient.IDToken.verify(jwt, opts)

    assert {:error, :invalid_signature} =
             AttestoClient.IDToken.verify(
               jwt,
               Keyword.put(opts, :enforce_fapi_alg_policy, true)
             )
  end
end
