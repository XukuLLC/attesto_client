defmodule AttestoClient.CryptoJWECompatibilityTest do
  use ExUnit.Case, async: true

  alias AttestoClient.CryptoJWE

  test "the deprecated wrapper delegates encryption and decryption to core" do
    key = JOSE.JWK.generate_key({:ec, "P-256"})
    {_type, public} = JOSE.JWK.to_public_map(key)
    header = %{"alg" => "ECDH-ES", "enc" => "A128GCM"}
    encrypt = Function.capture(CryptoJWE, :encrypt, 3)
    decrypt = Function.capture(CryptoJWE, :decrypt, 2)

    assert {:ok, compact} = encrypt.(public, "credential", header)
    assert {:ok, "credential", _header} = decrypt.(key, compact)
  end
end
