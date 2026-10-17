defmodule AttestoClient.CryptoJWECompatibilityTest do
  use ExUnit.Case, async: true

  alias AttestoClient.CryptoJWE

  test "a missing core capability returns a controlled error before encryption" do
    key = JOSE.JWK.generate_key({:ec, "P-256"})
    {_type, public} = JOSE.JWK.to_public_map(key)
    header = %{"alg" => "ECDH-ES", "enc" => "A128GCM"}
    encrypt = Function.capture(CryptoJWE, :encrypt, 3)
    decrypt = Function.capture(CryptoJWE, :decrypt, 2)

    if Code.ensure_loaded?(Attesto.JWE) do
      assert {:ok, compact} = encrypt.(public, "credential", header)
      assert {:ok, "credential", _header} = decrypt.(key, compact)
    else
      assert {:error, :unsupported_core_version} = encrypt.(public, "credential", header)

      assert {:error, :unsupported_core_version} = decrypt.(key, "invalid")
    end
  end
end
