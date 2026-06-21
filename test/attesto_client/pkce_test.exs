defmodule AttestoClient.PKCETest do
  use ExUnit.Case, async: true

  alias AttestoClient.PKCE

  @rfc_verifier "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  @rfc_challenge "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

  describe "code_verifier/0" do
    test "generates a valid verifier with fresh entropy" do
      verifier1 = PKCE.code_verifier()
      verifier2 = PKCE.code_verifier()

      assert verifier1 != verifier2
      assert byte_size(verifier1) == 43
      assert Attesto.PKCE.valid_verifier?(verifier1)
      assert Attesto.PKCE.valid_verifier?(verifier2)
    end
  end

  describe "code_challenge/1" do
    test "matches the RFC 7636 S256 vector" do
      assert {:ok, @rfc_challenge} = PKCE.code_challenge(@rfc_verifier)
    end

    test "round-trips through attesto's server-side verifier" do
      verifier = PKCE.code_verifier()

      assert {:ok, challenge} = PKCE.code_challenge(verifier)
      assert :ok = Attesto.PKCE.verify(challenge, verifier)
    end

    test "rejects malformed verifiers" do
      assert {:error, :invalid_verifier} = PKCE.code_challenge("too-short")
    end
  end
end
