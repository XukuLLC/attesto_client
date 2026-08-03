defmodule AttestoClient.DPoPTest do
  use ExUnit.Case, async: true

  alias AttestoClient.DPoP

  @htu "https://issuer.example.com/credential"

  defp es256_key, do: JOSE.JWK.generate_key({:ec, "P-256"})

  defp claims(jwt), do: jwt |> JOSE.JWS.peek_payload() |> JSON.decode!()
  defp header(jwt), do: jwt |> JOSE.JWS.peek_protected() |> JSON.decode!()

  describe "proof/4" do
    test "produces a typed dpop proof carrying the public jwk, htm/htu/iat/jti" do
      key = es256_key()
      now = 1_700_000_000

      assert {:ok, jwt} = DPoP.proof(key, "post", @htu, now: now)

      h = header(jwt)
      assert h["typ"] == "dpop+jwt"
      assert h["alg"] == "ES256"
      assert is_map(h["jwk"])
      refute Map.has_key?(h["jwk"], "d")

      {_type, expected_public} = JOSE.JWK.to_public_map(key)
      assert h["jwk"] == expected_public

      c = claims(jwt)
      assert c["htm"] == "POST"
      assert c["htu"] == @htu
      assert c["iat"] == now
      assert is_binary(c["jti"]) and c["jti"] != ""
      refute Map.has_key?(c, "ath")
      refute Map.has_key?(c, "nonce")
    end

    test "strips query and fragment from htu (RFC 9449 §4.2)" do
      assert {:ok, jwt} = DPoP.proof(es256_key(), "GET", @htu <> "?cb=1#frag")
      assert claims(jwt)["htu"] == @htu
    end

    test "binds ath to the access token and echoes a server nonce when supplied" do
      access_token = "the-access-token"

      assert {:ok, jwt} =
               DPoP.proof(es256_key(), "POST", @htu,
                 access_token: access_token,
                 nonce: "server-nonce-1"
               )

      c = claims(jwt)
      assert c["ath"] == Attesto.DPoP.compute_ath(access_token)
      assert c["nonce"] == "server-nonce-1"
    end

    test "an explicit jti and kid override the defaults" do
      assert {:ok, jwt} = DPoP.proof(es256_key(), "POST", @htu, jti: "dpop-1", kid: "key-9")
      assert claims(jwt)["jti"] == "dpop-1"
      assert header(jwt)["kid"] == "key-9"
    end
  end

  describe "proof/4 rejects invalid input (fail fast)" do
    test "bad htm, htu, time, alg, jti, and key" do
      key = es256_key()

      assert {:error, :invalid_htm} = DPoP.proof(key, "  ", @htu)
      assert {:error, :invalid_htu} = DPoP.proof(key, "POST", "not-a-url")
      assert {:error, :invalid_htu} = DPoP.proof(key, "POST", "/relative/only")
      assert {:error, :invalid_time} = DPoP.proof(key, "POST", @htu, now: -1)
      assert {:error, :unsupported_alg} = DPoP.proof(key, "POST", @htu, alg: "none")
      assert {:error, :invalid_jti} = DPoP.proof(key, "POST", @htu, jti: "")

      assert {:error, :unsupported_key} =
               DPoP.proof(JOSE.JWK.generate_key({:oct, 32}), "POST", @htu)

      assert {:error, :invalid_key} = DPoP.proof(%{"kty" => "bogus"}, "POST", @htu)
    end
  end

  describe "interop with Attesto.DPoP.verify_proof/2" do
    test "a built proof verifies, binding to the token's ath and the key's jkt" do
      key = es256_key()
      access_token = "resource-access-token"
      now = 1_700_000_000

      assert {:ok, jwt} =
               DPoP.proof(key, "POST", @htu, access_token: access_token, now: now)

      assert {:ok, %{jkt: jkt, ath: ath, htm: "POST", htu: @htu}} =
               Attesto.DPoP.verify_proof(jwt,
                 http_method: "POST",
                 http_uri: @htu,
                 access_token: access_token,
                 now: now
               )

      assert jkt == Attesto.DPoP.compute_jkt(key)
      assert ath == Attesto.DPoP.compute_ath(access_token)
    end

    test "verification fails on a mismatched method, uri, or access token" do
      key = es256_key()
      now = 1_700_000_000
      assert {:ok, jwt} = DPoP.proof(key, "POST", @htu, access_token: "tok", now: now)

      assert {:error, _} =
               Attesto.DPoP.verify_proof(jwt, http_method: "GET", http_uri: @htu, now: now)

      assert {:error, _} =
               Attesto.DPoP.verify_proof(jwt,
                 http_method: "POST",
                 http_uri: "https://issuer.example.com/other",
                 now: now
               )

      assert {:error, _} =
               Attesto.DPoP.verify_proof(jwt,
                 http_method: "POST",
                 http_uri: @htu,
                 access_token: "wrong",
                 now: now
               )
    end
  end
end
