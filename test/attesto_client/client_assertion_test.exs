defmodule AttestoClient.ClientAssertionTest do
  use ExUnit.Case, async: true

  alias AttestoClient.ClientAssertion
  alias AttestoClient.Test.Python

  @client_id "attesto-fapi-dpop-client"
  @audience "https://op.example.com"

  defp es256_key, do: JOSE.JWK.generate_key({:ec, "P-256"})

  defp es256_map, do: es256_key() |> JOSE.JWK.to_map() |> elem(1)

  defp public_jwk(jose_jwk, overrides) do
    {_, public} = JOSE.JWK.to_public_map(jose_jwk)
    Map.merge(public, overrides)
  end

  defp claims(assertion) do
    assertion |> JOSE.JWS.peek_payload() |> JSON.decode!()
  end

  describe "build/2" do
    test "permits a legacy type or omission and rejects an invalid type" do
      key = es256_key()
      base = [client_id: @client_id, audience: @audience]

      for typ <- [nil, "JWT"] do
        assert {:ok, assertion} = ClientAssertion.build(key, Keyword.put(base, :typ, typ))
        header = JSON.decode!(JOSE.JWS.peek_protected(assertion))
        assert Map.get(header, "typ") == typ
        if is_nil(typ), do: refute(Map.has_key?(header, "typ"))
      end

      for invalid <- ["", false, 42, []] do
        assert {:error, :invalid_typ} =
                 ClientAssertion.build(key, Keyword.put(base, :typ, invalid))
      end
    end

    test "produces an RFC 7523 assertion with iss=sub=client_id and the given aud" do
      now = 1_700_000_000

      {:ok, assertion} =
        ClientAssertion.build(es256_key(),
          client_id: @client_id,
          audience: @audience,
          now: now,
          lifetime: 60
        )

      assert %{"typ" => "client-authentication+jwt"} =
               assertion |> JOSE.JWS.peek_protected() |> JSON.decode!()

      c = claims(assertion)
      assert c["iss"] == @client_id
      assert c["sub"] == @client_id
      assert c["aud"] == @audience
      assert c["iat"] == now
      assert c["exp"] == now + 60
      assert is_binary(c["jti"]) and c["jti"] != ""
    end

    test "defaults the lifetime to 60 seconds and generates a fresh jti each call" do
      key = es256_key()
      now = 1_700_000_000
      opts = [client_id: @client_id, audience: @audience, now: now]

      {:ok, a1} = ClientAssertion.build(key, opts)
      {:ok, a2} = ClientAssertion.build(key, opts)

      assert claims(a1)["exp"] == now + 60
      assert claims(a1)["jti"] != claims(a2)["jti"]
    end

    test "infers ES256 for an EC P-256 key and honours an explicit kid" do
      {:ok, assertion} =
        ClientAssertion.build(public_or_private_with_kid(),
          client_id: @client_id,
          audience: @audience,
          kid: "key-1"
        )

      %{"alg" => alg, "kid" => kid} = assertion |> JOSE.JWS.peek_protected() |> JSON.decode!()
      assert alg == "ES256"
      assert kid == "key-1"
    end

    test "carries the kid embedded in a JOSE.JWK struct (no explicit :kid)" do
      # A caller naturally keeps the key as a %JOSE.JWK{}; an embedded kid must
      # still reach the header so the AS can select the verification key.
      struct_key = JOSE.JWK.from_map(Map.put(es256_map(), "kid", "struct-kid"))

      {:ok, assertion} =
        ClientAssertion.build(struct_key, client_id: @client_id, audience: @audience)

      %{"kid" => kid} = assertion |> JOSE.JWS.peek_protected() |> JSON.decode!()
      assert kid == "struct-kid"
    end

    test "RSA inference remains RS256 and FAPI callers can select PS256 explicitly" do
      key = JOSE.JWK.generate_key({:rsa, 2048})

      assert {:ok, inferred} =
               ClientAssertion.build(key, client_id: @client_id, audience: @audience)

      assert %{"alg" => "RS256"} = inferred |> JOSE.JWS.peek_protected() |> JSON.decode!()

      assert {:ok, fapi} =
               ClientAssertion.build(key,
                 client_id: @client_id,
                 audience: @audience,
                 alg: "PS256"
               )

      assert %{"alg" => "PS256"} = fapi |> JOSE.JWS.peek_protected() |> JSON.decode!()

      assert {:ok, _claims} =
               Attesto.ClientAssertion.verify(
                 fapi,
                 @client_id,
                 @audience,
                 %{"keys" => [public_jwk(key, %{"alg" => "PS256"})]}
               )
    end

    test "the assertion_type/0 is the RFC 7523 jwt-bearer value" do
      assert ClientAssertion.assertion_type() ==
               "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    end
  end

  describe "build/2 rejects invalid input (fail fast)" do
    test "empty or missing client_id / audience" do
      key = es256_key()

      assert {:error, :invalid_client_id} =
               ClientAssertion.build(key, client_id: "", audience: @audience)

      assert {:error, :invalid_client_id} = ClientAssertion.build(key, audience: @audience)

      assert {:error, :invalid_audience} =
               ClientAssertion.build(key, client_id: @client_id, audience: "")

      assert {:error, :invalid_audience} = ClientAssertion.build(key, client_id: @client_id)
    end

    test "a non-positive lifetime or empty jti" do
      key = es256_key()
      base = [client_id: @client_id, audience: @audience]

      assert {:error, :invalid_lifetime} = ClientAssertion.build(key, base ++ [lifetime: -5])
      assert {:error, :invalid_lifetime} = ClientAssertion.build(key, base ++ [lifetime: 0])
      assert {:error, :invalid_jti} = ClientAssertion.build(key, base ++ [jti: ""])
      assert {:error, :invalid_time} = ClientAssertion.build(key, base ++ [now: -1])
      assert {:error, :invalid_time} = ClientAssertion.build(key, base ++ [now: "now"])

      for kid <- ["", 42, []] do
        assert {:error, :invalid_kid} = ClientAssertion.build(key, base ++ [kid: kid])
      end
    end

    test "an unsupported algorithm, including none" do
      key = es256_key()
      base = [client_id: @client_id, audience: @audience]

      assert {:error, :unsupported_alg} = ClientAssertion.build(key, base ++ [alg: "none"])
      assert {:error, :unsupported_alg} = ClientAssertion.build(key, base ++ [alg: "bogus"])
    end

    test "a key/algorithm mismatch preserves the signing_failed error tuple" do
      key = es256_key()

      assert {:error, {:signing_failed, "signing operation failed"}} =
               ClientAssertion.build(key,
                 client_id: @client_id,
                 audience: @audience,
                 alg: "RS256"
               )
    end

    test "a signing backend failure does not expose private key material" do
      key = es256_key()
      {:jose_jwk_kty_ec, private_key} = key.kty
      private_sentinel = "private-signing-sentinel-that-must-not-escape"
      malformed_private_key = put_elem(private_key, 2, private_sentinel)
      malformed_key = %{key | kty: {:jose_jwk_kty_ec, malformed_private_key}}

      assert {:error, {:signing_failed, message}} =
               ClientAssertion.build(malformed_key,
                 client_id: @client_id,
                 audience: @audience,
                 alg: "ES256"
               )

      assert message == "signing operation failed"
      refute message =~ private_sentinel
    end

    test "an unsupported key type (symmetric oct) fails as unsupported_key, not a raise" do
      key = JOSE.JWK.generate_key({:oct, 32})

      assert {:error, :unsupported_key} =
               ClientAssertion.build(key, client_id: @client_id, audience: @audience)
    end

    test "a malformed JWK map fails as invalid_key, not a raise" do
      assert {:error, :invalid_key} =
               ClientAssertion.build(%{"kty" => "bogus"},
                 client_id: @client_id,
                 audience: @audience
               )

      assert {:error, :invalid_key} =
               ClientAssertion.build(%{}, client_id: @client_id, audience: @audience)
    end
  end

  describe "interop" do
    test "attesto's server-side verifier accepts the assertion (in-family interop)" do
      key = es256_key()

      {:ok, assertion} =
        ClientAssertion.build(key, client_id: @client_id, audience: @audience)

      jwks = %{"keys" => [public_jwk(key, %{"alg" => "ES256"})]}

      assert {:ok, verified} =
               Attesto.ClientAssertion.verify(assertion, @client_id, @audience, jwks)

      assert verified["iss"] == @client_id
    end

    test "an independent PyJWT verifier accepts the assertion (external parity, Leg A)" do
      case Python.available("verify_client_assertion.py") do
        {:ok, python} ->
          key = es256_key()

          {:ok, assertion} =
            ClientAssertion.build(key, client_id: @client_id, audience: @audience)

          result =
            Python.run(python, "verify_client_assertion.py", %{
              assertion: assertion,
              public_jwk: public_jwk(key, %{"alg" => "ES256"}),
              audience: @audience
            })

          assert {:ok, %{"claims" => c}} = result
          assert c["iss"] == @client_id
          assert c["sub"] == @client_id
          assert c["aud"] == @audience

        {:skip, reason} ->
          IO.puts("Skipping PyJWT client-assertion parity: #{reason}")
      end
    end
  end

  # ── helpers ──────────────────────────────────────────────────────────────

  defp public_or_private_with_kid do
    # A private JWK map carrying a `kid`, to exercise the kid default path.
    {_, map} = es256_key() |> JOSE.JWK.to_map()
    Map.put(map, "kid", "key-1")
  end
end
