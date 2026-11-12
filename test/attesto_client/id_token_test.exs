defmodule AttestoClient.IDTokenTest do
  use ExUnit.Case, async: true

  alias AttestoClient.IDToken

  @issuer "https://op.example.com"
  @client_id "client-abc"
  @subject "usr_end_user_1"
  @now 1_700_000_000

  defmodule Keystore do
    @moduledoc false
    @behaviour Attesto.Keystore

    @pem JOSE.JWK.generate_key({:rsa, 2048}) |> JOSE.JWK.to_pem() |> elem(1)

    @impl true
    def signing_pem, do: @pem

    @impl true
    def verification_pems, do: [@pem]
  end

  defp config do
    Attesto.Config.new(
      issuer: @issuer,
      audience: @issuer,
      keystore: Keystore,
      principal_kinds: [Attesto.PrincipalKind.new("user", "usr_")]
    )
  end

  defp jwks, do: Attesto.JWKS.from_keystore(Keystore)

  defp public_jwk(pem, overrides \\ %{}) do
    {_, public_map} = pem |> Attesto.Key.jwk() |> JOSE.JWK.to_public_map()

    public_map
    |> Map.merge(%{"kid" => Attesto.Key.kid(pem), "use" => "sig"})
    |> Map.merge(overrides)
  end

  defp verify(jwt, opts \\ []) do
    IDToken.verify(
      jwt,
      Keyword.merge([issuer: @issuer, client_id: @client_id, jwks: jwks(), now: @now], opts)
    )
  end

  defp hash_claim(value, alg \\ "RS256") do
    {digest, half_bytes} =
      case alg do
        alg when alg in ~w(RS256 PS256 ES256) -> {:sha256, 16}
        "ES384" -> {:sha384, 24}
        alg when alg in ~w(ES512 EdDSA Ed25519) -> {:sha512, 32}
      end

    digest
    |> :crypto.hash(value)
    |> binary_part(0, half_bytes)
    |> Base.url_encode64(padding: false)
  end

  defp base_claims(overrides \\ %{}) do
    Map.merge(
      %{
        "iss" => @issuer,
        "sub" => @subject,
        "aud" => @client_id,
        "iat" => @now,
        "exp" => @now + 600
      },
      overrides
    )
  end

  defp sign(claims, header_overrides \\ %{}) do
    pem = Keystore.signing_pem()
    jwk = Attesto.Key.signing_jwk(pem)

    header =
      %{"alg" => "RS256", "kid" => Attesto.Key.kid(pem), "typ" => "JWT"}
      |> Map.merge(header_overrides)

    {_, jwt} = jwk |> JOSE.JWS.sign(JSON.encode!(claims), header) |> JOSE.JWS.compact()
    jwt
  end

  defp sign_raw_payload(payload) when is_binary(payload) do
    pem = Keystore.signing_pem()
    jwk = Attesto.Key.signing_jwk(pem)
    header = %{"alg" => "RS256", "kid" => Attesto.Key.kid(pem), "typ" => "JWT"}
    {_, jwt} = jwk |> JOSE.JWS.sign(payload, header) |> JOSE.JWS.compact()
    jwt
  end

  describe "verify/2 success" do
    test "verifies an ID token minted by attesto with nonce and hash claims" do
      access_token = "access-token-123"
      code = "code-123"

      {:ok, jwt} =
        Attesto.IDToken.mint(config(), @subject, @client_id,
          now: @now,
          nonce: "nonce-1",
          access_token: access_token,
          code: code,
          auth_time: @now - 5
        )

      assert {:ok, claims} =
               verify(jwt,
                 nonce: "nonce-1",
                 access_token: access_token,
                 code: code,
                 max_age: 60
               )

      assert claims["sub"] == @subject
      assert claims["at_hash"] == hash_claim(access_token)
      assert claims["c_hash"] == hash_claim(code)
    end

    test "checks s_hash when the state is supplied" do
      jwt = sign(base_claims(%{"s_hash" => hash_claim("state-123")}))

      assert {:ok, _claims} = verify(jwt, state: "state-123")
    end

    test "can fetch the JWKS through discovery metadata" do
      {:ok, jwt} = Attesto.IDToken.mint(config(), @subject, @client_id, now: @now)
      metadata = %{"issuer" => @issuer, "jwks_uri" => "#{@issuer}/jwks"}

      plug = fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(200, JSON.encode!(jwks()))
      end

      assert {:ok, claims} =
               IDToken.verify(jwt,
                 issuer: @issuer,
                 client_id: @client_id,
                 metadata: metadata,
                 req_options: [plug: plug],
                 now: @now
               )

      assert claims["sub"] == @subject
    end

    test "accepts an additional audience only when it is trusted and azp names this client" do
      jwt = sign(base_claims(%{"aud" => ["other", @client_id], "azp" => @client_id}))

      # OIDC Core §3.1.3.7 item 3: strict by default.
      assert {:error, :untrusted_audience} = verify(jwt)
      assert {:error, :untrusted_audience} = verify(jwt, trusted_audiences: [])
      assert {:error, :untrusted_audience} = verify(jwt, trusted_audiences: ["someone-else"])
      assert {:ok, _claims} = verify(jwt, trusted_audiences: ["other"])

      # Every additional audience must be trusted, not just one of them.
      three = sign(base_claims(%{"aud" => ["other", @client_id, "third"], "azp" => @client_id}))
      assert {:error, :untrusted_audience} = verify(three, trusted_audiences: ["other"])
      assert {:ok, _claims} = verify(three, trusted_audiences: ["third", "other"])

      # A single-element array naming only this client has no additional audience.
      assert {:ok, _claims} = verify(sign(base_claims(%{"aud" => [@client_id]})))
    end

    test "trusting an audience does not relax the azp rules or stand in for this client" do
      trusted = [trusted_audiences: ["other"]]

      assert {:error, :missing_azp} =
               verify(sign(base_claims(%{"aud" => ["other", @client_id]})), trusted)

      assert {:error, :invalid_azp} =
               verify(
                 sign(base_claims(%{"aud" => ["other", @client_id], "azp" => "other"})),
                 trusted
               )

      assert {:error, :invalid_audience} =
               verify(sign(base_claims(%{"aud" => ["other"]})), trusted)

      assert {:error, :invalid_audience} = verify(sign(base_claims(%{"aud" => "other"})), trusted)
    end

    test "rejects a malformed :trusted_audiences" do
      jwt = sign(base_claims())

      for invalid <- ["other", [:other], [""], %{}, :any] do
        assert {:error, :invalid_trusted_audiences} = verify(jwt, trusted_audiences: invalid)
      end
    end

    test "ignores unrelated malformed JWKS keys after kid filtering" do
      pem = Keystore.signing_pem()
      jwt = sign(base_claims())

      jwks = %{
        "keys" => [
          %{"kid" => "other", "kty" => "oct", "alg" => "HS256", "k" => "not-for-jws"},
          public_jwk(pem, %{"alg" => "RS256"})
        ]
      }

      assert {:ok, _claims} = verify(jwt, jwks: jwks)
    end

    test "selects exactly one key eligible for the protected-header algorithm" do
      pem = Keystore.signing_pem()
      {_, ec_map} = JOSE.JWK.generate_key({:ec, "P-256"}) |> JOSE.JWK.to_public_map()
      jwt = sign(base_claims())

      jwks = %{
        "keys" => [
          Map.merge(ec_map, %{"kid" => "signing", "alg" => "ES256", "use" => "sig"}),
          public_jwk(pem, %{"alg" => "RS256"})
        ]
      }

      assert {:ok, _claims} = verify(jwt, jwks: jwks)
    end

    test "accepts PS256 for a bare RSA JWKS key when policy allows it" do
      pem = Keystore.signing_pem()

      jwt =
        Attesto.JWS.sign_compact(
          pem,
          %{"alg" => "PS256", "kid" => Attesto.Key.kid(pem), "typ" => "JWT"},
          base_claims()
        )

      jwks = %{"keys" => [public_jwk(pem)]}

      assert {:ok, _claims} = verify(jwt, jwks: jwks, accepted_algs: ["PS256"])
    end

    test "retains nil-as-default accepted-alg compatibility" do
      {:ok, jwt} = Attesto.IDToken.mint(config(), @subject, @client_id, now: @now)
      assert {:ok, _claims} = verify(jwt, accepted_algs: nil)
    end
  end

  describe "verify/2 rejects" do
    test "wrong issuer, audience, and azp" do
      assert {:error, :invalid_issuer} =
               verify(sign(base_claims(%{"iss" => "https://evil.example"})))

      assert {:error, :invalid_audience} =
               verify(sign(base_claims(%{"aud" => "someone-else"})))

      assert {:error, :untrusted_audience} =
               verify(sign(base_claims(%{"aud" => ["other", @client_id]})))

      assert {:error, :missing_azp} =
               verify(sign(base_claims(%{"aud" => ["other", @client_id]})),
                 trusted_audiences: ["other"]
               )

      assert {:error, :invalid_azp} =
               verify(sign(base_claims(%{"aud" => ["other", @client_id], "azp" => "other"})),
                 trusted_audiences: ["other"]
               )
    end

    test "nonce and max_age failures" do
      assert {:error, :nonce_required} =
               verify(sign(base_claims()), nonce: "expected")

      assert {:error, :nonce_mismatch} =
               verify(sign(base_claims(%{"nonce" => "actual"})), nonce: "expected")

      assert {:error, :auth_time_required} =
               verify(sign(base_claims()), max_age: 60)

      assert {:error, :max_age_exceeded} =
               verify(sign(base_claims(%{"auth_time" => @now - 120})), max_age: 60)

      assert {:error, :invalid_auth_time} =
               verify(sign(base_claims(%{"auth_time" => @now + 120})), max_age: 60)
    end

    test "time and required-claim failures" do
      assert {:error, :expired} =
               verify(sign(base_claims(%{"exp" => @now - 1})))

      assert {:error, :expired} =
               verify(sign(base_claims(%{"exp" => -1})))

      assert {:error, :missing_exp} =
               verify(sign(Map.delete(base_claims(), "exp")))

      assert {:error, :not_yet_valid} =
               verify(sign(base_claims(%{"iat" => @now + 120})))

      assert {:error, :not_yet_valid} =
               verify(sign(base_claims(%{"nbf" => @now + 120})))

      assert {:error, :invalid_nbf} =
               verify(sign(base_claims(%{"nbf" => "later"})))

      assert {:error, :invalid_claims} =
               verify(sign(base_claims(%{"sub" => ""})))
    end

    test "detached hash failures" do
      assert {:error, :missing_at_hash} =
               verify(sign(base_claims()), access_token: "access-token", require_at_hash: true)

      assert {:ok, _claims} = verify(sign(base_claims()), access_token: "access-token")

      assert {:error, :invalid_at_hash} =
               verify(sign(base_claims(%{"at_hash" => nil})), access_token: "access-token")

      assert {:error, :missing_c_hash} = verify(sign(base_claims()), code: "code-123")
      assert {:error, :missing_s_hash} = verify(sign(base_claims()), state: "state-123")

      assert {:error, :invalid_at_hash} =
               verify(sign(base_claims(%{"at_hash" => hash_claim("other")})),
                 access_token: "access-token"
               )

      assert {:error, :invalid_c_hash} =
               verify(sign(base_claims(%{"c_hash" => hash_claim("other")})), code: "code-123")

      assert {:error, :invalid_s_hash} =
               verify(sign(base_claims(%{"s_hash" => hash_claim("other")})), state: "state-123")
    end

    test "signature, typ, and malformed inputs" do
      other = JOSE.JWK.generate_key({:rsa, 2048})
      {_, jwt} = other |> JOSE.JWT.sign(%{"alg" => "RS256"}, base_claims()) |> JOSE.JWS.compact()

      assert {:error, :invalid_signature} = verify(jwt)
      assert {:ok, _claims} = verify(sign(base_claims(), %{"typ" => "jwt"}))
      assert {:error, :unexpected_typ} = verify(sign(base_claims(), %{"typ" => "at+jwt"}))

      assert {:error, :invalid_token} =
               IDToken.verify("not.a.jwt", issuer: @issuer, client_id: @client_id, jwks: jwks())
    end

    test "rejects ambiguous, unknown, ineligible, and weak verification keys" do
      pem = Keystore.signing_pem()
      jwt = sign(base_claims())
      key = public_jwk(pem, %{"alg" => "RS256"})

      assert {:error, :ambiguous_key} = verify(jwt, jwks: %{"keys" => [key, key]})

      assert {:error, :invalid_signature} =
               verify(jwt, jwks: %{"keys" => [%{key | "kid" => "other"}]})

      assert {:error, :invalid_signature} =
               verify(jwt, jwks: %{"keys" => [%{key | "use" => "enc"}]})

      assert {:error, :invalid_signature} =
               verify(jwt, jwks: %{"keys" => [Map.put(key, "key_ops", ["sign"])]})

      assert {:error, :invalid_signature} =
               verify(jwt,
                 jwks: %{
                   "keys" => [key |> Map.put("use", "sig") |> Map.put("key_ops", ["encrypt"])]
                 }
               )

      for private_member <- ~w(d p q dp dq qi oth k) do
        private_key = Map.put(key, private_member, "private-member")

        assert {:error, :invalid_signature} =
                 verify(jwt, jwks: %{"keys" => [private_key]})
      end

      # An ineligible private entry must not poison selection of an otherwise
      # valid public key with the same kid.
      private_key = Map.put(key, "d", "private-member")
      assert {:ok, _claims} = verify(jwt, jwks: %{"keys" => [private_key, key]})

      weak = JOSE.JWK.generate_key({:rsa, 1024})
      {_, weak_public} = JOSE.JWK.to_public_map(weak)

      {_, weak_jwt} =
        weak
        |> JOSE.JWT.sign(%{"alg" => "RS256", "kid" => "weak", "typ" => "JWT"}, base_claims())
        |> JOSE.JWS.compact()

      assert {:error, :weak_key} =
               verify(weak_jwt,
                 jwks: %{
                   "keys" => [Map.merge(weak_public, %{"kid" => "weak", "alg" => "RS256"})]
                 }
               )
    end

    test "rejects a huge RSA exponent before JOSE bignum verification" do
      jwt = sign(base_claims())
      key = public_jwk(Keystore.signing_pem(), %{"alg" => "RS256"})

      huge_exponent =
        :binary.copy(<<0xFF>>, 100_000)
        |> Base.url_encode64(padding: false)

      hostile_key = Map.put(key, "e", huge_exponent)

      {microseconds, result} =
        :timer.tc(fn -> verify(jwt, jwks: %{"keys" => [hostile_key]}) end)

      assert result == {:error, :invalid_signature}
      assert microseconds < 500_000
    end
  end

  describe "verify/2 issuer aliases" do
    @alias_iss "issuer.example.com"

    test "an alias is accepted as iss only when the caller lists it" do
      token = sign(base_claims(%{"iss" => @alias_iss}))

      assert {:error, :invalid_issuer} = verify(token)
      assert {:error, :invalid_issuer} = verify(token, issuer_aliases: [])
      assert {:error, :invalid_issuer} = verify(token, issuer_aliases: ["other.example.com"])
      assert {:ok, %{"iss" => @alias_iss}} = verify(token, issuer_aliases: [@alias_iss])
    end

    test "the configured issuer is still accepted alongside aliases" do
      assert {:ok, %{"iss" => @issuer}} =
               verify(sign(base_claims()), issuer_aliases: [@alias_iss])
    end

    test "aliases match exactly" do
      token = sign(base_claims(%{"iss" => @alias_iss <> "/"}))

      assert {:error, :invalid_issuer} = verify(token, issuer_aliases: [@alias_iss])
    end

    test "rejects a malformed alias list" do
      for bad <- ["issuer.example.com", [""], [:alias], [@alias_iss, 1], %{}] do
        assert {:error, :invalid_issuer_aliases} =
                 verify(sign(base_claims()), issuer_aliases: bad)
      end
    end
  end

  describe "verify/2 stricter relying-party checks" do
    test ":max_token_age_seconds rejects an iat older than the bound plus clock skew" do
      token = sign(base_claims(%{"iat" => @now - 400}))

      assert {:ok, _claims} = verify(token)
      # Default skew is 60: 400 <= 340 + 60, 400 > 339 + 60.
      assert {:ok, _claims} = verify(token, max_token_age_seconds: 340)
      assert {:error, :token_too_old} = verify(token, max_token_age_seconds: 339)
      assert {:ok, _claims} = verify(token, max_token_age_seconds: 400, clock_skew_seconds: 0)

      assert {:error, :token_too_old} =
               verify(token, max_token_age_seconds: 399, clock_skew_seconds: 0)

      for invalid <- [-1, 1.5, "60", :none] do
        assert {:error, :invalid_max_token_age_seconds} =
                 verify(token, max_token_age_seconds: invalid)
      end
    end

    test "require_auth_time demands auth_time without :max_age" do
      without = sign(base_claims())
      with_auth_time = sign(base_claims(%{"auth_time" => @now - 5_000}))

      assert {:ok, _claims} = verify(without)
      assert {:ok, _claims} = verify(without, require_auth_time: false)
      assert {:error, :auth_time_required} = verify(without, require_auth_time: true)
      # No age is enforced without :max_age.
      assert {:ok, _claims} = verify(with_auth_time, require_auth_time: true)

      assert {:error, :max_age_exceeded} =
               verify(with_auth_time, require_auth_time: true, max_age: 60)

      malformed = sign(base_claims(%{"auth_time" => "yesterday"}))
      assert {:error, :invalid_auth_time} = verify(malformed, require_auth_time: true)

      assert {:error, :invalid_require_auth_time} = verify(without, require_auth_time: "yes")
    end
  end

  describe "verify/2 clock tolerance" do
    test "exp has no leeway unless :expiry_leeway_seconds is set" do
      token = sign(base_claims(%{"exp" => @now - 30}))

      assert {:error, :expired} = verify(token)
      # :clock_skew_seconds bounds future-dated claims; it does not extend exp.
      assert {:error, :expired} = verify(token, clock_skew_seconds: 300)
      assert {:error, :expired} = verify(token, expiry_leeway_seconds: 30)
      assert {:ok, _claims} = verify(token, expiry_leeway_seconds: 31)
    end

    test ":clock_skew_seconds bounds iat, nbf, and auth_time in the future" do
      for claim <- ["iat", "nbf"] do
        token = sign(base_claims(%{claim => @now + 90}))

        assert {:error, :not_yet_valid} = verify(token)
        assert {:ok, _claims} = verify(token, clock_skew_seconds: 90)
        assert {:error, :not_yet_valid} = verify(token, clock_skew_seconds: 89)
      end

      token = sign(base_claims(%{"auth_time" => @now + 90}))
      assert {:error, :invalid_auth_time} = verify(token)
      assert {:ok, _claims} = verify(token, clock_skew_seconds: 90)

      strict = sign(base_claims(%{"iat" => @now + 1}))
      assert {:ok, _claims} = verify(strict)
      assert {:error, :not_yet_valid} = verify(strict, clock_skew_seconds: 0)
    end

    test "each tolerance is an integer from 0 to 300" do
      token = sign(base_claims())

      for bad <- [-1, 301, 1.5, "60", :none] do
        assert {:error, :invalid_clock_skew_seconds} = verify(token, clock_skew_seconds: bad)

        assert {:error, :invalid_expiry_leeway_seconds} =
                 verify(token, expiry_leeway_seconds: bad)
      end

      assert {:ok, _claims} = verify(token, clock_skew_seconds: 300, expiry_leeway_seconds: 300)
      assert {:ok, _claims} = verify(token, clock_skew_seconds: nil, expiry_leeway_seconds: nil)
    end
  end

  describe "verify/2 compact input bounds" do
    test "rejects an oversized protected header before signature verification" do
      protected =
        %{"alg" => "RS256", "padding" => String.duplicate("a", 200_000)}
        |> JSON.encode!()
        |> Base.url_encode64(padding: false)

      payload = base_claims() |> JSON.encode!() |> Base.url_encode64(padding: false)
      jwt = Enum.join([protected, payload, "AA"], ".")

      assert byte_size(protected) > 256 * 1_024
      assert byte_size(jwt) < 1_048_576
      assert {:error, :invalid_token} = verify(jwt)
    end

    test "rejects an oversized signature segment before JOSE verification" do
      [protected, payload, _signature] = sign(base_claims()) |> String.split(".")
      signature = :binary.copy("A", 256 * 1_024 + 4)
      jwt = Enum.join([protected, payload, signature], ".")

      assert byte_size(jwt) < 1_048_576
      assert {:error, :invalid_token} = verify(jwt)
    end

    test "rejects an oversized unsigned token before payload decoding" do
      jwt = unsigned(base_claims(%{"padding" => String.duplicate("a", 768 * 1_024)}))

      assert byte_size(jwt) > 1_048_576
      assert {:error, :invalid_token} = verify(jwt, allow_unsigned: true)
    end

    test "rejects a separator flood through the bounded compact parser" do
      jwt = :binary.copy("e30.", 50_000) <> "e30"

      assert byte_size(jwt) < 1_048_576
      assert {:error, :invalid_token} = verify(jwt)
    end

    test "rejects duplicate JSON members before claims are used" do
      duplicate_payload =
        ~s({"iss":"#{@issuer}","iss":["#{@issuer}","https://evil.example"],"sub":"#{@subject}","aud":"#{@client_id}","iat":#{@now},"exp":#{@now + 600}})

      assert {:error, :invalid_token} = duplicate_payload |> sign_raw_payload() |> verify()

      duplicate_header = ~s({"alg":"RS256","alg":"none","typ":"JWT"})
      payload = base_claims() |> JSON.encode!() |> Base.url_encode64(padding: false)
      jwt = Base.url_encode64(duplicate_header, padding: false) <> "." <> payload <> ".AA"

      assert {:error, :invalid_token} = verify(jwt)
    end
  end

  describe "verify/2 unsigned (alg none)" do
    defp unsigned(claims, header \\ %{"alg" => "none"}) do
      Enum.map_join([header, claims], ".", fn part ->
        part |> JSON.encode!() |> Base.url_encode64(padding: false)
      end) <> "."
    end

    test "rejected by default" do
      assert {:error, :unsupported_alg} = verify(unsigned(base_claims()))
    end

    test "accepted with allow_unsigned: true (OIDC Core §3.1.3.7 code-flow case)" do
      assert {:ok, claims} = verify(unsigned(base_claims()), allow_unsigned: true)
      assert claims["sub"] == @subject

      assert {:ok, _claims} =
               verify(unsigned(base_claims()),
                 allow_unsigned: true,
                 access_token: "optional-without-at-hash"
               )
    end

    test "all claim checks still run when unsigned" do
      assert {:error, :invalid_issuer} =
               verify(unsigned(base_claims(%{"iss" => "https://evil.example"})),
                 allow_unsigned: true
               )

      assert {:error, :invalid_audience} =
               verify(unsigned(base_claims(%{"aud" => "other-client"})), allow_unsigned: true)

      assert {:error, :nonce_mismatch} =
               verify(unsigned(base_claims(%{"nonce" => "wrong"})),
                 allow_unsigned: true,
                 nonce: "expected"
               )

      assert {:error, :expired} =
               verify(unsigned(base_claims(%{"exp" => @now - 1})), allow_unsigned: true)

      assert {:error, :invalid_claims} =
               verify(unsigned(Map.delete(base_claims(), "sub")), allow_unsigned: true)
    end

    test "does not weaken signed tokens: a bad signature still fails" do
      other = JOSE.JWK.generate_key({:rsa, 2048})
      {_, jwt} = other |> JOSE.JWT.sign(%{"alg" => "RS256"}, base_claims()) |> JOSE.JWS.compact()

      assert {:error, :invalid_signature} = verify(jwt, allow_unsigned: true)
    end

    test "rejects alg none with a non-empty signature part (RFC 7519 §6.1)" do
      forged = unsigned(base_claims()) <> Base.url_encode64("sig", padding: false)
      assert {:error, :invalid_token} = verify(forged, allow_unsigned: true)
    end

    test "rejects an unsigned token carrying a crit header" do
      header = %{"alg" => "none", "crit" => ["exp"]}

      assert {:error, :invalid_token} =
               verify(unsigned(base_claims(), header), allow_unsigned: true)
    end
  end
end
