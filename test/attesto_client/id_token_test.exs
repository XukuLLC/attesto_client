defmodule AttestoClient.IDTokenTest do
  use ExUnit.Case, async: true

  alias Attesto.SigningAlg
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
    alg
    |> SigningAlg.hash_alg()
    |> :crypto.hash(value)
    |> binary_part(0, SigningAlg.hash_half_bytes(alg))
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

    test "accepts multiple audiences only when azp names this client" do
      jwt = sign(base_claims(%{"aud" => ["other", @client_id], "azp" => @client_id}))

      assert {:ok, _claims} = verify(jwt)
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
  end

  describe "verify/2 rejects" do
    test "wrong issuer, audience, and azp" do
      assert {:error, :invalid_issuer} =
               verify(sign(base_claims(%{"iss" => "https://evil.example"})))

      assert {:error, :invalid_audience} =
               verify(sign(base_claims(%{"aud" => "someone-else"})))

      assert {:error, :missing_azp} =
               verify(sign(base_claims(%{"aud" => ["other", @client_id]})))

      assert {:error, :invalid_azp} =
               verify(sign(base_claims(%{"aud" => ["other", @client_id], "azp" => "other"})))
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

      assert {:error, :missing_exp} =
               verify(sign(Map.delete(base_claims(), "exp")))

      assert {:error, :not_yet_valid} =
               verify(sign(base_claims(%{"iat" => @now + 120})))

      assert {:error, :invalid_claims} =
               verify(sign(base_claims(%{"sub" => ""})))
    end

    test "detached hash failures" do
      assert {:error, :missing_at_hash} =
               verify(sign(base_claims()), access_token: "access-token")

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
      assert {:error, :unexpected_typ} = verify(sign(base_claims(), %{"typ" => "at+jwt"}))

      assert {:error, :invalid_token} =
               IDToken.verify("not.a.jwt", issuer: @issuer, client_id: @client_id, jwks: jwks())
    end
  end
end
