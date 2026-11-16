defmodule AttestoClient.IDTokenKidTest do
  use ExUnit.Case, async: true

  alias AttestoClient.IDToken

  @now 1_800_000_000
  @issuer "https://issuer.example"

  setup do
    key = JOSE.JWK.generate_key({:ec, "P-256"})
    public = Attesto.Key.public_map(key) |> Map.put("kid", "current")

    claims = %{
      "iss" => @issuer,
      "aud" => "client",
      "sub" => "subject",
      "iat" => @now,
      "exp" => @now + 60
    }

    jwt = Attesto.JWS.sign_compact_jwk(key, %{"alg" => "ES256"}, claims)
    %{key: key, public: public, claims: claims, jwt: jwt}
  end

  defp verify(jwt, keys, opts \\ []) do
    IDToken.verify(
      jwt,
      [issuer: @issuer, client_id: "client", jwks: %{"keys" => keys}, now: @now] ++ opts
    )
  end

  test "one key permits an absent kid unless explicitly required", %{jwt: jwt, public: public} do
    assert {:ok, _} = verify(jwt, [public])
    assert {:error, :missing_kid} = verify(jwt, [public], require_kid: true)
    assert {:error, :invalid_require_kid} = verify(jwt, [public], require_kid: "true")
  end

  test "count the published set before algorithm, usage, and duplicate filtering", %{
    jwt: jwt,
    public: public
  } do
    other = JOSE.JWK.generate_key({:ec, "P-384"}) |> Attesto.Key.public_map()

    for second <- [
          other,
          Map.put(public, "use", "enc"),
          public,
          Map.put(public, "key_ops", ["sign"])
        ] do
      assert {:error, :missing_kid} = verify(jwt, [public, second])
      assert {:error, :missing_kid} = verify(jwt, [public, second], require_kid: false)
    end
  end

  test "a supplied kid selects its key, and duplicate eligible ids stay ambiguous", context do
    jwt =
      Attesto.JWS.sign_compact_jwk(
        context.key,
        %{"alg" => "ES256", "kid" => "current"},
        context.claims
      )

    other = Map.put(context.public, "kid", "other")
    assert {:ok, _} = verify(jwt, [other, context.public])
    assert {:error, :ambiguous_key} = verify(jwt, [context.public, context.public])
  end

  test "always-required identifiers also apply to explicitly allowed unsigned tokens", context do
    jwt =
      Base.url_encode64(JSON.encode!(%{"alg" => "none"}), padding: false) <>
        "." <>
        Base.url_encode64(JSON.encode!(context.claims), padding: false) <> "."

    assert {:ok, _} = verify(jwt, [context.public], allow_unsigned: true)

    assert {:error, :missing_kid} =
             verify(jwt, [context.public], allow_unsigned: true, require_kid: true)
  end
end
