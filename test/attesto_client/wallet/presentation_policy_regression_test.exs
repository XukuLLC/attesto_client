defmodule AttestoClient.Wallet.PresentationPolicyRegressionTest do
  use ExUnit.Case, async: true

  alias AttestoClient.Wallet.{Presentation, PresentationRequest}
  alias AttestoClient.Wallet.Presentation.Encryption

  @now 1_700_000_000
  @client "https://verifier.example"
  @audience "https://self-issued.me/v2"

  setup_all do
    key = JOSE.JWK.generate_key({:ec, "P-256"})
    {_type, public} = JOSE.JWK.to_public_map(key)
    %{key: key, public: public}
  end

  defp claims do
    %{
      "client_id" => @client,
      "aud" => @audience,
      "response_type" => "vp_token",
      "response_mode" => "direct_post",
      "nonce" => "n-0S6_WzA2Mj",
      "state" => "state-123",
      "response_uri" => "https://verifier.example/response",
      "dcql_query" => %{"credentials" => [%{"id" => "identity", "format" => "dc+sd-jwt"}]},
      "client_metadata" => %{"vp_formats_supported" => %{"dc+sd-jwt" => %{}}},
      "iat" => @now,
      "exp" => @now + 300
    }
  end

  defp sign(key, claims, header \\ %{"alg" => "ES256", "typ" => "oauth-authz-req+jwt"}) do
    Attesto.JWS.sign_compact_jwk(key, header, claims)
  end

  defp options, do: [client_id: @client, now: @now]

  test "registered identity is client_id; absent and unrelated iss are ignored", context do
    for request_claims <- [
          claims(),
          Map.put(claims(), "iss", "https://unrelated.example"),
          Map.put(claims(), "iss", nil),
          Map.put(claims(), "iss", %{"not" => "identity"})
        ] do
      assert {:ok, %PresentationRequest{client_id: @client}} =
               PresentationRequest.verify(
                 sign(context.key, request_claims),
                 context.public,
                 options()
               )
    end

    assert {:error, :invalid_client_id} =
             PresentationRequest.verify(
               sign(context.key, claims()),
               context.public,
               Keyword.put(options(), :client_id, "https://other.example")
             )
  end

  test "registered type is mandatory and caller accepted_typ/profile cannot weaken it", context do
    for header <- [
          %{"alg" => "ES256"},
          %{"alg" => "ES256", "typ" => "JWT"},
          %{"alg" => "ES256", "typ" => "application/oauth-authz-req+jwt"},
          %{"alg" => "ES256", "typ" => nil}
        ],
        overrides <- [[], [accepted_typ: nil], [accepted_typ: [nil, "JWT"]], [profile: :jar]] do
      assert {:error, :invalid_typ} =
               PresentationRequest.verify(
                 sign(context.key, claims(), header),
                 context.public,
                 Keyword.merge(options(), overrides)
               )
    end
  end

  test "empty, malformed, weak and HAIP-relaxing algorithms fail before request verification",
       context do
    jwt = sign(context.key, claims())

    for algorithms <- [
          [],
          nil,
          "ES256",
          %{},
          [nil],
          [1],
          [:ES256],
          ["none"],
          ["HS256"],
          ["RS256"]
        ] do
      assert {:error, :invalid_algorithm_policy} =
               PresentationRequest.verify(
                 jwt,
                 context.public,
                 Keyword.put(options(), :accepted_algs, algorithms)
               )
    end

    for algorithms <- [["RS256"], ["none"], ["HS256"]] do
      opts =
        Keyword.merge(options(),
          haip: true,
          enforce_fapi_alg_policy: false,
          accepted_algs: algorithms
        )

      assert {:error, :invalid_algorithm_policy} =
               PresentationRequest.verify(jwt, context.public, opts)
    end

    for algorithms <- [["ES384"], ["ES512"], ["RS256"]] do
      opts = Keyword.merge(options(), enforce_fapi_alg_policy: true, accepted_algs: algorithms)

      assert {:error, :invalid_algorithm_policy} =
               PresentationRequest.verify(jwt, context.public, opts)
    end

    assert {:ok, _} =
             PresentationRequest.verify(
               jwt,
               context.public,
               Keyword.put(options(), :accepted_algs, ["ES256"])
             )
  end

  test "registered PS256 cannot accept RSA-1024 even with explicit caller policy" do
    key = JOSE.JWK.generate_key({:rsa, 1024})
    {_type, public} = JOSE.JWK.to_public_map(key)
    public = Map.put(public, "alg", "PS256")
    jwt = sign(key, claims(), %{"alg" => "PS256", "typ" => "oauth-authz-req+jwt"})

    assert {:error, :invalid_signature} =
             PresentationRequest.verify(jwt, public,
               client_id: @client,
               now: @now,
               accepted_algs: ["PS256"],
               enforce_fapi_alg_policy: false
             )
  end

  test "response_mode is required", context do
    assert {:error, :invalid_response_mode} =
             PresentationRequest.verify(
               sign(context.key, Map.delete(claims(), "response_mode")),
               context.public,
               options()
             )
  end

  test "request_uri_method without request_uri fails for outer and signed parameters", context do
    jwt = sign(context.key, claims())

    uri =
      "openid4vp://?" <>
        URI.encode_query(%{
          "client_id" => @client,
          "request" => jwt,
          "request_uri_method" => "post"
        })

    assert {:error, :invalid_request_object} =
             PresentationRequest.from_uri(uri, context.public, options())

    assert {:error, :invalid_request_uri_method} =
             PresentationRequest.verify(
               sign(context.key, Map.put(claims(), "request_uri_method", "post")),
               context.public,
               options()
             )
  end

  test "nonce and state accept URL-safe ASCII only and enforce their byte bound", context do
    for {field, error} <- [{"nonce", :invalid_nonce}, {"state", :invalid_state}],
        value <- [
          "",
          "contains space",
          "é",
          "line\nbreak",
          "+",
          "/",
          "%",
          <<0>>,
          String.duplicate("a", 8193)
        ] do
      assert {:error, ^error} =
               PresentationRequest.verify(
                 sign(context.key, Map.put(claims(), field, value)),
                 context.public,
                 options()
               )
    end

    valid = Map.merge(claims(), %{"nonce" => "AZaz09-._~", "state" => "AZaz09-._~"})

    assert {:ok, _} =
             PresentationRequest.verify(sign(context.key, valid), context.public, options())
  end

  defp response_request(keys \\ nil) do
    %PresentationRequest{
      client_id: @client,
      nonce: "nonce",
      response_uri: "https://verifier.example/response",
      response_mode: if(keys, do: "direct_post.jwt", else: "direct_post"),
      dcql_query: %{
        "credentials" => [%{"id" => "identity", "format" => "dc+sd-jwt", "multiple" => true}]
      },
      client_metadata:
        Map.put(
          if(keys, do: %{"jwks" => %{"keys" => keys}}, else: %{}),
          "vp_formats_supported",
          %{"dc+sd-jwt" => %{}}
        )
    }
  end

  test "every advertised encryption key has a bounded unique nonempty kid", context do
    usable = Map.merge(context.public, %{"alg" => "ECDH-ES", "kid" => "recipient"})
    assert {:ok, _} = Encryption.context(response_request([usable]))

    for keys <- [
          [Map.delete(usable, "kid")],
          [Map.put(usable, "kid", "")],
          [Map.put(usable, "kid", nil)],
          [Map.put(usable, "kid", 42)],
          [Map.put(usable, "kid", String.duplicate("a", 257))],
          [usable, usable],
          [usable, %{"alg" => "RSA-OAEP"}],
          [usable, nil]
        ] do
      assert {:error, :invalid_encryption_metadata} = Encryption.context(response_request(keys))
    end

    plaintext = %{response_request([usable]) | response_mode: "direct_post"}
    assert {:ok, nil} = Encryption.context(plaintext)

    for keys <- [[Map.delete(usable, "kid")], [usable, usable], [Map.put(usable, "kid", "")]] do
      invalid = put_in(plaintext.client_metadata["jwks"]["keys"], keys)
      assert {:error, :invalid_encryption_metadata} = Encryption.context(invalid)
    end
  end

  test "aggregate response size is capped before encryption or HTTP", context do
    public = Map.merge(context.public, %{"alg" => "ECDH-ES", "kid" => "recipient"})
    large = String.duplicate("A", 600_000)
    encrypted = response_request([public])

    assert {:error, :response_too_large} =
             Presentation.build_response(encrypted, %{"identity" => [large, large]})

    plain = response_request()

    plain =
      put_in(plain.dcql_query["credentials"], [
        %{"id" => "identity", "format" => "dc+sd-jwt"},
        %{"id" => "other", "format" => "dc+sd-jwt"}
      ])

    plug = fn _conn -> flunk("oversized response reached HTTP") end

    assert {:error, :response_too_large} =
             Presentation.submit(plain, %{"identity" => [large], "other" => [large]},
               req_options: [plug: plug]
             )

    escaped = String.duplicate(<<0>>, 200_000)

    assert {:error, :response_too_large} =
             Presentation.build_response(response_request(), %{"identity" => [escaped]})

    assert {:ok, _} = Presentation.build_response(response_request(), %{"identity" => ["small"]})

    assert {:error, :invalid_vp_token} =
             Presentation.build_response(response_request(), %{"identity" => [<<255>>]})
  end

  test "caller-built response cannot bypass nonce or state validation" do
    request = response_request()

    assert {:error, :invalid_nonce} =
             Presentation.build_response(%{request | nonce: "unsafe/nonce"}, %{
               "identity" => "small"
             })

    assert {:error, :invalid_state} =
             Presentation.build_response(%{request | state: "unsafe state"}, %{
               "identity" => "small"
             })
  end
end
