defmodule AttestoClient.Wallet.PresentationX509Test do
  use ExUnit.Case, async: true
  alias AttestoClient.Wallet.Presentation.CertificateTrust
  alias AttestoClient.Wallet.PresentationRequest

  setup_all do
    curve = {:namedCurve, {1, 2, 840, 10_045, 3, 1, 7}}

    data =
      :public_key.pkix_test_data(%{root: [key: curve], intermediates: [], peer: [key: curve]})

    key = data[:key] |> elem(1) |> JOSE.JWK.from_der()
    recipient = JOSE.JWK.generate_key({:ec, "P-256"}) |> JOSE.JWK.to_public_map() |> elem(1)

    client_id =
      "x509_hash:" <> (:crypto.hash(:sha256, data[:cert]) |> Base.url_encode64(padding: false))

    claims = %{
      "client_id" => client_id,
      "aud" => "https://self-issued.me/v2",
      "nonce" => "fresh-request-nonce",
      "response_type" => "vp_token",
      "response_mode" => "direct_post.jwt",
      "response_uri" => "https://verifier.example/response",
      "dcql_query" => %{"credentials" => [%{"id" => "identity", "format" => "dc+sd-jwt"}]},
      "client_metadata" => %{
        "encrypted_response_enc_values_supported" => ["A128GCM", "A256GCM"],
        "vp_formats_supported" => %{"dc+sd-jwt" => %{}},
        "jwks" => %{"keys" => [Map.merge(recipient, %{"alg" => "ECDH-ES", "kid" => "recipient"})]}
      }
    }

    %{key: key, leaf: data[:cert], anchors: data[:cacerts], claims: claims}
  end

  defp sign(context, overrides \\ %{}, header_overrides \\ %{}) do
    claims = Map.merge(context.claims, overrides)

    header =
      Map.merge(
        %{
          "alg" => "ES256",
          "typ" => "oauth-authz-req+jwt",
          "x5c" => [Base.encode64(context.leaf)]
        },
        header_overrides
      )

    Attesto.JWS.sign_compact_jwk(context.key, header, claims)
  end

  defp options(context),
    do: [trusted_certificates: context.anchors, accepted_algs: ["ES256"], haip: true]

  defp deep_link(context, jwt, overrides \\ %{}) do
    params = Map.merge(%{"client_id" => context.claims["client_id"], "request" => jwt}, overrides)
    "openid4vp://?" <> URI.encode_query(params)
  end

  test "validates a final request without JAR iss and derives the actual leaf public key",
       context do
    assert {:ok, request} = PresentationRequest.verify(sign(context), nil, options(context))
    assert request.client_id == context.claims["client_id"]
    assert request.response_mode == "direct_post.jwt"
    assert request.profile == :haip
    assert {:ok, provenance} = CertificateTrust.verify([context.leaf], options(context))
    assert provenance.public_key == context.key |> JOSE.JWK.to_public_map() |> elem(1)
    assert is_list(provenance.authority_key_identifiers)
  end

  test "HAIP requires signed advertisement of both GCM algorithms", context do
    for values <- [nil, [], ["A128GCM"], ["A256GCM"]] do
      metadata =
        Map.put(
          context.claims["client_metadata"],
          "encrypted_response_enc_values_supported",
          values
        )

      assert {:error, :invalid_encryption_metadata} =
               PresentationRequest.verify(
                 sign(context, %{"client_metadata" => metadata}),
                 nil,
                 options(context)
               )
    end
  end

  test "signed request iss is ignored rather than used as verifier identity", context do
    for issuer <- ["https://other-verifier.example", nil, %{"unexpected" => "issuer"}] do
      assert {:ok, request} =
               PresentationRequest.verify(
                 sign(context, %{"iss" => issuer}),
                 nil,
                 options(context)
               )

      assert request.client_id == context.claims["client_id"]
    end
  end

  test "an mdoc issuer leaf cannot authenticate an x509 verifier request", context do
    data =
      :public_key.pkix_test_data(%{
        root: [key: {:namedCurve, {1, 2, 840, 10_045, 3, 1, 7}}],
        intermediates: [],
        peer: [
          key: {:namedCurve, {1, 2, 840, 10_045, 3, 1, 7}},
          extensions: [{:Extension, {2, 5, 29, 37}, true, [{1, 0, 18_013, 5, 1, 2}]}]
        ]
      })

    issuer = certificate_context(context, data)
    opts = Keyword.put(options(issuer), :purpose, :mdoc_issuer)
    assert {:ok, _verified} = CertificateTrust.verify([issuer.leaf], opts)
    jwt = sign(issuer)
    assert {true, %JOSE.JWT{}, _} = JOSE.JWT.verify_strict(issuer.key, ["ES256"], jwt)
    assert {:error, :untrusted_certificate} = PresentationRequest.verify(jwt, nil, opts)
  end

  test "ignoring iss preserves static and configured dynamic wallet audience checks", context do
    claims = %{"iss" => "https://other-verifier.example", "aud" => "https://self-issued.me/v2"}
    assert {:ok, _} = PresentationRequest.verify(sign(context, claims), nil, options(context))

    dynamic_audience = "https://wallet.example"
    dynamic_opts = Keyword.put(options(context), :audience, dynamic_audience)
    dynamic = Map.put(claims, "aud", dynamic_audience)
    assert {:ok, _} = PresentationRequest.verify(sign(context, dynamic), nil, dynamic_opts)

    assert {:error, :invalid_audience} =
             PresentationRequest.verify(sign(context, dynamic), nil, options(context))

    assert {:error, :invalid_audience} =
             PresentationRequest.verify(sign(context, claims), nil, dynamic_opts)

    for audience <- [
          nil,
          "",
          [],
          %{},
          "https://other-wallet.example",
          ["https://self-issued.me/v2", 42],
          ["https://self-issued.me/v2", nil]
        ] do
      assert {:error, :invalid_audience} =
               PresentationRequest.verify(
                 sign(context, %{"aud" => audience}),
                 nil,
                 options(context)
               )
    end

    missing = %{context | claims: Map.delete(context.claims, "aud")}

    assert {:error, :invalid_audience} =
             PresentationRequest.verify(sign(missing), nil, options(missing))
  end

  test "ignored issuer cannot replace signed or outer client identity", context do
    other_id = "x509_hash:other-verifier"
    signed = sign(context, %{"iss" => other_id})
    opts = Keyword.put(options(context), :haip, false)

    assert {:error, :invalid_client_id} =
             PresentationRequest.from_uri(
               deep_link(context, signed, %{"client_id" => other_id}),
               nil,
               opts
             )

    assert {:error, :invalid_client_id} =
             PresentationRequest.verify(
               sign(context, %{"client_id" => other_id, "iss" => context.claims["client_id"]}),
               nil,
               options(context)
             )
  end

  test "chain requires explicit trust and an additional policy cannot bypass it", context do
    jwt = sign(context)

    assert {:error, :untrusted_certificate} =
             PresentationRequest.verify(jwt, nil, certificate_trust: fn _ -> :ok end)

    %{cert: unrelated} = :public_key.pkix_test_root_cert(~c"unrelated-root", [])

    assert {:error, :untrusted_certificate} =
             PresentationRequest.verify(jwt, nil, trusted_certificates: [unrelated])

    assert {:error, :untrusted_certificate} =
             PresentationRequest.verify(
               jwt,
               nil,
               Keyword.put(options(context), :certificate_trust, fn _ ->
                 {:error, :policy_denied}
               end)
             )

    assert {:error, :untrusted_certificate} =
             CertificateTrust.verify([:binary.copy("x", 65_537)], options(context))
  end

  test "rejects incorrect leaf hash, signature, typ and critical extension", context do
    assert {:error, :invalid_client_id} =
             PresentationRequest.verify(
               sign(context, %{"client_id" => "x509_hash:incorrect"}),
               nil,
               options(context)
             )

    wrong = %{context | key: JOSE.JWK.generate_key({:ec, "P-256"})}

    assert {:error, :invalid_signature} =
             PresentationRequest.verify(sign(wrong), nil, options(context))

    assert {:error, :invalid_typ} =
             PresentationRequest.verify(
               sign(context, %{}, %{"typ" => "JWT"}),
               nil,
               options(context)
             )

    assert {:error, :unsupported_crit} =
             PresentationRequest.verify(
               sign(context, %{}, %{"crit" => ["unknown"]}),
               nil,
               options(context)
             )
  end

  test "outer client identity is bound and other unsigned authorization parameters are ignored",
       context do
    # By value is supported by final OID4VP; HAIP requires request_uri instead.
    opts = Keyword.put(options(context), :haip, false)

    assert {:ok, request} =
             PresentationRequest.from_uri(
               deep_link(context, sign(context), %{"response_uri" => "https://untrusted.example"}),
               nil,
               opts
             )

    assert request.response_uri == context.claims["response_uri"]

    assert {:error, :invalid_client_id} =
             PresentationRequest.from_uri(
               deep_link(context, sign(context), %{"client_id" => "x509_hash:other"}),
               nil,
               opts
             )

    assert {:error, :invalid_request_object} =
             PresentationRequest.from_uri(
               deep_link(context, sign(context)) <> "&client_id=duplicate",
               nil,
               opts
             )

    assert {:error, :invalid_request_object} =
             PresentationRequest.from_uri(
               deep_link(context, sign(context)),
               nil,
               options(context)
             )
  end

  test "HAIP rejects embedded trust anchors and self-signed signing certificates", context do
    assert {:error, :untrusted_certificate} =
             PresentationRequest.verify(
               sign(context, %{}, %{
                 "x5c" => Enum.map([context.leaf | context.anchors], &Base.encode64/1)
               }),
               nil,
               options(context)
             )

    data =
      :public_key.pkix_test_root_cert(~c"self-signed-verifier",
        key: {:namedCurve, {1, 2, 840, 10_045, 3, 1, 7}}
      )

    assert {:error, :untrusted_certificate} =
             CertificateTrust.verify([data.cert], trusted_certificates: [data.cert], haip: true)
  end

  test "validated request rejects redirect_uri, missing nonce, unknown transaction data and bad dates",
       context do
    for {overrides, reason} <- [
          {%{"redirect_uri" => "https://verifier.example/redirect"}, :invalid_request},
          {%{"nonce" => ""}, :invalid_nonce},
          {%{"transaction_data" => ["unsupported"]}, :invalid_transaction_data},
          {%{"iat" => "not-a-date"}, :invalid_request_object},
          {%{"exp" => System.system_time(:second) - 1}, :expired},
          {%{"client_id" => "origin:https://verifier.example"}, :invalid_client_id},
          {%{"client_id" => "unsupported:client"}, :unsupported_client_id_prefix}
        ] do
      assert {:error, ^reason} =
               PresentationRequest.verify(sign(context, overrides), nil, options(context))
    end
  end

  test "POST request_uri sends and validates a fresh wallet nonce", context do
    request_uri = "https://verifier.example/request"

    plug = fn conn ->
      assert conn.method == "POST"
      assert Plug.Conn.get_req_header(conn, "accept") == ["application/oauth-authz-req+jwt"]
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      nonce = URI.decode_query(body)["wallet_nonce"]
      assert is_binary(nonce) and byte_size(nonce) >= 32
      jwt = sign(context, %{"wallet_nonce" => nonce})

      conn
      |> Plug.Conn.put_resp_content_type("application/oauth-authz-req+jwt")
      |> Plug.Conn.send_resp(200, jwt)
    end

    uri =
      "openid4vp://?" <>
        URI.encode_query(%{
          "client_id" => context.claims["client_id"],
          "request_uri" => request_uri,
          "request_uri_method" => "post"
        })

    assert {:ok, _} =
             PresentationRequest.from_uri(
               uri,
               nil,
               Keyword.put(options(context), :req_options, plug: plug)
             )

    wrong_plug = fn conn ->
      conn
      |> Plug.Conn.put_resp_content_type("application/oauth-authz-req+jwt")
      |> Plug.Conn.send_resp(200, sign(context, %{"wallet_nonce" => "wrong"}))
    end

    assert {:error, :invalid_wallet_nonce} =
             PresentationRequest.from_uri(
               uri,
               nil,
               Keyword.put(options(context), :req_options, plug: wrong_plug)
             )
  end

  test "verified issuer provenance includes AKI bytes but excludes subject key identifiers" do
    curve = {:namedCurve, {1, 2, 840, 10_045, 3, 1, 7}}
    aki = :crypto.strong_rand_bytes(20)
    ski = :crypto.strong_rand_bytes(20)

    extensions = [
      {:Extension, {2, 5, 29, 35}, false,
       {:AuthorityKeyIdentifier, aki, :asn1_NOVALUE, :asn1_NOVALUE}},
      {:Extension, {2, 5, 29, 14}, false, ski}
    ]

    data =
      :public_key.pkix_test_data(%{
        root: [key: curve, extensions: [{:Extension, {2, 5, 29, 14}, false, aki}]],
        intermediates: [],
        peer: [key: curve, extensions: extensions]
      })

    assert {:ok, provenance} =
             CertificateTrust.verify([data[:cert]], trusted_certificates: data[:cacerts])

    assert provenance.authority_key_identifiers == [Base.url_encode64(aki, padding: false)]
    refute Base.url_encode64(ski, padding: false) in provenance.authority_key_identifiers
  end

  test "PS256 rejects a correctly signed weak RSA leaf even with an explicit algorithm policy",
       context do
    for bits <- [1024, 2048] do
      data =
        :public_key.pkix_test_data(%{
          root: [key: {:namedCurve, {1, 2, 840, 10_045, 3, 1, 7}}],
          intermediates: [],
          peer: [key: {:rsa, bits, 65_537}]
        })

      rsa_context = certificate_context(context, data)
      jwt = sign(rsa_context, %{}, %{"alg" => "PS256"})
      opts = Keyword.put(options(rsa_context), :accepted_algs, ["PS256"])

      # The chain is trusted and the RSA signature is cryptographically valid;
      # only the independent key-strength policy must reject the weak leaf.
      assert {:ok, _provenance} = CertificateTrust.verify([rsa_context.leaf], opts)

      assert {true, %JOSE.JWT{}, _} =
               JOSE.JWT.verify_strict(JOSE.JWK.to_public(rsa_context.key), ["PS256"], jwt)

      assert_ps256_result(PresentationRequest.verify(jwt, nil, opts), bits)

      assert_ps256_result(
        PresentationRequest.verify(jwt, nil, Keyword.delete(opts, :accepted_algs)),
        bits
      )
    end
  end

  test "the RSA strength filter does not remove ES384 or ES512", context do
    for {curve, algorithm} <- [{{1, 3, 132, 0, 34}, "ES384"}, {{1, 3, 132, 0, 35}, "ES512"}] do
      data =
        :public_key.pkix_test_data(%{
          root: [key: {:namedCurve, {1, 2, 840, 10_045, 3, 1, 7}}],
          intermediates: [],
          peer: [key: {:namedCurve, curve}]
        })

      ec_context = certificate_context(context, data)
      jwt = sign(ec_context, %{}, %{"alg" => algorithm})

      assert {:ok, _request} =
               PresentationRequest.verify(
                 jwt,
                 nil,
                 Keyword.put(options(ec_context), :accepted_algs, [algorithm])
               )

      assert {:error, :invalid_algorithm_policy} =
               PresentationRequest.verify(
                 jwt,
                 nil,
                 options(ec_context)
                 |> Keyword.put(:enforce_fapi_alg_policy, true)
                 |> Keyword.put(:accepted_algs, [algorithm])
               )
    end
  end

  defp certificate_context(context, data) do
    id = "x509_hash:" <> (:crypto.hash(:sha256, data[:cert]) |> Base.url_encode64(padding: false))

    %{
      context
      | key: data[:key] |> elem(1) |> JOSE.JWK.from_der(),
        leaf: data[:cert],
        anchors: data[:cacerts],
        claims: Map.put(context.claims, "client_id", id)
    }
  end

  defp assert_ps256_result(result, 1024), do: assert(result == {:error, :invalid_signature})
  defp assert_ps256_result({:ok, %PresentationRequest{}}, 2048), do: :ok
end
