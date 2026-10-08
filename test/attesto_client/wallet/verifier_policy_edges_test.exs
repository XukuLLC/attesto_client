defmodule AttestoClient.Wallet.VerifierPolicyEdgesTest do
  use ExUnit.Case, async: true

  alias Attesto.{Mdoc, SdJwtVc, VpToken}
  alias AttestoClient.Wallet.{Presentation, PresentationRequest}
  alias AttestoClient.Wallet.Presentation.CertificateTrust

  @now 1_700_000_000
  @client "registered-verifier"
  @doc_type "org.iso.18013.5.1.mDL"
  @namespace "org.iso.18013.5.1"
  @curve {:namedCurve, {1, 2, 840, 10_045, 3, 1, 7}}

  setup_all do
    issuer = JOSE.JWK.generate_key({:ec, "P-256"})
    holder = JOSE.JWK.generate_key({:ec, "P-256"})
    public = public(holder)
    issuer_public = public(issuer)
    pem = issuer |> JOSE.JWK.to_pem() |> elem(1)

    sd_jwt =
      SdJwtVc.issue([iss: "https://issuer.example", vct: "identity", pem: pem],
        claims: %{"given_name" => "Synthetic"},
        cnf: %{"jwk" => public},
        iat: @now
      )

    {:ok, verified_sd} = SdJwtVc.verify(sd_jwt, issuer_public, now: @now)

    {:ok, mdoc} =
      Mdoc.issue(
        issuer_pem: pem,
        doc_type: @doc_type,
        device_key: public,
        namespaces: %{@namespace => %{"given_name" => "Synthetic"}},
        validity: %{signed: @now - 10, valid_from: @now - 5, valid_until: @now + 3600}
      )

    {:ok, verified_mdoc} = Mdoc.verify(mdoc, issuer_public, now: @now)

    %{
      issuer: issuer,
      issuer_public: issuer_public,
      holder: holder,
      sd: %{
        format: "dc+sd-jwt",
        credential: sd_jwt,
        claims: verified_sd.claims,
        holder_binding: %{"jwk" => public}
      },
      mdoc: %{
        format: "mso_mdoc",
        credential: mdoc,
        claims: verified_mdoc.namespaces,
        holder_binding: public,
        doc_type: @doc_type
      }
    }
  end

  test "mdoc advertised -7 and -9 both accept real P-256 issuer and device signatures", context do
    for issuer_alg <- [-7, -9], device_alg <- [-7, -9] do
      request =
        request("mso_mdoc", %{
          "issuerauth_alg_values" => [issuer_alg],
          "deviceauth_alg_values" => [device_alg]
        })

      assert {:ok, %{"identity" => [presentation]} = token} =
               Presentation.build_vp_token(%{"identity" => context.mdoc}, request,
                 holder_keys: %{"identity" => context.holder}
               )

      assert is_binary(presentation)
      assert {:ok, _form} = Presentation.build_response(request, token)

      assert {:ok, %{"identity" => [verified]}} =
               VpToken.verify(token,
                 nonce: request.nonce,
                 audience: @client,
                 response_uri: request.response_uri,
                 formats: %{"identity" => "mso_mdoc"},
                 issuer_jwks: context.issuer_public,
                 now: @now
               )

      assert verified.doc_type == @doc_type
    end
  end

  test "mdoc incompatible issuer or device algorithms reject generated and manual responses",
       context do
    allowed = request("mso_mdoc", %{})

    assert {:ok, token} =
             Presentation.build_vp_token(%{"identity" => context.mdoc}, allowed,
               holder_keys: %{"identity" => context.holder}
             )

    for field <- ["issuerauth_alg_values", "deviceauth_alg_values"] do
      incompatible = request("mso_mdoc", %{field => [-35]})

      assert {:error, {"identity", :incompatible_verifier_format}} =
               Presentation.build_vp_token(%{"identity" => context.mdoc}, incompatible,
                 holder_keys: %{"identity" => context.holder}
               )

      assert {:error, :incompatible_verifier_format} =
               Presentation.build_response(incompatible, token)
    end
  end

  test "authoritative registered format algorithms cannot be widened by signed metadata",
       context do
    signed = metadata("dc+sd-jwt", %{"sd-jwt_alg_values" => ["ES256"]})
    trusted = metadata("dc+sd-jwt", %{"sd-jwt_alg_values" => ["ES384"]})
    jwt = signed_request(context.issuer, signed)

    assert {:ok, verified} =
             PresentationRequest.verify(jwt, context.issuer_public,
               now: @now,
               client_id: @client,
               verifier_metadata: trusted
             )

    assert verified.client_metadata["vp_formats_supported"] == trusted["vp_formats_supported"]

    assert {:error, {"identity", :incompatible_verifier_format}} =
             Presentation.build_vp_token(%{"identity" => context.sd}, verified,
               holder_keys: %{"identity" => context.holder},
               now: @now
             )
  end

  test "x509 format metadata must come from the actual signed request" do
    chain =
      :public_key.pkix_test_data(%{root: [key: @curve], intermediates: [], peer: [key: @curve]})

    key = chain[:key] |> elem(1) |> JOSE.JWK.from_der()
    id = "x509_hash:" <> Base.url_encode64(:crypto.hash(:sha256, chain[:cert]), padding: false)

    claims =
      claims(%{}, id)
      |> Map.delete("client_metadata")
      |> Map.put("exp", System.system_time(:second) + 300)
      |> Map.put("iat", System.system_time(:second))

    header = %{
      "alg" => "ES256",
      "typ" => "oauth-authz-req+jwt",
      "x5c" => [Base.encode64(chain[:cert])]
    }

    jwt = sign(key, claims, header)

    assert {:error, :invalid_verifier_metadata} =
             PresentationRequest.verify(jwt, nil,
               trusted_certificates: chain[:cacerts],
               verifier_metadata: metadata("dc+sd-jwt", %{})
             )
  end

  test "malformed raw certificates fail closed without invalidating unrelated valid anchors" do
    chain =
      :public_key.pkix_test_data(%{root: [key: @curve], intermediates: [], peer: [key: @curve]})

    for malformed <- [
          <<48, 128, 0, 0>>,
          <<48, 130, 255>>,
          <<48, 3, 48, 1, 0>>,
          chain[:cert] <> <<0>>
        ] do
      assert {:error, _reason} =
               CertificateTrust.verify([malformed], trusted_certificates: chain[:cacerts])

      assert {:ok, _verified} =
               CertificateTrust.verify([chain[:cert]],
                 trusted_certificates: [malformed | chain[:cacerts]]
               )
    end
  end

  test "both response modes require arrays and aggregate size is rejected before HTTP", context do
    encryption = JOSE.JWK.generate_key({:ec, "P-256"})
    enc_public = Map.merge(public(encryption), %{"alg" => "ECDH-ES", "kid" => "recipient"})
    owner = self()

    spy = fn conn ->
      send(owner, :unexpected_http)
      Req.Test.json(conn, %{})
    end

    for mode <- ["direct_post", "direct_post.jwt"] do
      request = request("dc+sd-jwt", %{})

      request = %{
        request
        | response_mode: mode,
          client_metadata: Map.put(request.client_metadata, "jwks", %{"keys" => [enc_public]})
      }

      assert {:ok, %{"identity" => [presentation]} = token} =
               Presentation.build_vp_token(%{"identity" => context.sd}, request,
                 holder_keys: %{"identity" => context.holder},
                 now: @now
               )

      assert {:ok, _form} = Presentation.build_response(request, token)

      for invalid <- [presentation, []] do
        assert {:error, :invalid_vp_token} =
                 Presentation.submit(request, %{"identity" => invalid}, req_options: [plug: spy])
      end

      query = put_in(request.dcql_query, ["credentials", Access.at(0), "multiple"], true)
      count = div(1_048_576, byte_size(presentation)) + 1
      oversized = %{"identity" => List.duplicate(presentation, count)}

      assert {:error, :response_too_large} =
               Presentation.submit(%{request | dcql_query: query}, oversized,
                 req_options: [plug: spy]
               )

      refute_received :unexpected_http
    end
  end

  defp public(key), do: key |> JOSE.JWK.to_public_map() |> elem(1)

  defp metadata(format, algorithms), do: %{"vp_formats_supported" => %{format => algorithms}}

  defp request(format, algorithms) do
    %PresentationRequest{
      client_id: @client,
      nonce: "synthetic-nonce",
      response_uri: "https://verifier.example/response",
      response_mode: "direct_post",
      dcql_query: %{"credentials" => [%{"id" => "identity", "format" => format}]},
      client_metadata: metadata(format, algorithms)
    }
  end

  defp claims(metadata, client_id \\ @client) do
    %{
      "client_id" => client_id,
      "aud" => "https://self-issued.me/v2",
      "iat" => @now,
      "exp" => @now + 300,
      "nonce" => "synthetic-nonce",
      "response_type" => "vp_token",
      "response_mode" => "direct_post",
      "response_uri" => "https://verifier.example/response",
      "dcql_query" => %{"credentials" => [%{"id" => "identity", "format" => "dc+sd-jwt"}]},
      "client_metadata" => metadata
    }
  end

  defp signed_request(key, metadata), do: sign(key, claims(metadata))

  defp sign(key, claims, header \\ %{"alg" => "ES256", "typ" => "oauth-authz-req+jwt"}) do
    {_jws, jwt} = key |> JOSE.JWT.sign(header, claims) |> JOSE.JWS.compact()
    jwt
  end
end
