defmodule AttestoClient.Wallet.VerifierFormatPolicyTest do
  use ExUnit.Case, async: true
  alias AttestoClient.Wallet.{Presentation, PresentationRequest}

  setup_all do
    issuer = JOSE.JWK.generate_key({:ec, "P-256"})
    holder = JOSE.JWK.generate_key({:ec, "P-256"})
    public = holder |> JOSE.JWK.to_public_map() |> elem(1)

    credential =
      Attesto.SdJwtVc.issue(
        [
          iss: "https://issuer.example",
          vct: "identity",
          pem: issuer |> JOSE.JWK.to_pem() |> elem(1)
        ],
        cnf: %{"jwk" => public},
        claims: %{"given_name" => "Synthetic"}
      )

    {:ok, verified} =
      Attesto.SdJwtVc.verify(credential, issuer |> JOSE.JWK.to_public_map() |> elem(1))

    held = %{
      format: "dc+sd-jwt",
      credential: credential,
      claims: verified.claims,
      holder_binding: %{"jwk" => public}
    }

    %{
      issuer: issuer,
      issuer_public: issuer |> JOSE.JWK.to_public_map() |> elem(1),
      holder: holder,
      held: held
    }
  end

  test "registered requests need format metadata when it is unavailable elsewhere", ctx do
    jwt = sign_request(ctx.issuer, %{})

    assert {:error, :invalid_verifier_metadata} =
             PresentationRequest.verify(jwt, ctx.issuer_public)

    assert {:ok, request} =
             PresentationRequest.verify(jwt, ctx.issuer_public, verifier_metadata: metadata())

    assert request.client_metadata["vp_formats_supported"] == metadata()["vp_formats_supported"]
  end

  test "trusted registered metadata takes precedence over signed metadata", ctx do
    signed = metadata(%{"sd-jwt_alg_values" => ["ES384"]})

    assert {:ok, request} =
             PresentationRequest.verify(sign_request(ctx.issuer, signed), ctx.issuer_public,
               verifier_metadata: metadata()
             )

    assert {:ok, _} = build(ctx, request)
  end

  test "x509 verifiers cannot supply missing format metadata through caller options", ctx do
    curve = {:namedCurve, {1, 2, 840, 10_045, 3, 1, 7}}

    chain =
      :public_key.pkix_test_data(%{root: [key: curve], intermediates: [], peer: [key: curve]})

    key = chain[:key] |> elem(1) |> JOSE.JWK.from_der()
    id = "x509_hash:" <> Base.url_encode64(:crypto.hash(:sha256, chain[:cert]), padding: false)

    {_jws, jwt} =
      JOSE.JWT.sign(
        key,
        %{
          "alg" => "ES256",
          "typ" => "oauth-authz-req+jwt",
          "x5c" => [Base.encode64(chain[:cert])]
        },
        claims(%{}, id)
      )
      |> JOSE.JWS.compact()

    assert {:error, :invalid_verifier_metadata} =
             PresentationRequest.verify(jwt, nil,
               trusted_certificates: chain[:cacerts],
               verifier_metadata: metadata()
             )

    assert {:ok, _} = build(ctx, request())
  end

  test "plaintext presentations always use nonempty arrays and scalars are rejected", ctx do
    req = request()
    assert {:ok, %{"identity" => [presentation]} = vp} = build(ctx, req)
    assert {:ok, form} = Presentation.build_response(req, vp)
    assert JSON.decode!(form["vp_token"]) == vp

    assert {:error, :invalid_vp_token} =
             Presentation.build_response(req, %{"identity" => presentation})

    assert {:error, :invalid_vp_token} = Presentation.build_response(req, %{"identity" => []})
  end

  test "issuer and holder algorithm advertisements constrain actual generated signatures", ctx do
    for field <- ["sd-jwt_alg_values", "kb-jwt_alg_values"] do
      incompatible = request(metadata(%{field => ["ES384"]}))
      assert {:error, {"identity", :incompatible_verifier_format}} = build(ctx, incompatible)
    end

    assert {:error, {"identity", :incompatible_verifier_format}} =
             build(ctx, request(%{"vp_formats_supported" => %{"mso_mdoc" => %{}}}))

    assert {:ok, _} =
             build(ctx, request(metadata(%{"unknown_extension" => %{"ignored" => true}})))
  end

  test "manually built responses cannot bypass verifier algorithm constraints", ctx do
    assert {:ok, vp} = build(ctx, request())

    for field <- ["sd-jwt_alg_values", "kb-jwt_alg_values"] do
      assert {:error, :incompatible_verifier_format} =
               Presentation.build_response(request(metadata(%{field => ["ES384"]})), vp)
    end
  end

  test "missing, empty and malformed format metadata fails closed before submission", ctx do
    parent = self()

    forbidden = fn conn ->
      send(parent, :network)
      Req.Test.json(conn, %{})
    end

    for bad <- [
          %{},
          %{"vp_formats_supported" => %{}},
          %{"vp_formats_supported" => []},
          metadata(%{"kb-jwt_alg_values" => []}),
          metadata(%{"sd-jwt_alg_values" => [123]})
        ] do
      assert {:error, :invalid_verifier_metadata} =
               Presentation.present(request(bad), [ctx.held],
                 holder_keys: %{"identity" => ctx.holder},
                 req_options: [plug: forbidden]
               )

      refute_received :network
    end
  end

  defp build(ctx, request),
    do:
      Presentation.build_vp_token(%{"identity" => ctx.held}, request,
        holder_keys: %{"identity" => ctx.holder}
      )

  defp metadata(overrides \\ %{}),
    do: %{
      "vp_formats_supported" => %{
        "dc+sd-jwt" =>
          Map.merge(
            %{"sd-jwt_alg_values" => ["ES256"], "kb-jwt_alg_values" => ["ES256"]},
            overrides
          )
      }
    }

  defp request(metadata \\ metadata()) do
    %PresentationRequest{
      client_id: "https://verifier.example",
      nonce: "synthetic-nonce",
      response_uri: "https://verifier.example/response",
      response_mode: "direct_post",
      dcql_query: query(),
      client_metadata: metadata
    }
  end

  defp query, do: %{"credentials" => [%{"id" => "identity", "format" => "dc+sd-jwt"}]}

  defp claims(metadata, id \\ "https://verifier.example") do
    now = System.system_time(:second)

    %{
      "client_id" => id,
      "aud" => "https://self-issued.me/v2",
      "iat" => now,
      "exp" => now + 300,
      "nonce" => "synthetic-nonce",
      "response_type" => "vp_token",
      "response_mode" => "direct_post",
      "response_uri" => "https://verifier.example/response",
      "dcql_query" => query(),
      "client_metadata" => metadata
    }
  end

  defp sign_request(key, metadata) do
    {_jws, jwt} =
      JOSE.JWT.sign(key, %{"alg" => "ES256", "typ" => "oauth-authz-req+jwt"}, claims(metadata))
      |> JOSE.JWS.compact()

    jwt
  end
end
