defmodule AttestoClient.Wallet.PresentationRequestTest do
  use ExUnit.Case, async: true

  alias AttestoClient.RequestObject
  alias AttestoClient.Wallet.PresentationRequest

  @verifier_client_id "https://verifier.example.com"
  @wallet_audience "https://wallet.example.com"
  @nonce "nonce-abc"
  @response_uri "https://verifier.example.com/response"

  defp verifier_keypair do
    jwk = JOSE.JWK.generate_key({:ec, "P-256"})
    {_type, public} = JOSE.JWK.to_public_map(jwk)
    {jwk, public}
  end

  defp dcql_query do
    %{
      "credentials" => [
        %{"id" => "cred1", "format" => "dc+sd-jwt", "meta" => %{"vct_values" => ["identity"]}}
      ]
    }
  end

  defp verify_opts(overrides \\ []) do
    Keyword.merge([issuer: @verifier_client_id, audience: @wallet_audience], overrides)
  end

  defp build_request_jwt(rp_key, params_overrides \\ %{}) do
    params =
      Map.merge(
        %{
          "client_id" => @verifier_client_id,
          "response_type" => "vp_token",
          "nonce" => @nonce,
          "response_uri" => @response_uri,
          "dcql_query" => dcql_query()
        },
        params_overrides
      )

    {:ok, jwt} =
      RequestObject.build(rp_key,
        client_id: @verifier_client_id,
        audience: @wallet_audience,
        params: params
      )

    jwt
  end

  describe "verify/3" do
    test "parses a valid signed OID4VP request object" do
      {rp_key, rp_public} = verifier_keypair()
      jwt = build_request_jwt(rp_key)

      assert {:ok, %PresentationRequest{} = request} =
               PresentationRequest.verify(jwt, rp_public, verify_opts())

      assert request.client_id == @verifier_client_id
      assert request.nonce == @nonce
      assert request.response_uri == @response_uri
      assert request.response_mode == "direct_post"
      assert request.dcql_query == dcql_query()
      assert request.state == nil
    end

    test "carries state and an explicit response_mode" do
      {rp_key, rp_public} = verifier_keypair()

      jwt =
        build_request_jwt(rp_key, %{"state" => "state-1", "response_mode" => "direct_post.jwt"})

      assert {:ok, request} = PresentationRequest.verify(jwt, rp_public, verify_opts())
      assert request.state == "state-1"
      assert request.response_mode == "direct_post.jwt"
    end

    test "rejects a tampered signature" do
      {rp_key, rp_public} = verifier_keypair()
      jwt = build_request_jwt(rp_key)
      [header, payload, signature] = String.split(jwt, ".")
      flipped = if String.last(signature) == "A", do: "B", else: "A"
      tampered = Enum.join([header, payload, String.slice(signature, 0..-2//1) <> flipped], ".")

      assert {:error, _reason} = PresentationRequest.verify(tampered, rp_public, verify_opts())
    end

    test "rejects the wrong audience or issuer" do
      {rp_key, rp_public} = verifier_keypair()
      jwt = build_request_jwt(rp_key)

      assert {:error, :invalid_audience} =
               PresentationRequest.verify(
                 jwt,
                 rp_public,
                 verify_opts(audience: "https://other.example.com")
               )

      assert {:error, :invalid_issuer} =
               PresentationRequest.verify(
                 jwt,
                 rp_public,
                 verify_opts(issuer: "https://other-verifier.example.com")
               )
    end

    test "rejects a response_type other than vp_token" do
      {rp_key, rp_public} = verifier_keypair()
      jwt = build_request_jwt(rp_key, %{"response_type" => "code"})

      assert {:error, :invalid_response_type} =
               PresentationRequest.verify(jwt, rp_public, verify_opts())
    end

    test "rejects an unrecognised response_mode" do
      {rp_key, rp_public} = verifier_keypair()
      jwt = build_request_jwt(rp_key, %{"response_mode" => "fragment"})

      assert {:error, :invalid_response_mode} =
               PresentationRequest.verify(jwt, rp_public, verify_opts())
    end

    test "rejects a missing nonce, response_uri, or dcql_query" do
      {rp_key, rp_public} = verifier_keypair()

      assert {:error, :invalid_nonce} =
               build_request_jwt(rp_key, %{"nonce" => ""})
               |> PresentationRequest.verify(rp_public, verify_opts())

      assert {:error, :invalid_response_uri} =
               build_request_jwt(rp_key, %{"response_uri" => ""})
               |> PresentationRequest.verify(rp_public, verify_opts())

      {:ok, jwt_without_dcql} =
        RequestObject.build(rp_key,
          client_id: @verifier_client_id,
          audience: @wallet_audience,
          params: %{
            "client_id" => @verifier_client_id,
            "response_type" => "vp_token",
            "nonce" => @nonce,
            "response_uri" => @response_uri
          }
        )

      assert {:error, :invalid_dcql_query} =
               PresentationRequest.verify(jwt_without_dcql, rp_public, verify_opts())
    end
  end

  describe "fetch/3" do
    defp text_plug(status, body) do
      fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/oauth-authz-req+jwt")
        |> Plug.Conn.send_resp(status, body)
      end
    end

    test "GETs the request object and verifies it" do
      {rp_key, rp_public} = verifier_keypair()
      jwt = build_request_jwt(rp_key)

      assert {:ok, request} =
               PresentationRequest.fetch(
                 "https://verifier.example.com/requests/abc123",
                 rp_public,
                 verify_opts(req_options: [plug: text_plug(200, jwt)])
               )

      assert request.nonce == @nonce
    end

    test "surfaces a non-200 status" do
      assert {:error, {:http_status, 404}} =
               PresentationRequest.fetch(
                 "https://verifier.example.com/requests/missing",
                 %{},
                 verify_opts(req_options: [plug: text_plug(404, "not found")])
               )
    end
  end
end
