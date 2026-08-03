defmodule AttestoClient.OAuthHTTPTest do
  use ExUnit.Case, async: true

  alias AttestoClient.OAuthHTTP

  @endpoint "https://op.example.com/token"

  defp call(client_auth, parent) do
    plug = fn conn ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)

      send(
        parent,
        {:request, Plug.Conn.get_req_header(conn, "authorization"), URI.decode_query(body)}
      )

      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.send_resp(200, JSON.encode!(%{"ok" => true}))
    end

    OAuthHTTP.post_form(@endpoint, %{"grant_type" => "authorization_code"},
      client_id: "client id:one",
      client_auth: client_auth,
      req_options: [plug: plug]
    )
  end

  test "supports public and client_secret_post authentication" do
    assert {:ok, %{"ok" => true}} = call(:none, self())
    assert_receive {:request, [], %{"client_id" => "client id:one"}}

    assert {:ok, %{"ok" => true}} = call({:client_secret_post, "s:e c"}, self())

    assert_receive {:request, [], form}
    assert form["client_id"] == "client id:one"
    assert form["client_secret"] == "s:e c"
  end

  test "form-encodes client_secret_basic credentials before base64" do
    assert {:ok, _response} = call({:client_secret_basic, "s:e c"}, self())
    assert_receive {:request, ["Basic " <> encoded], form}
    assert Base.decode64!(encoded) == "client+id%3Aone:s%3Ae+c"
    refute Map.has_key?(form, "client_id")
    refute Map.has_key?(form, "client_secret")
  end

  test "supports private_key_jwt defaults and registered assertion overrides" do
    key = JOSE.JWK.generate_key({:rsa, 2048})

    assert {:ok, _response} =
             call(
               {:private_key_jwt, key,
                [
                  audience: "https://op.example.com/custom-audience",
                  alg: "RS256",
                  kid: "registered-key",
                  now: 1_700_000_000,
                  jti: "assertion-jti"
                ]},
               self()
             )

    assert_receive {:request, [], form}
    assert form["client_id"] == "client id:one"
    assert form["client_assertion_type"] == AttestoClient.ClientAssertion.assertion_type()

    [header, claims, _signature] = String.split(form["client_assertion"], ".")
    assert %{"alg" => "RS256", "kid" => "registered-key"} = decode_segment(header)

    assert %{
             "iss" => "client id:one",
             "sub" => "client id:one",
             "aud" => "https://op.example.com/custom-audience",
             "jti" => "assertion-jti"
           } = decode_segment(claims)

    assert {:error, :invalid_client_assertion_options} =
             call({:private_key_jwt, key, [algg: "RS256"]}, self())

    assert {:error, :invalid_client_assertion_options} =
             call({:private_key_jwt, key, [alg: "RS256", alg: "PS256"]}, self())
  end

  defp decode_segment(segment) do
    {:ok, json} = Base.url_decode64(segment, padding: false)
    JSON.decode!(json)
  end

  describe "post_json/4" do
    test "authenticates with a bearer token and returns the decoded JSON body" do
      parent = self()

      plug = fn conn ->
        {:ok, body, conn} = Plug.Conn.read_body(conn)

        send(
          parent,
          {:request, Plug.Conn.get_req_header(conn, "authorization"), JSON.decode!(body)}
        )

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(200, JSON.encode!(%{"ok" => true}))
      end

      assert {:ok, %{"ok" => true}} =
               OAuthHTTP.post_json(
                 "https://issuer.example.com/credential",
                 %{"a" => 1},
                 "access-token",
                 req_options: [plug: plug]
               )

      assert_receive {:request, ["Bearer access-token"], %{"a" => 1}}
    end

    test "surfaces an OAuth-shaped error body, including a retry c_nonce" do
      plug = fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(
          400,
          JSON.encode!(%{"error" => "invalid_proof", "c_nonce" => "fresh-nonce"})
        )
      end

      assert {:error,
              {:oauth_error, 400, %{"error" => "invalid_proof", "c_nonce" => "fresh-nonce"}}} =
               OAuthHTTP.post_json("https://issuer.example.com/credential", %{}, "access-token",
                 req_options: [plug: plug]
               )
    end

    test "rejects a non-https endpoint before making the request" do
      assert {:error, :invalid_endpoint} =
               OAuthHTTP.post_json("http://issuer.example.com/credential", %{}, "at", [])
    end
  end

  describe "DPoP sender-constraining" do
    defp dpop_claims(proof), do: proof |> JOSE.JWS.peek_payload() |> JSON.decode!()
    defp dpop_header(proof), do: proof |> JOSE.JWS.peek_protected() |> JSON.decode!()

    defp echo_dpop_plug(parent, status \\ 200) do
      fn conn ->
        [proof] = Plug.Conn.get_req_header(conn, "dpop")
        send(parent, {:dpop, proof})

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(status, JSON.encode!(%{"ok" => true}))
      end
    end

    test "post_json binds the proof to the method, uri, and access token (ath)" do
      parent = self()
      key = JOSE.JWK.generate_key({:ec, "P-256"})

      assert {:ok, %{"ok" => true}} =
               OAuthHTTP.post_json(
                 "https://issuer.example.com/credential",
                 %{},
                 "access-token",
                 dpop: key,
                 req_options: [plug: echo_dpop_plug(parent)]
               )

      assert_receive {:dpop, proof}
      assert dpop_header(proof)["typ"] == "dpop+jwt"
      claims = dpop_claims(proof)
      assert claims["htm"] == "POST"
      assert claims["htu"] == "https://issuer.example.com/credential"
      assert claims["ath"] == Attesto.DPoP.compute_ath("access-token")
    end

    test "post_form attaches a proof with no ath (no access token at the token endpoint)" do
      parent = self()
      key = JOSE.JWK.generate_key({:ec, "P-256"})

      assert {:ok, %{"ok" => true}} =
               OAuthHTTP.post_form(
                 "https://op.example.com/token",
                 %{"grant_type" => "authorization_code"},
                 client_id: "c",
                 dpop: key,
                 req_options: [plug: echo_dpop_plug(parent)]
               )

      assert_receive {:dpop, proof}
      claims = dpop_claims(proof)
      assert claims["htm"] == "POST"
      assert claims["htu"] == "https://op.example.com/token"
      refute Map.has_key?(claims, "ath")
    end

    test "retries a use_dpop_nonce challenge once, echoing the server DPoP-Nonce" do
      parent = self()
      key = JOSE.JWK.generate_key({:ec, "P-256"})
      {:ok, counter} = Agent.start_link(fn -> 0 end)

      plug = fn conn ->
        n = Agent.get_and_update(counter, fn c -> {c, c + 1} end)
        [proof] = Plug.Conn.get_req_header(conn, "dpop")
        send(parent, {:attempt, n, proof})

        if n == 0 do
          conn
          |> Plug.Conn.put_resp_header("dpop-nonce", "server-nonce-xyz")
          |> Plug.Conn.put_resp_content_type("application/json")
          |> Plug.Conn.send_resp(400, JSON.encode!(%{"error" => "use_dpop_nonce"}))
        else
          conn
          |> Plug.Conn.put_resp_content_type("application/json")
          |> Plug.Conn.send_resp(200, JSON.encode!(%{"ok" => true}))
        end
      end

      assert {:ok, %{"ok" => true}} =
               OAuthHTTP.post_form(
                 "https://op.example.com/token",
                 %{"grant_type" => "authorization_code"},
                 client_id: "c",
                 dpop: key,
                 req_options: [plug: plug]
               )

      assert_receive {:attempt, 0, first}
      assert_receive {:attempt, 1, second}
      refute_receive {:attempt, 2, _}

      refute Map.has_key?(dpop_claims(first), "nonce")
      assert dpop_claims(second)["nonce"] == "server-nonce-xyz"
      # Each attempt carries a distinct proof (a fresh jti), never a replay.
      refute dpop_claims(first)["jti"] == dpop_claims(second)["jti"]

      Agent.stop(counter)
    end

    test "surfaces the error and stops after one retry when the challenge repeats" do
      parent = self()
      key = JOSE.JWK.generate_key({:ec, "P-256"})

      plug = fn conn ->
        send(parent, :attempt)

        conn
        |> Plug.Conn.put_resp_header("dpop-nonce", "server-nonce-xyz")
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(400, JSON.encode!(%{"error" => "use_dpop_nonce"}))
      end

      assert {:error, {:oauth_error, 400, %{"error" => "use_dpop_nonce"}}} =
               OAuthHTTP.post_json(
                 "https://issuer.example.com/credential",
                 %{},
                 "access-token",
                 dpop: key,
                 req_options: [plug: plug]
               )

      # Exactly two attempts: the original and one nonce retry.
      assert_receive :attempt
      assert_receive :attempt
      refute_receive :attempt
    end
  end

  describe "client_attestation client authentication" do
    setup do
      provider = JOSE.JWK.generate_key({:ec, "P-256"})
      instance = JOSE.JWK.generate_key({:ec, "P-256"})
      client_id = "wallet-instance-1"
      audience = "https://op.example.com"

      {:ok, attestation} =
        AttestoClient.WalletAttestation.attestation(provider,
          client_id: client_id,
          instance_key: instance
        )

      %{
        provider: provider,
        instance: instance,
        client_id: client_id,
        audience: audience,
        attestation: attestation
      }
    end

    defp capture_headers_plug(parent) do
      fn conn ->
        send(
          parent,
          {:headers,
           %{
             "oauth-client-attestation" => Plug.Conn.get_req_header(conn, "oauth-client-attestation"),
             "oauth-client-attestation-pop" =>
               Plug.Conn.get_req_header(conn, "oauth-client-attestation-pop"),
             "dpop" => Plug.Conn.get_req_header(conn, "dpop")
           }}
        )

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(200, JSON.encode!(%{"ok" => true}))
      end
    end

    test "sets both attestation headers and a PoP that verifies against the attestation", ctx do
      assert {:ok, %{"ok" => true}} =
               OAuthHTTP.post_form(
                 "https://op.example.com/token",
                 %{"grant_type" => "authorization_code"},
                 client_id: ctx.client_id,
                 client_auth:
                   {:client_attestation, ctx.attestation, ctx.instance, audience: ctx.audience},
                 req_options: [plug: capture_headers_plug(self())]
               )

      assert_receive {:headers, headers}
      assert [ctx.attestation] == headers["oauth-client-attestation"]
      assert [pop] = headers["oauth-client-attestation-pop"]

      {_, provider_public} = JOSE.JWK.to_public_map(ctx.provider)

      assert {:ok, %{instance_key: %{jwk: jwk}}} =
               Attesto.WalletAttestation.verify(ctx.attestation, pop,
                 trusted_wallet_provider_jwks: provider_public,
                 audience: ctx.audience,
                 client_id: ctx.client_id
               )

      {_, instance_public} = JOSE.JWK.to_public_map(ctx.instance)
      assert jwk == instance_public
    end

    test "composes with DPoP - both attestation headers and a DPoP proof are present", ctx do
      dpop_key = JOSE.JWK.generate_key({:ec, "P-256"})

      assert {:ok, %{"ok" => true}} =
               OAuthHTTP.post_form(
                 "https://op.example.com/token",
                 %{"grant_type" => "authorization_code"},
                 client_id: ctx.client_id,
                 client_auth:
                   {:client_attestation, ctx.attestation, ctx.instance, audience: ctx.audience},
                 dpop: dpop_key,
                 req_options: [plug: capture_headers_plug(self())]
               )

      assert_receive {:headers, headers}
      assert [ctx.attestation] == headers["oauth-client-attestation"]
      assert [_pop] = headers["oauth-client-attestation-pop"]
      assert [proof] = headers["dpop"]
      assert (proof |> JOSE.JWS.peek_protected() |> JSON.decode!())["typ"] == "dpop+jwt"
    end
  end

  describe "get_json/2" do
    test "returns the decoded JSON body" do
      plug = fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(
          200,
          JSON.encode!(%{"credential_issuer" => "https://issuer.example.com"})
        )
      end

      assert {:ok, %{"credential_issuer" => "https://issuer.example.com"}} =
               OAuthHTTP.get_json("https://issuer.example.com/offers/1",
                 req_options: [plug: plug]
               )
    end

    test "surfaces a non-200 status" do
      plug = fn conn -> Plug.Conn.send_resp(conn, 404, "") end

      assert {:error, {:http_status, 404}} =
               OAuthHTTP.get_json("https://issuer.example.com/offers/missing",
                 req_options: [plug: plug]
               )
    end
  end

  describe "get_text/2" do
    test "returns the raw response body" do
      plug = fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/oauth-authz-req+jwt")
        |> Plug.Conn.send_resp(200, "header.payload.signature")
      end

      assert {:ok, "header.payload.signature"} =
               OAuthHTTP.get_text("https://verifier.example.com/requests/1",
                 req_options: [plug: plug]
               )
    end

    test "surfaces a non-200 status" do
      plug = fn conn -> Plug.Conn.send_resp(conn, 404, "") end

      assert {:error, {:http_status, 404}} =
               OAuthHTTP.get_text("https://verifier.example.com/requests/missing",
                 req_options: [plug: plug]
               )
    end
  end

  describe "post_form_open/3" do
    test "POSTs unauthenticated and returns the decoded JSON body" do
      parent = self()

      plug = fn conn ->
        {:ok, body, conn} = Plug.Conn.read_body(conn)
        send(parent, {:request, URI.decode_query(body)})

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(
          200,
          JSON.encode!(%{"redirect_uri" => "https://wallet.example.com/done"})
        )
      end

      assert {:ok, %{"redirect_uri" => "https://wallet.example.com/done"}} =
               OAuthHTTP.post_form_open(
                 "https://verifier.example.com/response",
                 %{"vp_token" => "{}", "state" => "state-1"},
                 req_options: [plug: plug]
               )

      assert_receive {:request, %{"vp_token" => "{}", "state" => "state-1"}}
    end

    test "treats a non-JSON success body as an empty map" do
      plug = fn conn -> Plug.Conn.send_resp(conn, 200, "") end

      assert {:ok, %{}} =
               OAuthHTTP.post_form_open("https://verifier.example.com/response", %{},
                 req_options: [plug: plug]
               )
    end

    test "surfaces an oauth-shaped error body and a bare non-2xx status" do
      error_plug = fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(400, JSON.encode!(%{"error" => "invalid_request"}))
      end

      assert {:error, {:oauth_error, 400, %{"error" => "invalid_request"}}} =
               OAuthHTTP.post_form_open("https://verifier.example.com/response", %{},
                 req_options: [plug: error_plug]
               )

      plain_plug = fn conn -> Plug.Conn.send_resp(conn, 500, "") end

      assert {:error, {:http_status, 500}} =
               OAuthHTTP.post_form_open("https://verifier.example.com/response", %{},
                 req_options: [plug: plain_plug]
               )
    end
  end
end
