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
