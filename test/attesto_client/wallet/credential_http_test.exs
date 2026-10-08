defmodule AttestoClient.Wallet.CredentialHTTPTest do
  use ExUnit.Case, async: true

  alias AttestoClient.OAuthHTTP

  @endpoint "https://issuer.example.com/credential"

  test "compact credential requests retain custom headers and retry DPoP nonce once" do
    owner = self()
    count = start_supervised!({Agent, fn -> 0 end})
    key = JOSE.JWK.generate_key({:ec, "P-256"})

    plug = fn conn ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      assert body == "protected..iv.ciphertext.tag"
      assert Plug.Conn.get_req_header(conn, "content-type") == ["application/jwt"]
      assert Plug.Conn.get_req_header(conn, "x-request-id") == ["request"]
      assert Plug.Conn.get_req_header(conn, "authorization") == ["DPoP access-token"]
      [proof] = Plug.Conn.get_req_header(conn, "dpop")
      attempt = Agent.get_and_update(count, &{&1, &1 + 1})
      send(owner, {:attempt, attempt, proof})

      if attempt == 0 do
        conn
        |> Plug.Conn.put_resp_header("dpop-nonce", "server-nonce")
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(401, "{\"error\":\"use_dpop_nonce\"}")
      else
        conn
        |> Plug.Conn.put_resp_content_type("application/jwt")
        |> Plug.Conn.send_resp(202, "encrypted-response")
      end
    end

    assert {:ok, %{status: 202, body: "encrypted-response"}} =
             OAuthHTTP.post_credential(
               @endpoint,
               {:jwt, "protected..iv.ciphertext.tag"},
               "access-token",
               dpop: key,
               req_options: [headers: [{"x-request-id", "request"}], plug: plug]
             )

    assert_receive {:attempt, 0, first}
    assert_receive {:attempt, 1, second}
    first = first |> JOSE.JWS.peek_payload() |> JSON.decode!()
    second = second |> JOSE.JWS.peek_payload() |> JSON.decode!()
    assert second["nonce"] == "server-nonce"
    assert second["htu"] == @endpoint
    assert second["ath"] == Attesto.DPoP.compute_ath("access-token")
    refute first["jti"] == second["jti"]
    refute_receive {:attempt, 2, _}
  end

  test "request URI POST keeps form inputs and raw signed response with no authorization" do
    plug = fn conn ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      assert URI.decode_query(body) == %{"wallet_nonce" => "nonce", "wallet_metadata" => "{}"}
      assert Plug.Conn.get_req_header(conn, "authorization") == []
      assert Plug.Conn.get_req_header(conn, "accept") == ["application/oauth-authz-req+jwt"]
      assert Plug.Conn.get_req_header(conn, "x-request-id") == []

      conn
      |> Plug.Conn.put_resp_content_type("application/oauth-authz-req+jwt")
      |> Plug.Conn.send_resp(200, "header.payload.signature")
    end

    assert {:ok, "header.payload.signature"} =
             OAuthHTTP.post_text_open(
               "https://verifier.example.com/request",
               %{"wallet_nonce" => "nonce", "wallet_metadata" => "{}"},
               req_options: [
                 headers: [{"Accept", "application/json"}, {"x-request-id", "request"}],
                 plug: plug
               ]
             )
  end

  test "both new transports reject unsafe endpoints before requesting" do
    opts = [req_options: [plug: fn _ -> flunk("unexpected request") end]]

    for endpoint <- [
          "http://issuer.example.com",
          "https://user:password@issuer.example.com",
          "https://issuer.example.com/#fragment"
        ] do
      assert {:error, :invalid_endpoint} =
               OAuthHTTP.post_credential(endpoint, {:json, %{}}, "token", opts)

      assert {:error, :invalid_endpoint} = OAuthHTTP.post_text_open(endpoint, %{}, opts)
    end
  end

  test "unencrypted credential responses cannot contain duplicate JSON members" do
    plug = fn conn ->
      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.send_resp(200, "{\"credentials\":[],\"credentials\":[]}")
    end

    assert {:error, :invalid_credential_response} =
             OAuthHTTP.post_credential(@endpoint, {:json, %{}}, "token",
               req_options: [plug: plug]
             )
  end

  test "form expected status rejects other successful statuses without changing default callers" do
    for status <- [200, 201, 202] do
      plug = fn conn ->
        conn
        |> Plug.Conn.put_status(status)
        |> Req.Test.json(%{"request_uri" => "urn:example:request", "expires_in" => 90})
      end

      opts = [client_id: "wallet", req_options: [plug: plug]]

      assert {:ok, %{"request_uri" => "urn:example:request"}} =
               OAuthHTTP.post_form(@endpoint, %{}, opts)

      result = OAuthHTTP.post_form(@endpoint, %{}, Keyword.put(opts, :expected_status, 201))

      if status == 201 do
        assert {:ok, %{"request_uri" => "urn:example:request"}} = result
      else
        assert {:error, {:unexpected_http_status, ^status}} = result
      end
    end
  end

  test "form expected status preserves OAuth errors and rejects invalid options before HTTP" do
    plug = fn conn ->
      conn |> Plug.Conn.put_status(400) |> Req.Test.json(%{"error" => "invalid_request"})
    end

    assert {:error, {:oauth_error, 400, %{"error" => "invalid_request"}}} =
             OAuthHTTP.post_form(@endpoint, %{},
               client_id: "wallet",
               expected_status: 201,
               req_options: [plug: plug]
             )

    for invalid <- [false, "201", 100, 400, 600] do
      assert {:error, :invalid_expected_status} =
               OAuthHTTP.post_form(@endpoint, %{},
                 expected_status: invalid,
                 req_options: [plug: fn _ -> flunk("unexpected request") end]
               )
    end
  end
end
