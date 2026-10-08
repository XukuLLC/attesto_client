defmodule AttestoClient.OAuthHTTPReferenceSecurityTest do
  use ExUnit.Case, async: true

  alias AttestoClient.OAuthHTTP

  @endpoint "https://untrusted.example/request?original=1"
  @jwt "header.payload.signature"

  test "unauthenticated GET and POST never send caller credentials or custom headers" do
    for method <- [:json_get, :jwt_get, :jwt_post, :direct_post] do
      plug = fn conn ->
        assert conn.host == "untrusted.example"
        assert conn.query_string == "original=1"
        assert conn.request_path == "/request"

        for header <- [
              "authorization",
              "cookie",
              "x-api-key",
              "x-custom-secret",
              "proxy-authorization",
              "oauth-client-attestation",
              "oauth-client-attestation-pop",
              "dpop"
            ] do
          assert Plug.Conn.get_req_header(conn, header) == []
        end

        {:ok, body, conn} = Plug.Conn.read_body(conn)
        refute String.contains?(body, "private-value")
        assert_request(method, conn, body)
        respond(conn, 200, response_type(method), response_body(method))
      end

      assert {:ok, _result} = invoke(method, hostile_options(plug))
    end
  end

  test "request URI GET and POST require the request-object media type" do
    for method <- [:jwt_get, :jwt_post] do
      for media_type <- [nil, "text/plain", "application/json", "application/jwt"] do
        plug = &respond(&1, 200, media_type, @jwt)

        assert {:error, :invalid_response_content_type} =
                 invoke(method, req_options: [plug: plug])
      end

      plug = &respond(&1, 200, "Application/OAuth-Authz-Req+JWT; charset=UTF-8", @jwt)
      assert {:ok, @jwt} = invoke(method, req_options: [plug: plug])
    end
  end

  test "request URI GET and POST reject successful statuses other than 200" do
    for method <- [:jwt_get, :jwt_post], status <- [201, 202, 204] do
      plug = &respond(&1, status, "application/oauth-authz-req+jwt", @jwt)
      assert {:error, {:http_status, ^status}} = invoke(method, req_options: [plug: plug])
    end
  end

  test "direct_post rejects 201, 202 and 204 even when the body is a JSON object" do
    for status <- [201, 202, 204] do
      plug = &respond(&1, status, "application/json", "{}")

      assert {:error, {:http_status, ^status}} =
               OAuthHTTP.post_form_open(@endpoint, %{}, req_options: [plug: plug])
    end
  end

  test "direct_post requires application/json rather than a JSON-looking body" do
    for media_type <- [
          nil,
          "text/plain",
          "text/html",
          "application/jwt",
          "application/problem+json"
        ] do
      plug = &respond(&1, 200, media_type, "{}")

      assert {:error, :invalid_response_content_type} =
               OAuthHTTP.post_form_open(@endpoint, %{}, req_options: [plug: plug])
    end
  end

  test "direct_post rejects invalid, non-object and recursively duplicate JSON" do
    for body <- [
          "",
          "{",
          "[]",
          "null",
          "true",
          "\"text\"",
          "{\"redirect_uri\":\"https://safe.example\",\"redirect_uri\":\"https://other.example\"}",
          "{\"extension\":{\"value\":1,\"value\":2}}",
          "{\"extension\":[{\"value\":1,\"value\":2}]}"
        ] do
      plug = &respond(&1, 200, "application/json", body)

      assert {:error, :invalid_json} =
               OAuthHTTP.post_form_open(@endpoint, %{}, req_options: [plug: plug])
    end
  end

  test "direct_post accepts a complete JSON object and preserves extension values" do
    body = %{"redirect_uri" => "https://wallet.example/done", "extension" => [%{"value" => 1}]}
    plug = &respond(&1, 200, "Application/JSON; charset=utf-8", JSON.encode!(body))

    assert {:ok, ^body} = OAuthHTTP.post_form_open(@endpoint, %{}, req_options: [plug: plug])
  end

  test "ambiguous Content-Type headers are rejected for both response families" do
    for method <- [:json_get, :jwt_get, :jwt_post, :direct_post] do
      plug = fn conn ->
        conn
        |> Plug.Conn.prepend_resp_headers([
          {"content-type", response_type(method)},
          {"content-type", "text/plain"}
        ])
        |> Plug.Conn.send_resp(200, response_body(method))
      end

      assert {:error, :invalid_response_content_type} =
               invoke(method, req_options: [plug: plug])
    end
  end

  test "credential offers require JSON media type and reject duplicate members" do
    plug = &respond(&1, 200, "application/json", "{\"issuer\":1,\"issuer\":2}")
    assert {:error, :invalid_json} = OAuthHTTP.get_json(@endpoint, req_options: [plug: plug])

    plug = &respond(&1, 200, "text/plain", "{}")

    assert {:error, :invalid_response_content_type} =
             OAuthHTTP.get_json(@endpoint, req_options: [plug: plug])
  end

  test "reference redirects are returned as errors and never followed" do
    parent = self()

    plug = fn conn ->
      send(parent, :reference_request)

      conn
      |> Plug.Conn.put_resp_header("location", "https://other.example")
      |> Plug.Conn.send_resp(302, "")
    end

    for method <- [:json_get, :jwt_get, :jwt_post, :direct_post] do
      assert {:error, {:http_status, 302}} =
               invoke(method, req_options: [plug: plug, redirect: true, retry: true])

      assert_receive :reference_request
      refute_receive :reference_request
    end
  end

  test "malformed or ambiguous nested transport configuration fails before the request" do
    plug = fn _conn -> flunk("request must not run") end

    for options <- [
          [plug: plug, plug: plug],
          [plug: plug, connect_options: %{transport_opts: []}],
          [plug: plug, connect_options: [transport_opts: %{certfile: "private-value"}]],
          [plug: plug, connect_options: [transport_opts: [cacerts: [], cacerts: []]]]
        ] do
      assert {:error, :unsafe_transport_options} =
               OAuthHTTP.get_json(@endpoint, req_options: options)
    end
  end

  defp hostile_options(plug) do
    [
      client_id: "private-value",
      client_auth: {:client_secret_basic, "private-value"},
      headers: [{"x-custom-secret", "private-value"}],
      http_options: [auth: {:bearer, "private-value"}],
      req_options: [
        plug: plug,
        auth: {:bearer, "private-value"},
        cookies: [{"session", "private-value"}],
        headers: [
          {"Cookie", "session=private-value"},
          {"x-api-key", "private-value"},
          {"authorization", "Bearer private-value"},
          {"x-custom-secret", "private-value"},
          {"Accept", "private-value"}
        ],
        req_options: [headers: [{"x-api-key", "private-value"}]],
        connect_options: [
          timeout: 100,
          hostname: "other.example",
          proxy: {:http, "other.example", 8080, []},
          transport_opts: [
            verify: :verify_none,
            certfile: "private-value",
            keyfile: "private-value",
            password: "private-value",
            verify_fun: {fn _, _, _ -> flunk("caller verifier must not run") end, nil}
          ]
        ],
        plugins: [fn _request -> flunk("caller plugin must not run") end],
        adapter: fn _request -> flunk("caller adapter must not run") end,
        finch_request: fn _, _, _, _ -> flunk("caller request callback must not run") end,
        url: "https://other.example",
        params: [private: "private-value"],
        body: "private-value",
        form: %{private: "private-value"},
        json: %{private: "private-value"}
      ]
    ]
  end

  defp invoke(:json_get, opts), do: OAuthHTTP.get_json(@endpoint, opts)
  defp invoke(:jwt_get, opts), do: OAuthHTTP.get_text(@endpoint, opts)

  defp invoke(:jwt_post, opts),
    do: OAuthHTTP.post_text_open(@endpoint, %{"wallet_nonce" => "nonce"}, opts)

  defp invoke(:direct_post, opts),
    do: OAuthHTTP.post_form_open(@endpoint, %{"response" => "encrypted"}, opts)

  defp response_type(method) when method in [:jwt_get, :jwt_post],
    do: "application/oauth-authz-req+jwt"

  defp response_type(_method), do: "application/json"
  defp response_body(method) when method in [:jwt_get, :jwt_post], do: @jwt
  defp response_body(_method), do: "{}"

  defp assert_request(:json_get, conn, ""), do: assert(conn.method == "GET")

  defp assert_request(:jwt_get, conn, "") do
    assert conn.method == "GET"
    assert Plug.Conn.get_req_header(conn, "accept") == ["application/oauth-authz-req+jwt"]
  end

  defp assert_request(method, conn, body) do
    assert conn.method == "POST"

    expected =
      if method == :jwt_post,
        do: %{"wallet_nonce" => "nonce"},
        else: %{"response" => "encrypted"}

    assert URI.decode_query(body) == expected

    if method == :jwt_post do
      assert Plug.Conn.get_req_header(conn, "accept") == ["application/oauth-authz-req+jwt"]
    end
  end

  defp respond(conn, status, nil, body), do: Plug.Conn.send_resp(conn, status, body)

  defp respond(conn, status, media_type, body) do
    conn
    |> Plug.Conn.put_resp_header("content-type", media_type)
    |> Plug.Conn.send_resp(status, body)
  end
end
