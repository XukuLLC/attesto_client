defmodule AttestoClient.ClientCredentialsTest do
  use ExUnit.Case, async: true

  alias AttestoClient.{Token, TokenSet}

  @issuer "https://issuer.example"

  defp options(plug, extra \\ []) do
    Keyword.merge(
      [
        token_endpoint: @issuer <> "/token",
        issuer: @issuer,
        client_id: "client",
        client_auth: {:client_secret_basic, "secret"},
        req_options: [plug: plug]
      ],
      extra
    )
  end

  defp response(conn, type \\ "Bearer") do
    Req.Test.json(conn, %{
      "access_token" => "opaque",
      "token_type" => type,
      "expires_in" => 60,
      "extension" => %{"kept" => true}
    })
  end

  test "basic authentication preserves extensions and sends scope and resources" do
    plug = fn conn ->
      assert Plug.Conn.get_req_header(conn, "authorization") == [
               "Basic " <> Base.encode64("client:secret")
             ]

      {:ok, body, conn} = Plug.Conn.read_body(conn)
      pairs = Enum.to_list(URI.query_decoder(body))
      assert {"grant_type", "client_credentials"} in pairs
      assert {"scope", "read write"} in pairs

      assert Enum.filter(pairs, &(elem(&1, 0) == "resource")) == [
               {"resource", "https://api.example/a"},
               {"resource", "https://api.example/b"}
             ]

      refute Enum.any?(pairs, &(elem(&1, 0) == "client_secret"))
      response(conn)
    end

    assert {:ok,
            %TokenSet{
              access_token: "opaque",
              resources: ["https://api.example/a", "https://api.example/b"],
              extra: %{"extension" => %{"kept" => true}}
            }} =
             Token.client_credentials(
               options(plug,
                 scopes: ["read", "write", "read"],
                 resource: ["https://api.example/a", "https://api.example/b"]
               )
             )
  end

  test "post and private-key authentication use the existing request path" do
    key = JOSE.JWK.generate_key({:ec, "P-256"})

    for auth <- [{:client_secret_post, "secret"}, {:private_key_jwt, key}] do
      plug = fn conn ->
        {:ok, body, conn} = Plug.Conn.read_body(conn)
        form = URI.decode_query(body)
        assert form["client_id"] == "client"

        case auth do
          {:client_secret_post, _} ->
            assert form["client_secret"] == "secret"

          {:private_key_jwt, _} ->
            assert {true, %JOSE.JWT{fields: claims}, _} =
                     JOSE.JWT.verify_strict(
                       JOSE.JWK.to_public(key),
                       ["ES256"],
                       form["client_assertion"]
                     )

            assert claims["aud"] == @issuer
        end

        response(conn)
      end

      assert {:ok, %TokenSet{}} = Token.client_credentials(options(plug, client_auth: auth))
    end
  end

  test "pins both DPoP type refusals and accepts opaque DPoP tokens with a key" do
    key = JOSE.JWK.generate_key({:ec, "P-256"})
    assert {:error, :missing_dpop_key} = Token.client_credentials(options(&response(&1, "DPoP")))

    assert {:error, :invalid_token_type} =
             Token.client_credentials(options(&response/1, dpop: key))

    assert {:ok, %TokenSet{access_token: "opaque", dpop_jkt: jkt}} =
             Token.client_credentials(options(&response(&1, "DPoP"), dpop: key))

    assert is_binary(jkt)
  end

  test "does not expose an unsolicited nonce or inspect a bearer access token" do
    plug = fn conn ->
      assert Plug.Conn.get_req_header(conn, "dpop") == []
      conn |> Plug.Conn.put_resp_header("dpop-nonce", "unsolicited") |> response()
    end

    assert {:ok, %TokenSet{dpop_jkt: nil, access_token: "opaque", extra: extra}} =
             Token.client_credentials(options(plug))

    refute Map.has_key?(extra, "dpop_nonce")
  end

  test "invalid options and unsafe queries fail before sending" do
    plug = fn _ -> flunk("invalid input reached HTTP") end

    for {extra, reason} <- [
          {[client_auth: :none], :invalid_client_auth},
          {[client_id: nil], :missing_client_id},
          {[scopes: ["two scopes"]], :invalid_scopes},
          {[resource: []], :invalid_target},
          {[token_endpoint: @issuer <> "/token?grant_type=other"], :invalid_endpoint_query}
        ] do
      assert {:error, ^reason} = Token.client_credentials(options(plug, extra))
    end
  end

  test "bounds response size and never retries a server failure" do
    counter = start_supervised!({Agent, fn -> 0 end})

    plug = fn conn ->
      Agent.update(counter, &(&1 + 1))
      conn |> Plug.Conn.put_status(503) |> Req.Test.json(%{"error" => "temporarily_unavailable"})
    end

    assert {:error, {:oauth_error, 503, _}} = Token.client_credentials(options(plug))
    assert Agent.get(counter, & &1) == 1

    assert {:error, :response_too_large} =
             Token.client_credentials(
               options(fn conn ->
                 Req.Test.json(conn, %{
                   "access_token" => String.duplicate("x", 2_000_001),
                   "token_type" => "Bearer"
                 })
               end)
             )
  end
end
