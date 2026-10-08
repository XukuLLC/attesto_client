defmodule AttestoClient.AuthorizationCodeOAuthTest do
  use ExUnit.Case, async: true

  alias AttestoClient.AuthorizationCode
  alias AttestoClient.AuthorizationTransaction.Store
  alias AttestoClient.AuthorizationTransaction.Store.ETS

  @issuer "https://as.example"
  @redirect "https://wallet.example/callback"

  defp metadata(extra \\ %{}) do
    Map.merge(
      %{
        "issuer" => @issuer,
        "authorization_endpoint" => @issuer <> "/authorize",
        "token_endpoint" => @issuer <> "/token",
        "code_challenge_methods_supported" => ["S256"]
      },
      extra
    )
  end

  defp opts(extra \\ []) do
    Keyword.merge(
      [
        protocol: :oauth,
        issuer: @issuer,
        client_id: "wallet",
        redirect_uri: @redirect,
        browser_binding: "browser-session",
        metadata: metadata()
      ],
      extra
    )
  end

  defp store, do: {ETS, start_supervised!(ETS, id: make_ref())}

  defp form(conn) do
    {:ok, bytes, conn} = Plug.Conn.read_body(conn)
    {URI.decode_query(bytes), conn}
  end

  test "plain OAuth starts with PKCE and no OIDC requirements or nonce" do
    assert {:ok, started} = AuthorizationCode.start(store(), opts(scopes: ["credential"]))
    params = started.url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
    assert params["scope"] == "credential"
    assert params["code_challenge_method"] == "S256"
    refute Map.has_key?(params, "nonce")
    assert byte_size(params["state"]) >= 43
    assert byte_size(params["code_challenge"]) == 43
  end

  test "plain OAuth callback needs no JWKS or ID Token and cannot change stored protocol" do
    store = store()
    assert {:ok, started} = AuthorizationCode.start(store, opts())

    plug = fn conn ->
      assert conn.request_path == "/token"
      {params, conn} = form(conn)
      assert params["grant_type"] == "authorization_code"
      assert params["client_id"] == "wallet"
      assert params["redirect_uri"] == @redirect
      assert byte_size(params["code_verifier"]) >= 43
      Req.Test.json(conn, %{"access_token" => "access", "token_type" => "Bearer"})
    end

    response = %{"state" => started.state, "code" => "authorization-code"}

    assert {:ok, %{tokens: %{access_token: "access"}, id_token_claims: nil}} =
             AuthorizationCode.callback(store, response,
               browser_binding: "browser-session",
               protocol: :oidc,
               req_options: [plug: plug]
             )

    assert {:error, {:invalid_state, :not_found}} =
             AuthorizationCode.callback(store, response,
               browser_binding: "browser-session",
               req_options: [plug: plug]
             )
  end

  test "PAR sends the full bound request and redirects only with its request URI" do
    target = self()

    plug = fn conn ->
      assert conn.request_path == "/par"
      {params, conn} = form(conn)
      send(target, {:par, params})
      assert params["code_challenge_method"] == "S256"
      assert params["scope"] == "credential"
      refute Map.has_key?(params, "nonce")

      conn
      |> Plug.Conn.put_status(201)
      |> Req.Test.json(%{
        "request_uri" => "urn:ietf:params:oauth:request_uri:opaque",
        "expires_in" => 90
      })
    end

    assert {:ok, started} =
             AuthorizationCode.start(
               store(),
               opts(
                 par: true,
                 scopes: ["credential"],
                 metadata:
                   metadata(%{"pushed_authorization_request_endpoint" => @issuer <> "/par"}),
                 req_options: [plug: plug]
               )
             )

    assert_receive {:par, params}
    assert params["state"] == started.state

    assert started.url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query() == %{
             "client_id" => "wallet",
             "request_uri" => "urn:ietf:params:oauth:request_uri:opaque"
           }
  end

  test "required PAR cannot be downgraded and missing or malformed PAR configuration fails" do
    required =
      metadata(%{
        "require_pushed_authorization_requests" => true,
        "pushed_authorization_request_endpoint" => @issuer <> "/par"
      })

    assert {:error, :par_required} =
             AuthorizationCode.start(store(), opts(par: false, metadata: required))

    assert {:error, :missing_par_endpoint} = AuthorizationCode.start(store(), opts(par: true))

    assert {:error, :invalid_metadata} =
             AuthorizationCode.start(
               store(),
               opts(metadata: metadata(%{"require_pushed_authorization_requests" => "true"}))
             )

    assert {:error, :invalid_par_option} = AuthorizationCode.start(store(), opts(par: :sometimes))

    assert {:error, :invalid_endpoint} =
             AuthorizationCode.start(
               store(),
               opts(
                 par: true,
                 metadata:
                   metadata(%{"pushed_authorization_request_endpoint" => "http://as.example/par"})
               )
             )
  end

  test "a failed PAR removes the inaccessible transaction" do
    store = store()
    target = self()

    plug = fn conn ->
      {params, conn} = form(conn)
      send(target, {:par_state, params["state"]})
      conn |> Plug.Conn.put_status(400) |> Req.Test.json(%{"error" => "invalid_request"})
    end

    assert {:error, _reason} =
             AuthorizationCode.start(
               store,
               opts(
                 par: true,
                 metadata:
                   metadata(%{"pushed_authorization_request_endpoint" => @issuer <> "/par"}),
                 req_options: [plug: plug]
               )
             )

    assert_receive {:par_state, state}
    assert {:error, :not_found} = Store.take(store, state)
  end

  test "PAR requires HTTP 201 and its request lifetime caps the redirect lifetime" do
    par_metadata = metadata(%{"pushed_authorization_request_endpoint" => @issuer <> "/par"})

    for status <- [200, 202] do
      plug = fn conn ->
        conn
        |> Plug.Conn.put_status(status)
        |> Req.Test.json(%{"request_uri" => "urn:example:request", "expires_in" => 1})
      end

      assert {:error, _reason} =
               AuthorizationCode.start(
                 store(),
                 opts(par: true, metadata: par_metadata, req_options: [plug: plug])
               )
    end

    plug = fn conn ->
      conn
      |> Plug.Conn.put_status(201)
      |> Req.Test.json(%{"request_uri" => "urn:example:request", "expires_in" => 1})
    end

    assert {:ok, %{expires_in: 1}} =
             AuthorizationCode.start(
               store(),
               opts(par: true, metadata: par_metadata, req_options: [plug: plug])
             )
  end

  test "PAR cannot return a redirect after the transaction lifetime expires" do
    store = store()
    target = self()

    plug = fn conn ->
      {params, conn} = form(conn)
      send(target, {:expiring_par_state, params["state"]})
      Process.sleep(100)

      conn
      |> Plug.Conn.put_status(201)
      |> Req.Test.json(%{"request_uri" => "urn:example:request", "expires_in" => 90})
    end

    assert {:error, :authorization_transaction_expired} =
             AuthorizationCode.start(
               store,
               opts(
                 par: true,
                 transaction_ttl_ms: 50,
                 metadata:
                   metadata(%{"pushed_authorization_request_endpoint" => @issuer <> "/par"}),
                 req_options: [plug: plug]
               )
             )

    assert_receive {:expiring_par_state, state}
    assert {:error, :not_found} = Store.take(store, state)
  end

  test "DPoP key is bound at start and a bearer token response is rejected" do
    key = JOSE.JWK.generate_key({:ec, "P-256"})
    other = JOSE.JWK.generate_key({:ec, "P-256"})
    store = store()
    assert {:ok, first} = AuthorizationCode.start(store, opts(dpop: key))

    assert {:error, :dpop_key_mismatch} =
             AuthorizationCode.callback(store, %{"state" => first.state, "code" => "code"},
               browser_binding: "browser-session",
               dpop: other
             )

    assert {:ok, second} = AuthorizationCode.start(store, opts(dpop: key))

    plug = fn conn ->
      assert [_proof] = Plug.Conn.get_req_header(conn, "dpop")
      Req.Test.json(conn, %{"access_token" => "access", "token_type" => "Bearer"})
    end

    assert {:error, :invalid_token_type} =
             AuthorizationCode.callback(store, %{"state" => second.state, "code" => "code"},
               browser_binding: "browser-session",
               dpop: key,
               req_options: [plug: plug]
             )
  end

  test "advertised response issuer protection remains active for plain OAuth" do
    store = store()

    assert {:ok, started} =
             AuthorizationCode.start(
               store,
               opts(
                 metadata: metadata(%{"authorization_response_iss_parameter_supported" => true})
               )
             )

    assert {:error, :missing_response_issuer} =
             AuthorizationCode.callback(store, %{"state" => started.state, "code" => "code"},
               browser_binding: "browser-session"
             )
  end

  for profile <- [:haip, :fapi?], advertised <- [nil, false] do
    test "#{profile} pins response issuer protection with metadata flag #{inspect(advertised)}" do
      store = store()
      owner = self()

      protected_metadata =
        if is_nil(unquote(advertised)),
          do: metadata(),
          else:
            metadata(%{"authorization_response_iss_parameter_supported" => unquote(advertised)})

      protected_metadata =
        Map.put(protected_metadata, "pushed_authorization_request_endpoint", @issuer <> "/par")

      par = fn conn ->
        assert conn.request_path == "/par"

        conn
        |> Plug.Conn.put_status(201)
        |> Req.Test.json(%{"request_uri" => "urn:example:profile-par", "expires_in" => 90})
      end

      protected_opts =
        opts(
          [{unquote(profile), true}] ++
            [
              scopes: ["credential"],
              metadata: protected_metadata,
              req_options: [plug: par],
              client_auth: {:private_key_jwt, JOSE.JWK.generate_key({:ec, "P-256"})},
              dpop: JOSE.JWK.generate_key({:ec, "P-256"})
            ]
        )

      plug = fn conn ->
        send(owner, :token_exchange)
        Req.Test.json(conn, %{"access_token" => "access", "token_type" => "DPoP"})
      end

      callback_opts = [
        browser_binding: "browser-session",
        req_options: [plug: plug],
        client_auth: protected_opts[:client_auth],
        dpop: protected_opts[:dpop],
        haip: false,
        fapi?: false
      ]

      assert {:ok, missing} = AuthorizationCode.start(store, protected_opts)

      assert {:error, :missing_response_issuer} =
               AuthorizationCode.callback(
                 store,
                 %{"state" => missing.state, "code" => "code"},
                 callback_opts
               )

      assert {:error, {:invalid_state, :not_found}} =
               AuthorizationCode.callback(
                 store,
                 %{"state" => missing.state, "code" => "code", "iss" => @issuer},
                 callback_opts
               )

      assert {:ok, mismatched} = AuthorizationCode.start(store, protected_opts)

      assert {:error, :issuer_mismatch} =
               AuthorizationCode.callback(
                 store,
                 %{
                   "state" => mismatched.state,
                   "code" => "code",
                   "iss" => "https://other.example"
                 },
                 callback_opts
               )

      refute_receive :token_exchange
      assert {:ok, valid} = AuthorizationCode.start(store, protected_opts)

      assert {:ok, %{id_token_claims: nil}} =
               AuthorizationCode.callback(
                 store,
                 %{"state" => valid.state, "code" => "code", "iss" => @issuer},
                 callback_opts
               )

      assert_receive :token_exchange
    end
  end

  test "invalid issuer-protection options fail before starting authorization" do
    assert {:error, :invalid_haip} = AuthorizationCode.start(store(), opts(haip: "true"))
    assert {:error, :invalid_fapi} = AuthorizationCode.start(store(), opts(fapi?: :yes))
  end

  test "legacy generic transactions without the optional issuer policy remain compatible" do
    store = store()
    assert {:ok, started} = AuthorizationCode.start(store, opts())
    assert {:ok, transaction} = Store.take(store, started.state)

    assert :ok =
             Store.put_new(
               store,
               started.state,
               Map.delete(transaction, :require_response_issuer),
               10_000
             )

    plug = fn conn ->
      Req.Test.json(conn, %{"access_token" => "access", "token_type" => "Bearer"})
    end

    assert {:ok, %{id_token_claims: nil}} =
             AuthorizationCode.callback(store, %{"state" => started.state, "code" => "code"},
               browser_binding: "browser-session",
               req_options: [plug: plug]
             )
  end

  test "PAR and token exchange use the supplied proactive DPoP nonce" do
    key = JOSE.JWK.generate_key({:ec, "P-256"})
    store = store()

    plug = fn conn ->
      assert [proof] = Plug.Conn.get_req_header(conn, "dpop")
      assert {:ok, claims} = Attesto.JWS.peek_json(proof, :payload)

      case conn.request_path do
        "/par" ->
          assert claims["nonce"] == "par-nonce"

          conn
          |> Plug.Conn.put_status(201)
          |> Req.Test.json(%{"request_uri" => "urn:example:request", "expires_in" => 90})

        "/token" ->
          assert claims["nonce"] == "token-nonce"
          Req.Test.json(conn, %{"access_token" => "access", "token_type" => "DPoP"})
      end
    end

    assert {:ok, started} =
             AuthorizationCode.start(
               store,
               opts(
                 par: true,
                 metadata:
                   metadata(%{"pushed_authorization_request_endpoint" => @issuer <> "/par"}),
                 dpop: key,
                 dpop_nonce: "par-nonce",
                 req_options: [plug: plug]
               )
             )

    assert {:ok, %{id_token_claims: nil}} =
             AuthorizationCode.callback(store, %{"state" => started.state, "code" => "code"},
               browser_binding: "browser-session",
               dpop: key,
               dpop_nonce: "token-nonce",
               req_options: [plug: plug]
             )
  end

  test "raw callbacks may contain an issuer URL without being mistaken for a full URI" do
    store = store()

    assert {:ok, started} =
             AuthorizationCode.start(
               store,
               opts(
                 metadata: metadata(%{"authorization_response_iss_parameter_supported" => true})
               )
             )

    plug = fn conn ->
      Req.Test.json(conn, %{"access_token" => "access", "token_type" => "Bearer"})
    end

    response = "state=#{started.state}&code=code&iss=#{@issuer}"

    assert {:ok, %{id_token_claims: nil}} =
             AuthorizationCode.callback(store, response,
               browser_binding: "browser-session",
               req_options: [plug: plug]
             )
  end

  test "plain OAuth still validates issuer, endpoints, PKCE and reserved parameters" do
    assert {:error, :invalid_metadata} =
             AuthorizationCode.start(
               store(),
               opts(metadata: metadata(%{"code_challenge_methods_supported" => ["plain"]}))
             )

    assert {:error, :issuer_mismatch} =
             AuthorizationCode.start(
               store(),
               opts(metadata: metadata(%{"issuer" => "https://other.example"}))
             )

    assert {:error, :invalid_authorization_params} =
             AuthorizationCode.start(
               store(),
               opts(authorization_params: %{"dpop_jkt" => "injected"})
             )

    assert {:error, :invalid_protocol} =
             AuthorizationCode.start(store(), opts(protocol: :unknown))
  end
end
