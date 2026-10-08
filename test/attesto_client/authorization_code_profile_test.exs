defmodule AttestoClient.AuthorizationCodeProfileTest do
  use ExUnit.Case, async: true

  alias AttestoClient.AuthorizationCode
  alias AttestoClient.AuthorizationTransaction.Store.ETS
  alias Plug.Conn.Query

  @issuer "https://issuer.example"
  @reserved ~w(client_id redirect_uri response_type scope state nonce code_challenge code_challenge_method dpop_jkt request_uri request request_uri_method client_secret client_assertion client_assertion_type grant_type)

  defp store, do: {ETS, start_supervised!(ETS, id: make_ref())}

  defp options(extra \\ []) do
    Keyword.merge(
      [
        protocol: :oauth,
        scopes: ["credential"],
        issuer: @issuer,
        client_id: "client",
        redirect_uri: "https://client.example/callback",
        browser_binding: "browser-session",
        metadata: %{
          "issuer" => @issuer,
          "authorization_endpoint" => @issuer <> "/authorize",
          "token_endpoint" => @issuer <> "/token",
          "code_challenge_methods_supported" => ["S256"]
        }
      ],
      extra
    )
  end

  test "HAIP and FAPI require PAR when metadata omits or disables its requirement" do
    owner = self()

    par = fn conn ->
      assert conn.request_path == "/par"
      {:ok, bytes, conn} = Plug.Conn.read_body(conn)
      params = Query.decode(bytes)
      assert params["client_id"] == "client"
      assert is_binary(params["state"])
      assert params["code_challenge_method"] == "S256"
      send(owner, :par_request)

      conn
      |> Plug.Conn.put_status(201)
      |> Req.Test.json(%{"request_uri" => "urn:example:par", "expires_in" => 90})
    end

    for profile <- [:haip, :fapi?], advertised <- [nil, false] do
      metadata = Keyword.fetch!(options(), :metadata)
      metadata = Map.put(metadata, "pushed_authorization_request_endpoint", @issuer <> "/par")

      metadata =
        if is_nil(advertised),
          do: metadata,
          else: Map.put(metadata, "require_pushed_authorization_requests", advertised)

      key = JOSE.JWK.generate_key({:ec, "P-256"})

      opts =
        options([
          {profile, true},
          metadata: metadata,
          req_options: [plug: par],
          client_auth: {:private_key_jwt, key},
          dpop: key
        ])

      assert {:ok, started} = AuthorizationCode.start(store(), opts)
      assert_receive :par_request

      assert Query.decode(URI.parse(started.url).query) == %{
               "client_id" => "client",
               "request_uri" => "urn:example:par"
             }

      assert {:error, :par_required} =
               AuthorizationCode.start(store(), Keyword.put(opts, :par, false))

      assert {:error, :missing_par_endpoint} =
               AuthorizationCode.start(
                 store(),
                 Keyword.put(
                   opts,
                   :metadata,
                   Map.delete(metadata, "pushed_authorization_request_endpoint")
                 )
               )

      refute_receive :par_request
    end
  end

  test "protected authorization and PAR fields reject decoded bracket root aliases" do
    store = store()
    owner = self()

    spy = fn conn ->
      send(owner, :unexpected_par)
      Req.Test.json(conn, %{})
    end

    metadata = Keyword.fetch!(options(), :metadata)
    metadata = Map.put(metadata, "pushed_authorization_request_endpoint", @issuer <> "/par")

    for field <- @reserved, suffix <- ["", "[value]", "[]", "[0]"], par <- [false, true] do
      alias_key = field <> suffix
      decoded = Query.decode(URI.encode_query(%{alias_key => "override"}))
      assert Map.has_key?(decoded, field)

      assert {:error, :invalid_authorization_params} =
               AuthorizationCode.start(
                 store,
                 options(
                   par: par,
                   metadata: metadata,
                   req_options: [plug: spy],
                   authorization_params: %{alias_key => "override"}
                 )
               )
    end

    refute_receive :unexpected_par
  end

  test "a profile cannot disable PAR even before metadata discovery" do
    owner = self()

    spy = fn conn ->
      send(owner, :unexpected_discovery)
      Req.Test.json(conn, %{})
    end

    for profile <- [:haip, :fapi?] do
      opts = options([{profile, true}, par: false, req_options: [plug: spy]])

      assert {:error, :par_required} =
               AuthorizationCode.start(store(), Keyword.delete(opts, :metadata))
    end

    refute_receive :unexpected_discovery
  end

  test "nonprotected scalar extensions remain available" do
    assert {:ok, started} =
             AuthorizationCode.start(
               store(),
               options(authorization_params: %{"login_hint" => "user"})
             )

    assert Query.decode(URI.parse(started.url).query)["login_hint"] == "user"
  end

  test "authorization-code DPoP issuance retains the original local key thumbprint" do
    store = store()
    key = JOSE.JWK.generate_key({:ec, "P-256"})
    {_, public} = JOSE.JWK.to_public_map(key)
    {:ok, jkt} = Attesto.Thumbprint.of_jwk(public)
    assert {:ok, started} = AuthorizationCode.start(store, options(dpop: key))

    spy = fn conn ->
      assert [_proof] = Plug.Conn.get_req_header(conn, "dpop")

      Req.Test.json(conn, %{
        "access_token" => "access",
        "token_type" => "DPoP",
        "dpop_jkt" => "foreign"
      })
    end

    assert {:ok, %{tokens: tokens}} =
             AuthorizationCode.callback(store, %{"state" => started.state, "code" => "code"},
               browser_binding: "browser-session",
               dpop: key,
               req_options: [plug: spy]
             )

    assert Map.get(tokens, :dpop_jkt) == jkt
    assert tokens.extra["dpop_jkt"] == "foreign"
  end
end
