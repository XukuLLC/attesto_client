defmodule AttestoClient.OutboundTest do
  use ExUnit.Case, async: true

  alias AttestoClient.AuthorizationCode
  alias AttestoClient.AuthorizationTransaction.Store.ETS
  alias AttestoClient.Discovery
  alias AttestoClient.IDToken
  alias AttestoClient.Issuer
  alias AttestoClient.Logout
  alias AttestoClient.Outbound
  alias AttestoClient.Token
  alias AttestoClient.TokenSet

  @private_issuer "https://idp.internal.example"
  @loopback_issuer "http://localhost:4000"
  @redirect "https://rp.example/callback"

  # Answers every name with one private address, as split-horizon DNS would.
  defp resolver(ips) do
    fn _host, family -> answers(Enum.filter(ips, &(tuple_size(&1) == address_size(family)))) end
  end

  defp address_size(:inet), do: 4
  defp address_size(:inet6), do: 8

  defp answers([]), do: {:error, :nxdomain}
  defp answers(ips), do: {:ok, ips}

  defp metadata(issuer, extra \\ %{}) do
    Map.merge(
      %{
        "issuer" => issuer,
        "authorization_endpoint" => issuer <> "/authorize",
        "token_endpoint" => issuer <> "/token",
        "end_session_endpoint" => issuer <> "/logout",
        "code_challenge_methods_supported" => ["S256"]
      },
      extra
    )
  end

  defp oauth_opts(issuer, extra) do
    Keyword.merge(
      [
        protocol: :oauth,
        issuer: issuer,
        client_id: "client",
        redirect_uri: @redirect,
        browser_binding: "browser-session",
        metadata: metadata(issuer)
      ],
      extra
    )
  end

  defp store, do: {ETS, start_supervised!(ETS, id: make_ref())}

  defp token_plug do
    fn conn ->
      Req.Test.json(conn, %{"access_token" => "access", "token_type" => "Bearer"})
    end
  end

  describe "validate/1" do
    test "accepts an absent option and well-formed exceptions" do
      assert :ok = Outbound.validate([])
      assert :ok = Outbound.validate(outbound: nil)
      assert :ok = Outbound.validate(outbound: [])

      assert :ok =
               Outbound.validate(outbound: [allowed_cidrs: ["10.20.0.0/16", "fd12:3456::/32"]])

      assert :ok = Outbound.validate(outbound: [allow_loopback_http: true, allowed_cidrs: []])
    end

    test "refuses anything else, including a catch-all block and a host name" do
      for invalid <- [
            true,
            %{allowed_cidrs: []},
            [allowed_hosts: ["idp.internal.example"]],
            [allowed_cidrs: "10.20.0.0/16"],
            [allowed_cidrs: ["idp.internal.example"]],
            [allowed_cidrs: ["10.20.0.1/16"]],
            [allowed_cidrs: ["0.0.0.0/0"]],
            [allowed_cidrs: ["::/0"]],
            [allow_loopback_http: :yes],
            [allow_loopback_http: true, allow_loopback_http: false]
          ] do
        assert {:error, :invalid_outbound} = Outbound.validate(outbound: invalid),
               "expected #{inspect(invalid)} to be refused"
      end
    end
  end

  describe "allowed_cidrs at the screen" do
    test "a private answer is refused without the option and pinned with it" do
      opts = [resolver: resolver([{10, 20, 0, 5}])]
      url = @private_issuer <> "/token"

      assert {:error, :blocked_host} = Discovery.validate_endpoint(url, opts)
      assert {:error, :blocked_host} = Discovery.screen_endpoint(url, opts)

      allowed = Keyword.put(opts, :outbound, allowed_cidrs: ["10.20.0.0/16"])
      assert :ok = Discovery.validate_endpoint(url, allowed)

      assert {:ok, %{url: "https://10.20.0.5/token", host: "idp.internal.example"}} =
               Discovery.screen_endpoint(url, allowed)
    end

    test "an address outside every listed block stays refused" do
      outbound = [allowed_cidrs: ["10.20.0.0/16"]]

      for ips <- [
            [{10, 30, 0, 5}],
            [{192, 168, 1, 1}],
            [{169, 254, 169, 254}],
            [{127, 0, 0, 1}],
            # One listed and one unlisted answer: the whole set is refused.
            [{10, 20, 0, 5}, {10, 30, 0, 5}],
            [{0xFD00, 0, 0, 0, 0, 0, 0, 1}]
          ] do
        assert {:error, :blocked_host} =
                 Discovery.validate_endpoint(@private_issuer <> "/token",
                   resolver: resolver(ips),
                   outbound: outbound
                 )
      end
    end

    test "a public answer still passes, and a listed block never admits plain http" do
      outbound = [allowed_cidrs: ["10.20.0.0/16"]]

      assert :ok =
               Discovery.validate_endpoint("https://idp.example/token",
                 resolver: resolver([{93, 184, 216, 34}]),
                 outbound: outbound
               )

      assert {:error, :invalid_endpoint} =
               Discovery.validate_endpoint("http://idp.internal.example/token",
                 resolver: resolver([{10, 20, 0, 5}]),
                 outbound: outbound
               )
    end

    test "a malformed option is reported, not ignored" do
      assert {:error, :invalid_outbound} =
               Discovery.validate_endpoint(@private_issuer <> "/token",
                 outbound: [allowed_cidrs: ["0.0.0.0/0"]]
               )

      assert {:error, :invalid_outbound} =
               Discovery.fetch(@private_issuer,
                 outbound: [allowed_hosts: ["idp.internal.example"]]
               )

      assert {:error, :invalid_outbound} =
               Discovery.fetch_jwks(@private_issuer <> "/jwks", outbound: :any)
    end

    test "discovery, JWKS and the token request all reach a listed private address" do
      opts = [
        resolver: resolver([{10, 20, 0, 5}]),
        outbound: [allowed_cidrs: ["10.20.0.0/16"]],
        timeout: 500,
        req_options: [retry: false, connect_options: [timeout: 100]]
      ]

      # Nothing listens there, so each call gets past the screen and then
      # fails at the socket or runs into the deadline, depending on how the
      # network treats the address. Either way the screen let it through;
      # without the option the same calls stop at the screen.
      past_screen = fn result ->
        assert {:error, reason} = result
        refute reason in [:blocked_host, :invalid_endpoint, :invalid_outbound]
      end

      past_screen.(Discovery.fetch(@private_issuer, opts))
      past_screen.(Discovery.fetch_jwks(@private_issuer <> "/jwks", opts))

      blocked = Keyword.delete(opts, :outbound)
      assert {:error, :blocked_host} = Discovery.fetch(@private_issuer, blocked)
      assert {:error, :blocked_host} = Discovery.fetch_jwks(@private_issuer <> "/jwks", blocked)

      exchange = [
        token_endpoint: @private_issuer <> "/token",
        issuer: @private_issuer,
        client_id: "client",
        redirect_uri: @redirect,
        code_verifier: String.duplicate("v", 43)
      ]

      assert {:error, :blocked_host} = AuthorizationCode.exchange("code", exchange ++ blocked)

      assert {:error, reason} = AuthorizationCode.exchange("code", exchange ++ opts)
      refute reason in [:blocked_host, :invalid_endpoint, :invalid_outbound]
    end
  end

  describe "allow_loopback_http" do
    @loopback [outbound: [allow_loopback_http: true]]

    test "http is accepted for localhost and literal loopback addresses only" do
      local = resolver([{127, 0, 0, 1}])

      for url <- ["http://localhost:4000/token", "http://127.0.0.1:4000/token"] do
        assert {:error, :invalid_endpoint} = Discovery.validate_endpoint(url, resolver: local)
        assert :ok = Discovery.validate_endpoint(url, [resolver: local] ++ @loopback)
        assert :ok = Discovery.validate_browser_endpoint(url, @loopback)
        assert {:error, :invalid_endpoint} = Discovery.validate_browser_endpoint(url)
      end

      assert :ok = Discovery.validate_endpoint("http://[::1]:4000/token", @loopback)
    end

    test "every other http host stays refused with the option on" do
      for url <- [
            "http://idp.example/token",
            "http://10.20.0.5/token",
            "http://localhost.example/token",
            "http://127.0.0.1.example/token"
          ] do
        assert {:error, :invalid_endpoint} =
                 Discovery.validate_endpoint(
                   url,
                   [resolver: resolver([{127, 0, 0, 1}])] ++ @loopback
                 )

        assert {:error, :invalid_endpoint} = Discovery.validate_browser_endpoint(url, @loopback)
      end
    end

    test "a name that only resolves to loopback is not a loopback host" do
      # The exception is passed to the screen only for an http loopback URL, so
      # an https name answering 127.0.0.1 is refused as it always was.
      assert {:error, :blocked_host} =
               Discovery.validate_endpoint(
                 "https://idp.example/token",
                 [resolver: resolver([{127, 0, 0, 1}])] ++ @loopback
               )

      assert {:error, :blocked_host} =
               Discovery.validate_endpoint("https://127.0.0.1/token", @loopback)
    end

    test "the option is refused with an issuer that is not a loopback host" do
      plug = fn conn -> Req.Test.json(conn, metadata("https://idp.example")) end

      assert {:error, :invalid_outbound} =
               Discovery.fetch("https://idp.example", [req_options: [plug: plug]] ++ @loopback)

      assert {:error, :invalid_outbound} =
               Discovery.validate_metadata(
                 metadata("https://idp.example"),
                 "https://idp.example",
                 [protocol: :oauth] ++ @loopback
               )

      assert {:error, :invalid_outbound} =
               AuthorizationCode.start(store(), oauth_opts("https://idp.example", @loopback))

      assert {:error, :invalid_outbound} =
               Logout.url(
                 [issuer: "https://idp.example", metadata: metadata("https://idp.example")] ++
                   @loopback
               )

      assert {:error, :invalid_outbound} =
               IDToken.verify(
                 "a.b.c",
                 [issuer: "https://idp.example", client_id: "client"] ++ @loopback
               )

      assert_raise ArgumentError, ~r/allow_loopback_http requires a loopback :issuer/, fn ->
        Issuer.config!([issuer: "https://idp.example"] ++ @loopback, "Issuer")
      end
    end

    test "discovery and metadata validation accept a loopback issuer and its endpoints" do
      document = metadata(@loopback_issuer, %{"jwks_uri" => @loopback_issuer <> "/jwks"})
      plug = fn conn -> Req.Test.json(conn, document) end

      assert {:error, :invalid_issuer} =
               Discovery.fetch(@loopback_issuer, req_options: [plug: plug])

      assert {:ok, ^document} =
               Discovery.fetch(@loopback_issuer, [req_options: [plug: plug]] ++ @loopback)

      assert {:error, :invalid_issuer} =
               Discovery.validate_metadata(document, @loopback_issuer, protocol: :oauth)

      assert {:ok, ^document} =
               Discovery.validate_metadata(
                 document,
                 @loopback_issuer,
                 [protocol: :oauth] ++ @loopback
               )

      # A non-loopback http endpoint in a loopback issuer's document is refused.
      mixed = Map.put(document, "token_endpoint", "http://idp.example/token")

      assert {:error, :invalid_endpoint} =
               Discovery.validate_metadata(
                 mixed,
                 @loopback_issuer,
                 [protocol: :oauth] ++ @loopback
               )
    end

    test "a real http request reaches a server on the loopback interface" do
      {:ok, listener} =
        :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])

      {:ok, port} = :inet.port(listener)
      issuer = "http://127.0.0.1:#{port}"
      body = JSON.encode!(metadata(issuer))

      server =
        Task.async(fn ->
          {:ok, socket} = :gen_tcp.accept(listener, 5_000)
          {:ok, request} = :gen_tcp.recv(socket, 0, 5_000)

          :ok =
            :gen_tcp.send(
              socket,
              "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n" <>
                "content-length: #{byte_size(body)}\r\nconnection: close\r\n\r\n" <> body
            )

          :gen_tcp.close(socket)
          request
        end)

      assert {:ok, %{"issuer" => ^issuer}} =
               Discovery.fetch(issuer, [well_known: :oauth_authorization_server] ++ @loopback)

      request = Task.await(server)
      assert request =~ "GET /.well-known/oauth-authorization-server HTTP/1.1"
      assert request =~ "host: 127.0.0.1:#{port}"
      :gen_tcp.close(listener)

      assert {:error, :invalid_issuer} =
               Discovery.fetch(issuer, well_known: :oauth_authorization_server)
    end

    test "the authorization-code flow runs against a loopback issuer when both calls say so" do
      store = store()

      assert {:error, :invalid_issuer} =
               AuthorizationCode.start(store, oauth_opts(@loopback_issuer, []))

      assert {:ok, started} =
               AuthorizationCode.start(store, oauth_opts(@loopback_issuer, @loopback))

      assert String.starts_with?(started.url, @loopback_issuer <> "/authorize?")

      assert {:ok, %{tokens: %{access_token: "access"}}} =
               AuthorizationCode.callback(
                 store,
                 %{"state" => started.state, "code" => "code"},
                 [browser_binding: "browser-session", req_options: [plug: token_plug()]] ++
                   @loopback
               )
    end

    test "the transaction carries no allowance: a callback that does not pass it is refused" do
      store = store()

      assert {:ok, started} =
               AuthorizationCode.start(store, oauth_opts(@loopback_issuer, @loopback))

      assert {:error, :invalid_endpoint} =
               AuthorizationCode.callback(
                 store,
                 %{"state" => started.state, "code" => "code"},
                 browser_binding: "browser-session",
                 req_options: [plug: token_plug()]
               )
    end

    test "a malformed option at the callback does not spend the transaction" do
      store = store()

      assert {:ok, started} =
               AuthorizationCode.start(store, oauth_opts(@loopback_issuer, @loopback))

      response = %{"state" => started.state, "code" => "code"}
      opts = [browser_binding: "browser-session", req_options: [plug: token_plug()]]

      assert {:error, :invalid_outbound} =
               AuthorizationCode.callback(
                 store,
                 response,
                 opts ++ [outbound: [allow_loopback: true]]
               )

      assert {:ok, %{tokens: %{access_token: "access"}}} =
               AuthorizationCode.callback(store, response, opts ++ @loopback)
    end

    test "a callback cannot turn the option on for a transaction started against a deployed issuer" do
      store = store()

      assert {:ok, started} =
               AuthorizationCode.start(store, oauth_opts("https://idp.example", []))

      assert {:error, :invalid_outbound} =
               AuthorizationCode.callback(
                 store,
                 %{"state" => started.state, "code" => "code"},
                 [browser_binding: "browser-session", req_options: [plug: token_plug()]] ++
                   @loopback
               )
    end

    test "logout, exchange and refresh take the option" do
      assert {:ok, url} =
               Logout.url(
                 [
                   issuer: @loopback_issuer,
                   metadata: metadata(@loopback_issuer),
                   protocol: :oauth
                 ] ++
                   @loopback
               )

      assert url == @loopback_issuer <> "/logout"

      exchange = [
        token_endpoint: @loopback_issuer <> "/token",
        issuer: @loopback_issuer,
        client_id: "client",
        redirect_uri: @redirect,
        code_verifier: String.duplicate("v", 43),
        req_options: [plug: token_plug()]
      ]

      assert {:error, :invalid_endpoint} = AuthorizationCode.exchange("code", exchange)

      assert {:ok, %TokenSet{access_token: "access"}} =
               AuthorizationCode.exchange("code", exchange ++ @loopback)

      coordinator = start_supervised!({AttestoClient.RefreshCoordinator, name: nil})

      # Refresh reads the issuer's keys before the token request, so the stub
      # serves the metadata and JWKS over the loopback issuer as well.
      {_kty, public} = {:ec, "P-256"} |> JOSE.JWK.generate_key() |> JOSE.JWK.to_public_map()
      public = Map.merge(public, %{"kid" => "k1", "alg" => "ES256", "use" => "sig"})
      document = metadata(@loopback_issuer, %{"jwks_uri" => @loopback_issuer <> "/jwks"})

      plug = fn conn ->
        case conn.request_path do
          "/token" -> Req.Test.json(conn, %{"access_token" => "access", "token_type" => "Bearer"})
          "/jwks" -> Req.Test.json(conn, %{"keys" => [public]})
          _metadata -> Req.Test.json(conn, document)
        end
      end

      refresh = [
        token_endpoint: @loopback_issuer <> "/token",
        issuer: @loopback_issuer,
        client_id: "client",
        subject: "user",
        protocol: :oauth,
        well_known: :oauth_authorization_server,
        req_options: [plug: plug]
      ]

      tokens = %TokenSet{access_token: "old", token_type: "Bearer", refresh_token: "refresh"}

      assert {:error, :invalid_issuer} = Token.refresh(coordinator, "k1", tokens, refresh)

      assert {:ok, %{tokens: %TokenSet{access_token: "access"}}} =
               Token.refresh(coordinator, "k2", tokens, refresh ++ @loopback)
    end

    test "an issuer cache fetches a loopback issuer's keys" do
      jwk = JOSE.JWK.generate_key({:ec, "P-256"})
      {_kty, public} = JOSE.JWK.to_public_map(jwk)
      public = Map.merge(public, %{"kid" => "k1", "alg" => "ES256", "use" => "sig"})
      document = metadata(@loopback_issuer, %{"jwks_uri" => @loopback_issuer <> "/jwks"})

      plug = fn conn ->
        case conn.request_path do
          "/jwks" -> Req.Test.json(conn, %{"keys" => [public]})
          _metadata -> Req.Test.json(conn, document)
        end
      end

      cache =
        start_supervised!(
          {Issuer,
           [
             name: nil,
             issuer: @loopback_issuer,
             well_known: :oauth_authorization_server,
             req_options: [plug: plug]
           ] ++ @loopback}
        )

      assert {:ok, [%{"kid" => "k1"}]} = Issuer.keys(cache)

      assert_raise ArgumentError, ~r/requires an HTTPS :issuer/, fn ->
        Issuer.config!([issuer: @loopback_issuer], "Issuer")
      end

      assert_raise ArgumentError, ~r/:outbound must be a keyword list/, fn ->
        Issuer.config!(
          [issuer: "https://idp.example", outbound: [allowed_cidrs: ["nope"]]],
          "Issuer"
        )
      end
    end
  end

  describe "host parsing (core's rule, reached through every check here)" do
    test "a percent-encoded host and an empty label are refused" do
      for url <- ["https://auth.test%20evil/", "https://auth.test../", "https://auth..test/"] do
        assert {:error, :invalid_issuer} = Discovery.validate_issuer_identifier(url)
        assert {:error, :invalid_issuer} = Discovery.fetch(url)
        assert {:error, :invalid_endpoint} = Discovery.validate_endpoint(url)
        assert {:error, :invalid_endpoint} = Discovery.validate_browser_endpoint(url)
        assert {:error, :blocked_host} = Discovery.screen_endpoint(url)
        assert {:error, :invalid_jwks_uri} = Discovery.fetch_jwks(url)

        document = metadata("https://auth.test", %{"token_endpoint" => url <> "token"})

        assert {:error, :invalid_endpoint} =
                 Discovery.validate_metadata(document, "https://auth.test", protocol: :oauth)

        assert {:error, :invalid_issuer} =
                 AuthorizationCode.start(store(), oauth_opts(url, metadata: metadata(url)))
      end
    end

    test "an upper-case scheme is accepted and the request is sent as https" do
      url = "HTTPS://auth.test/token"
      public = resolver([{93, 184, 216, 34}])

      assert :ok = Discovery.validate_issuer_identifier("HTTPS://auth.test")
      assert :ok = Discovery.validate_browser_endpoint(url)
      assert :ok = Discovery.validate_endpoint(url, resolver: public)

      assert {:ok, %{url: "https://93.184.216.34/token", host: "auth.test"}} =
               Discovery.screen_endpoint(url, resolver: public)
    end

    test "one trailing dot is the fully qualified form and is accepted" do
      assert :ok = Discovery.validate_issuer_identifier("https://auth.test.")

      assert :ok =
               Discovery.validate_endpoint("https://auth.test./token",
                 resolver: resolver([{93, 184, 216, 34}])
               )
    end
  end
end
