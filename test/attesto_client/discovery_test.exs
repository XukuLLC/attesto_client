defmodule AttestoClient.DiscoveryTest do
  use ExUnit.Case, async: true

  alias AttestoClient.Discovery

  @issuer "https://op.example.com"

  # A Req plug that responds with `status` and `body` as JSON (Req decodes it
  # back to a map), so these tests never touch the network.
  defp json_plug(status, body) do
    fn conn ->
      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.send_resp(status, JSON.encode!(body))
    end
  end

  defp fetch(issuer, plug, opts \\ []) do
    Discovery.fetch(issuer, [req_options: [plug: plug]] ++ opts)
  end

  describe "fetch/2" do
    test "fetches and returns the metadata" do
      meta = %{
        "issuer" => @issuer,
        "jwks_uri" => "#{@issuer}/.well-known/jwks.json",
        "token_endpoint" => "#{@issuer}/oauth/token"
      }

      assert {:ok, m} = fetch(@issuer, json_plug(200, meta))
      assert m["jwks_uri"] == "#{@issuer}/.well-known/jwks.json"
      assert m["token_endpoint"] == "#{@issuer}/oauth/token"
    end

    test "requests the openid-configuration well-known path by default" do
      plug = fn conn ->
        assert conn.request_path == "/.well-known/openid-configuration"
        json_plug(200, %{"issuer" => @issuer}).(conn)
      end

      assert {:ok, _} = fetch(@issuer, plug)
    end

    test "uses the RFC 8414 document (segment before path) for a path-based issuer" do
      issuer = "https://op.example.com/tenant"

      plug = fn conn ->
        # RFC 8414 §3.1: inserted before the issuer path, not appended.
        assert conn.request_path == "/.well-known/oauth-authorization-server/tenant"
        json_plug(200, %{"issuer" => issuer}).(conn)
      end

      assert {:ok, _} = fetch(issuer, plug, well_known: :oauth_authorization_server)
    end

    test "removes a trailing slash for the request URL but matches the issuer exactly" do
      # A slash-terminated (e.g. multi-tenant path) issuer: the well-known
      # segment replaces the terminating slash (OIDC Discovery §4 / RFC 8414
      # §3.1), and the document's issuer must be byte-identical to the supplied
      # value - including the slash (RFC 8414 §3.3 / OIDC Discovery §4.3).
      issuer = "https://op.example.com/test/a/alias/"

      plug = fn conn ->
        assert conn.request_path == "/test/a/alias/.well-known/openid-configuration"
        json_plug(200, %{"issuer" => issuer}).(conn)
      end

      assert {:ok, %{"issuer" => ^issuer}} = fetch(issuer, plug)
    end

    test "rejects a document whose issuer differs only by a trailing slash" do
      # "https://op.example.com/" and "https://op.example.com" are different
      # issuer identifiers; a normalising comparison would conflate them.
      plug = json_plug(200, %{"issuer" => "https://op.example.com"})
      assert {:error, :issuer_mismatch} = fetch("https://op.example.com/", plug)
    end

    test "rejects a non-https issuer, or one with a query or fragment (RFC 8414 §2)" do
      assert {:error, :invalid_issuer} = Discovery.fetch("http://op.example.com")
      assert {:error, :invalid_issuer} = Discovery.fetch("not a url")
      assert {:error, :invalid_issuer} = Discovery.fetch("https://op.example.com?x=1")
      assert {:error, :invalid_issuer} = Discovery.fetch("https://op.example.com#frag")
      assert {:error, :invalid_issuer} = Discovery.fetch(:not_a_string)
    end

    test "rejects an unknown :well_known value (fail fast, no wrong-document fetch)" do
      # Must not fall through to the default document on a typo.
      assert {:error, :invalid_well_known} =
               fetch(@issuer, json_plug(200, %{"issuer" => @issuer}),
                 well_known: :oauth_authorization
               )
    end

    test "rejects an issuer mismatch (RFC 8414 §3.3)" do
      assert {:error, :issuer_mismatch} =
               fetch(@issuer, json_plug(200, %{"issuer" => "https://evil.example"}))
    end

    test "surfaces a non-200 status" do
      assert {:error, {:http_status, 404}} = fetch(@issuer, json_plug(404, %{"error" => "nope"}))
    end

    test "bounds a discovery body before JSON decoding" do
      oversized = %{"issuer" => @issuer, "padding" => String.duplicate("x", 256)}

      assert {:error, :response_too_large} =
               fetch(@issuer, json_plug(200, oversized), max_response_bytes: 64)
    end

    test "the overall deadline includes DNS screening" do
      parent = self()

      slow_resolver = fn _host, _family ->
        send(parent, :discovery_dns_started)
        Process.sleep(3_000)
        {:ok, [{93, 184, 216, 34}]}
      end

      started_at = System.monotonic_time(:millisecond)

      assert {:error, :timeout} =
               Discovery.fetch(@issuer, resolver: slow_resolver, timeout: 20)

      assert_receive :discovery_dns_started
      assert System.monotonic_time(:millisecond) - started_at < 1_500
    end

    test "rejects an invalid overall timeout before DNS" do
      resolver = fn _host, _family ->
        flunk("resolver must not run for an invalid timeout")
      end

      assert {:error, :invalid_timeout} =
               Discovery.fetch(@issuer, resolver: resolver, timeout: 0)
    end
  end

  describe "fetch_jwks/2" do
    test "returns a keys document" do
      jwks = %{"keys" => [%{"kty" => "EC", "crv" => "P-256", "kid" => "k1"}]}

      assert {:ok, result} =
               Discovery.fetch_jwks("#{@issuer}/jwks", req_options: [plug: json_plug(200, jwks)])

      assert [%{"kid" => "k1"}] = result["keys"]
    end

    test "rejects a document without a keys list" do
      assert {:error, :invalid_metadata} =
               Discovery.fetch_jwks("#{@issuer}/jwks",
                 req_options: [plug: json_plug(200, %{"x" => 1})]
               )
    end

    test "rejects a non-https (or non-string) JWKS URI - it is the signature trust root" do
      assert {:error, :invalid_jwks_uri} = Discovery.fetch_jwks("http://op.example.com/jwks")
      assert {:error, :invalid_jwks_uri} = Discovery.fetch_jwks("not a url")
      assert {:error, :invalid_jwks_uri} = Discovery.fetch_jwks(:nope)
    end
  end

  describe "SSRF hardening" do
    # A plug that 302-redirects to an internal target; if redirects were
    # followed, this would reach the metadata service.
    defp redirect_plug(location) do
      fn conn ->
        conn
        |> Plug.Conn.put_resp_header("location", location)
        |> Plug.Conn.send_resp(302, "")
      end
    end

    test "rejects an issuer that resolves to a link-local address (cloud metadata)" do
      assert {:error, :blocked_host} = Discovery.fetch("https://169.254.169.254")
    end

    test "rejects loopback and private issuers/JWKS URIs" do
      assert {:error, :blocked_host} = Discovery.fetch("https://127.0.0.1")
      assert {:error, :blocked_host} = Discovery.fetch("https://10.0.0.1")
      assert {:error, :blocked_host} = Discovery.fetch("https://192.168.1.1")
      assert {:error, :blocked_host} = Discovery.fetch_jwks("https://127.0.0.1/jwks")
      assert {:error, :blocked_host} = Discovery.fetch_jwks("https://[::1]/jwks")
    end

    test "rejects non-global IPv4 special-purpose destinations" do
      for host <- [
            "192.0.0.1",
            "192.0.2.1",
            "192.88.99.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "255.255.255.255"
          ] do
        assert {:error, :blocked_host} =
                 Discovery.validate_endpoint("https://#{host}/token"),
               host
      end

      # IANA carves these globally reachable anycast addresses out of the
      # otherwise non-global 192.0.0.0/24 protocol-assignment block.
      assert :ok = Discovery.validate_endpoint("https://192.0.0.9/token")
      assert :ok = Discovery.validate_endpoint("https://192.0.0.10/token")
    end

    test "rejects translated private and non-global IPv6 destinations" do
      for host <- [
            "[::]",
            "[::127.0.0.1]",
            "[64:ff9b::7f00:1]",
            "[64:ff9b:1::1]",
            "[fec0::1]",
            "[2002:7f00:1::]",
            "[2001::1]",
            "[2001:2::1]",
            "[2001:10::1]",
            "[2001:40::1]",
            "[2001:20::1]",
            "[2001:30::1]",
            "[2001:db8::1]",
            "[100:0:0:1::1]",
            "[4000::1]",
            "[8000::1]",
            "[3fff::1]",
            "[5f00::1]",
            "[ff00::1]"
          ] do
        assert {:error, :blocked_host} =
                 Discovery.validate_endpoint("https://#{host}/token"),
               host
      end

      # The globally reachable NAT64 prefix remains usable when its embedded
      # IPv4 destination is public.
      assert :ok = Discovery.validate_endpoint("https://[64:ff9b::808:808]/token")

      # More-specific globally reachable allocations within IANA's otherwise
      # non-global 2001::/23 protocol-assignment block remain usable.
      for host <- [
            "[2001:1::1]",
            "[2001:1::2]",
            "[2001:1::3]",
            "[2001:3::1]",
            "[2001:4:112::1]"
          ] do
        assert :ok = Discovery.validate_endpoint("https://#{host}/token"), host
      end

      assert :ok = Discovery.validate_endpoint("https://[2606:4700:4700::1111]/token")
    end

    test "pins the request URL to a screened address while retaining the original authority" do
      resolver = fn
        _host, :inet -> {:ok, [{93, 184, 216, 34}]}
        _host, :inet6 -> {:error, :nxdomain}
      end

      assert {:ok, target} =
               Discovery.screen_endpoint("https://op.example.com:8443/jwks",
                 resolver: resolver
               )

      assert target.url == "https://93.184.216.34:8443/jwks"
      assert target.host == "op.example.com"
      assert target.authority == "op.example.com:8443"
    end

    test "rejects proxy and custom Finch routing for a DNS-pinned fetch" do
      resolver = fn
        _host, :inet -> {:ok, [{93, 184, 216, 34}]}
        _host, :inet6 -> {:error, :nxdomain}
      end

      unsafe_options = [
        [connect_options: [proxy: {:http, "proxy.example", 8080, []}]],
        [finch: __MODULE__.CustomFinch]
      ]

      Enum.each(unsafe_options, fn req_options ->
        assert {:error, :unsafe_transport_options} =
                 Discovery.fetch(@issuer, resolver: resolver, req_options: req_options)
      end)
    end

    test "late Req signing and destination options cannot replace the screened authority" do
      resolver = fn
        _host, :inet -> {:ok, [{93, 184, 216, 34}]}
        _host, :inet6 -> {:error, :nxdomain}
      end

      parent = self()

      plug = fn conn ->
        {:ok, request_body, conn} = Plug.Conn.read_body(conn)

        send(parent, {
          :screened_discovery_request,
          %{
            method: conn.method,
            host: Plug.Conn.get_req_header(conn, "host"),
            authorization: Plug.Conn.get_req_header(conn, "authorization"),
            cookie: Plug.Conn.get_req_header(conn, "cookie"),
            request_path: conn.request_path,
            request_body: request_body,
            trace: Plug.Conn.get_req_header(conn, "x-trace")
          }
        })

        json_plug(200, %{"issuer" => @issuer}).(conn)
      end

      assert {:ok, %{"issuer" => @issuer}} =
               Discovery.fetch(@issuer,
                 resolver: resolver,
                 req_options: [
                   plug: plug,
                   adapter: fn _request -> raise "caller adapter ran" end,
                   auth: :netrc,
                   headers: [
                     {"authorization", "Bearer caller-token"},
                     {"cookie", "session=caller"},
                     {"x-trace", "preserved"}
                   ],
                   params: [reroute: "true"],
                   follow_redirects: true,
                   form: [caller: "form"],
                   body: "caller-body",
                   connect_options: [
                     transport_opts: [
                       verify: :verify_none,
                       server_name_indication: ~c"caller.invalid",
                       customize_hostname_check: [match_fun: fn _, _ -> true end],
                       verify_fun: {fn _, _, state -> {:valid, state} end, nil},
                       partial_chain: fn _ -> {:trusted_ca, :caller} end
                     ]
                   ],
                   aws_sigv4: [
                     access_key_id: "caller-access-key",
                     secret_access_key: "caller-secret-key",
                     region: "us-east-1",
                     service: "execute-api"
                   ]
                 ]
               )

      assert_receive {:screened_discovery_request,
                      %{
                        method: "GET",
                        host: ["op.example.com"],
                        authorization: [],
                        cookie: [],
                        request_path: "/.well-known/openid-configuration",
                        request_body: "",
                        trace: ["preserved"]
                      }}
    end

    test "rejects a mixed DNS answer instead of pinning only its public member" do
      resolver = fn
        _host, :inet -> {:ok, [{93, 184, 216, 34}, {169, 254, 169, 254}]}
        _host, :inet6 -> {:error, :nxdomain}
      end

      assert {:error, :blocked_host} =
               Discovery.screen_endpoint("https://op.example.com/jwks", resolver: resolver)
    end

    test "Req plug tests bypass DNS because no network transport is used" do
      plug = json_plug(200, %{"issuer" => "https://127.0.0.1"})

      assert :ok =
               Discovery.validate_endpoint("https://127.0.0.1/token",
                 req_options: [plug: plug]
               )

      assert {:ok, %{"issuer" => "https://127.0.0.1"}} =
               Discovery.fetch("https://127.0.0.1", req_options: [plug: plug])

      assert {:error, :blocked_host} =
               Discovery.validate_endpoint("https://127.0.0.1/token")
    end

    test "nil and false Req plugs retain the DNS guard" do
      Enum.each([nil, false], fn plug ->
        opts = [req_options: [plug: plug]]

        assert {:error, :blocked_host} =
                 Discovery.validate_endpoint("https://127.0.0.1/token", opts)

        assert {:error, :blocked_host} =
                 Discovery.fetch("https://127.0.0.1", opts)
      end)
    end

    test "rejects an invalid resolver instead of falling back to system DNS" do
      assert {:error, :invalid_resolver} =
               Discovery.fetch(@issuer, resolver: fn _host -> {:ok, []} end)
    end

    test "does not follow redirects (a 3xx is surfaced, never chased to its Location)" do
      # If redirects were followed, the fetch would chase the Location to the
      # internal target; instead the 302 is returned as a status error.
      assert {:error, {:http_status, 302}} =
               fetch(@issuer, redirect_plug("http://169.254.169.254/latest/meta-data/"))

      assert {:error, {:http_status, 302}} =
               Discovery.fetch_jwks("#{@issuer}/jwks",
                 req_options: [plug: redirect_plug("http://127.0.0.1/jwks")]
               )
    end
  end

  describe "interop" do
    defmodule Keystore do
      @moduledoc false
      @behaviour Attesto.Keystore

      @pem JOSE.JWK.generate_key({:ec, "P-256"}) |> JOSE.JWK.to_pem() |> elem(1)

      @impl true
      def signing_pem, do: @pem
      @impl true
      def verification_pems, do: [@pem]
    end

    test "reads the metadata that attesto's OpenIDDiscovery produces" do
      protocol_config =
        Attesto.Config.new(
          issuer: @issuer,
          audience: @issuer,
          keystore: Keystore,
          principal_kinds: [Attesto.PrincipalKind.new("user", "usr_")]
        )

      served = Attesto.OpenIDDiscovery.metadata(protocol_config)

      assert {:ok, m} = fetch(@issuer, json_plug(200, served))
      assert m["issuer"] == @issuer
      assert is_binary(m["token_endpoint"])
      assert is_binary(m["jwks_uri"])
    end
  end
end
