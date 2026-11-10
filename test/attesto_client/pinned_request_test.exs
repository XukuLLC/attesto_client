defmodule AttestoClient.PinnedRequestTest do
  use ExUnit.Case, async: false

  alias AttestoClient.OAuthHTTP
  alias AttestoClient.PinnedRequest

  @endpoint "https://service.example.test/document"

  setup do
    previous = Req.default_options()
    on_exit(fn -> Req.default_options(previous) end)
    :ok
  end

  test "per-request pinning ignores unsafe Req application defaults" do
    Req.default_options(
      auth: {:bearer, "global-token"},
      aws_sigv4: [
        access_key_id: "global-access-key",
        secret_access_key: "global-secret-key",
        region: "us-east-1",
        service: "execute-api"
      ],
      connect_options: [proxy: {:http, "proxy.example", 8080, []}],
      finch: __MODULE__.GlobalFinch,
      headers: [{"authorization", "Bearer global-header"}, {"host", "global.invalid"}],
      params: [reroute: "true"],
      unix_socket: "/tmp/global-req.sock"
    )

    plug = fn conn ->
      assert Plug.Conn.get_req_header(conn, "authorization") == []
      assert Plug.Conn.get_req_header(conn, "host") == ["service.example.test"]

      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.send_resp(200, JSON.encode!(%{"ok" => true}))
    end

    resolver = fn
      _host, :inet -> {:ok, [{93, 184, 216, 34}]}
      _host, :inet6 -> {:error, :nxdomain}
    end

    assert {:ok, %{"ok" => true}} =
             OAuthHTTP.get_json(@endpoint, resolver: resolver, req_options: [plug: plug])
  end

  test "pinning removes Req's URL-keyed cache options" do
    target = %{
      url: "https://93.184.216.34/document",
      host: "service.example.test",
      authority: "service.example.test"
    }

    assert {:ok, options} =
             PinnedRequest.prepare(target,
               cache: true,
               cache_dir: "/tmp/attesto-client-cache-must-not-be-used"
             )

    assert options[:cache] == nil
    assert options[:cache_dir] == nil
  end

  test "pinning protects the destination, request fields, and TLS identity" do
    target = %{
      url: "https://93.184.216.34:8443/document",
      host: "service.example.test",
      authority: "service.example.test:8443"
    }

    raising_adapter = fn _request -> raise "caller adapter ran" end

    assert {:ok, options} =
             PinnedRequest.prepare(
               target,
               [
                 plug: fn conn -> Plug.Conn.send_resp(conn, 204, "") end,
                 adapter: raising_adapter,
                 url: "https://caller.invalid/override",
                 method: :delete,
                 body: "caller-body",
                 auth: {:bearer, "caller-token"},
                 headers: [
                   {"authorization", "Bearer caller-header"},
                   {"content-encoding", "gzip"},
                   {"host", "caller.invalid"},
                   {"cookie", "session=caller"},
                   {"oauth_client_attestation", "underscore-smuggled"},
                   {"proxy_authorization", "underscore-smuggled"},
                   {"transfer-encoding", "chunked"},
                   {"x-trace", "preserved"}
                 ],
                 params: [reroute: true],
                 aws_sigv4: [service: "execute-api"],
                 connect_options: [
                   hostname: "caller.invalid",
                   timeout: 321,
                   transport_opts: [
                     cb_info: {__MODULE__.CallerTransport, :tcp, :tcp_closed, :tcp_error},
                     verify: :verify_none,
                     server_name_indication: ~c"caller.invalid",
                     customize_hostname_check: [match_fun: fn _, _ -> true end],
                     verify_fun: {fn _, _, state -> {:valid, state} end, nil},
                     partial_chain: fn _ -> {:trusted_ca, :caller} end
                   ]
                 ]
               ],
               ["authorization", "cookie", "oauth-client-attestation"],
               [:auth]
             )

    request =
      options
      |> Keyword.merge(url: target.url, method: :get, body: nil)
      |> PinnedRequest.new()

    assert URI.to_string(request.url) == target.url
    assert request.method == :get
    assert request.body == nil
    assert Req.Request.get_header(request, "host") == [target.authority]
    assert Req.Request.get_header(request, "authorization") == []
    assert Req.Request.get_header(request, "content-encoding") == []
    assert Req.Request.get_header(request, "cookie") == []
    assert Req.Request.get_header(request, "oauth_client_attestation") == []
    assert Req.Request.get_header(request, "proxy_authorization") == []
    assert Req.Request.get_header(request, "transfer-encoding") == []
    assert Req.Request.get_header(request, "x-trace") == ["preserved"]
    assert request.options[:auth] == nil
    assert request.options[:aws_sigv4] == nil
    assert request.options[:params] == nil
    assert request.adapter != raising_adapter

    connect_options = request.options[:connect_options]
    assert connect_options[:hostname] == target.host
    assert connect_options[:timeout] == 321

    transport_opts = connect_options[:transport_opts]
    assert transport_opts[:cb_info] == nil
    assert transport_opts[:verify] == :verify_peer
    assert transport_opts[:server_name_indication] == nil
    assert transport_opts[:customize_hostname_check] == nil
    assert transport_opts[:verify_fun] == nil
    assert transport_opts[:partial_chain] == nil
  end

  test "pinning rejects ambiguous duplicate transport options" do
    target = %{
      url: "https://93.184.216.34/document",
      host: "93.184.216.34",
      authority: "93.184.216.34"
    }

    proxy = {:http, "proxy.example", 8080, []}

    duplicate_options = [
      [finch: false, finch: __MODULE__.CallerFinch],
      [adapter: nil, adapter: fn request -> {request, Req.Response.new(status: 200)} end],
      [connect_options: [], connect_options: [transport_opts: [verify: :verify_none]]],
      [connect_options: [proxy: false, proxy: proxy]],
      [connect_options: [transport_opts: [verify: :verify_peer, verify: :verify_none]]]
    ]

    Enum.each(duplicate_options, fn options ->
      assert {:error, :unsafe_transport_options} = PinnedRequest.prepare(target, options)
    end)
  end

  test "requests to distinct hostnames leave no connection pool behind" do
    pools = fn -> DynamicSupervisor.count_children(Req.FinchSupervisor).active end
    before = pools.()

    for index <- 1..20 do
      host = "host-#{index}.example.test"
      # Nothing listens on port 1, so each connection is refused locally.
      target = %{url: "https://127.0.0.1:1/document", host: host, authority: host}
      assert {:ok, options} = PinnedRequest.prepare(target, [])

      request =
        options
        |> Keyword.merge(url: target.url, method: :get, retry: false)
        |> PinnedRequest.new()

      assert {:error, %Req.TransportError{}} = Req.request(request)
    end

    assert pools.() == before
  end

  @tag :capture_log
  test "a pinned request dials the screened address and verifies TLS for the original host" do
    curve = {:namedCurve, {1, 2, 840, 10_045, 3, 1, 7}}
    san = {:Extension, {2, 5, 29, 17}, false, [dNSName: ~c"service.example.test"]}

    data =
      :public_key.pkix_test_data(%{
        root: [key: curve, digest: :sha256],
        intermediates: [],
        peer: [key: curve, digest: :sha256, extensions: [san]]
      })

    server_config = [cert: data[:cert], key: data[:key]]
    port = start_tls_server(server_config, ["pinned body", String.duplicate("a", 64), ""])
    url = "https://127.0.0.1:#{port}/document?view=full"

    fetch = fn host ->
      target = %{url: url, host: host, authority: "#{host}:#{port}"}

      assert {:ok, options} =
               PinnedRequest.prepare(target,
                 connect_options: [transport_opts: [cacerts: data[:cacerts]]]
               )

      options
      |> Keyword.merge(
        url: url,
        method: :get,
        retry: false,
        raw: true,
        into: PinnedRequest.bounded_response_into(32)
      )
      |> PinnedRequest.new()
      |> Req.request()
    end

    assert {:ok, %Req.Response{status: 200, body: "pinned body"}} =
             fetch.("service.example.test")

    assert_receive {:served, ~c"service.example.test", head}
    assert head =~ "GET /document?view=full HTTP/1.1\r\n"
    assert head =~ "\r\nhost: service.example.test:#{port}\r\n"

    assert {:ok, %Req.Response{private: %{attesto_client_response_too_large: true}}} =
             fetch.("service.example.test")

    assert_receive {:served, ~c"service.example.test", _head}

    assert {:error, %Req.TransportError{reason: {:tls_alert, _alert}}} =
             fetch.("other.example.test")

    assert_receive {:handshake_failed, _reason}
  end

  test "pinning rejects a custom adapter even for a direct public IP" do
    target = %{
      url: "https://93.184.216.34/document",
      host: "93.184.216.34",
      authority: "93.184.216.34"
    }

    adapter = fn request -> {request, Req.Response.new(status: 200)} end

    assert {:error, :unsafe_transport_options} =
             PinnedRequest.prepare(target, adapter: adapter)
  end

  defp start_tls_server(server_config, bodies) do
    parent = self()

    spawn_link(fn ->
      options = [ip: {127, 0, 0, 1}, active: false, mode: :binary, reuseaddr: true]
      {:ok, listener} = :ssl.listen(0, options ++ server_config)
      {:ok, {_address, port}} = :ssl.sockname(listener)
      send(parent, {:tls_port, port})
      Enum.each(bodies, &serve_once(listener, parent, &1))
    end)

    assert_receive {:tls_port, port}
    port
  end

  defp serve_once(listener, parent, body) do
    {:ok, socket} = :ssl.transport_accept(listener, 5_000)

    case :ssl.handshake(socket, 5_000) do
      {:ok, socket} ->
        {:ok, [sni_hostname: sni]} = :ssl.connection_information(socket, [:sni_hostname])
        head = read_head(socket, "")

        :ok =
          :ssl.send(socket, [
            "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\nconnection: close\r\n",
            "content-length: #{byte_size(body)}\r\n\r\n",
            body
          ])

        send(parent, {:served, sni, head})
        :ssl.close(socket)

      {:error, reason} ->
        send(parent, {:handshake_failed, reason})
    end
  end

  defp read_head(socket, acc) do
    if String.contains?(acc, "\r\n\r\n") do
      acc
    else
      {:ok, data} = :ssl.recv(socket, 0, 5_000)
      read_head(socket, acc <> data)
    end
  end
end
