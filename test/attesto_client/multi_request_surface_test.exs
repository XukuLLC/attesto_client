defmodule AttestoClient.MultiRequestSurfaceTest do
  use ExUnit.Case, async: true

  alias AttestoClient.{Discovery, IDToken, Issuer, ResourceServer, SignedIntrospection, UserInfo}

  alias AttestoClient.ResourceServer.Plug, as: ResourceServerPlug

  @issuer "https://issuer.example"

  for module <- [IDToken, SignedIntrospection, UserInfo] do
    @module module
    test "#{inspect(module)}.verify: metadata GET then failed JWKS connect remains not_sent" do
      parent = self()
      plug = metadata_then_failure(parent)

      assert {:error, :not_sent} =
               @module.verify("header.payload.signature",
                 issuer: @issuer,
                 client_id: "client",
                 audience: "audience",
                 subject: "subject",
                 req_options: [plug: plug]
               )

      assert_receive {:request, "GET", "/.well-known/openid-configuration"}
      assert_receive {:request, "GET", "/jwks"}
    end
  end

  for {module, operation} <- [
        {Issuer, :metadata},
        {Issuer, :keys},
        {Issuer, :warm},
        {Issuer, :refresh},
        {ResourceServer, :warm},
        {ResourceServer, :refresh},
        {ResourceServer, :verify}
      ] do
    @module module
    @operation operation
    test "#{inspect(module)}.#{operation}: metadata GET then failed JWKS connect retains its refresh wrapper" do
      server =
        start_supervised!(
          {@module,
           issuer: @issuer,
           audience: "audience",
           accepted_algs: ["ES256"],
           req_options: [plug: metadata_then_failure(self())]}
        )

      args =
        if @operation == :verify, do: [server, "header.payload.signature", []], else: [server]

      assert {:error, {:jwks_refresh_failed, :not_sent}} = apply(@module, @operation, args)
      assert_receive {:request, "GET", "/.well-known/openid-configuration"}
      assert_receive {:request, "GET", "/jwks"}
    end
  end

  test "authorization_server: resource GET then failed issuer connection remains not_sent" do
    parent = self()
    resource = "https://resource.example"

    plug = fn conn ->
      send(parent, {:request, conn.method, conn.host})

      if conn.host == "resource.example",
        do: Req.Test.json(conn, %{"resource" => resource, "authorization_servers" => [@issuer]}),
        else:
          Plug.Conn.put_private(conn, :req_test_exception, %Req.TransportError{
            reason: {:not_sent, {:transport, :econnrefused}}
          })
    end

    assert {:error, :not_sent} =
             Discovery.authorization_server(resource, req_options: [plug: plug])

    assert_receive {:request, "GET", "resource.example"}
    assert_receive {:request, "GET", "issuer.example"}
  end

  test "the resource-server plug retains its unavailable response on a later JWKS connect failure" do
    server =
      start_supervised!(
        {ResourceServer,
         issuer: @issuer,
         audience: "audience",
         accepted_algs: ["ES256"],
         req_options: [plug: metadata_then_failure(self())]}
      )

    conn =
      Plug.Test.conn(:get, "/resource")
      |> Plug.Conn.put_req_header("authorization", "Bearer header.payload.signature")
      |> ResourceServerPlug.call(server: server)

    assert conn.status == 503
    assert conn.halted
    assert_receive {:request, "GET", "/.well-known/openid-configuration"}
    assert_receive {:request, "GET", "/jwks"}
  end

  test "logout with a cache retains the refresh failure after metadata is fetched" do
    server =
      start_supervised!(
        {Issuer, issuer: @issuer, req_options: [plug: metadata_then_failure(self())]}
      )

    assert {:error, {:jwks_refresh_failed, :not_sent}} =
             AttestoClient.Logout.url(issuer: @issuer, issuer_cache: server)

    assert_receive {:request, "GET", "/.well-known/openid-configuration"}
    assert_receive {:request, "GET", "/jwks"}
  end

  defp metadata_then_failure(parent) do
    fn conn ->
      send(parent, {:request, conn.method, conn.request_path})

      case conn.request_path do
        "/.well-known/openid-configuration" ->
          Req.Test.json(conn, %{"issuer" => @issuer, "jwks_uri" => @issuer <> "/jwks"})

        "/jwks" ->
          Plug.Conn.put_private(conn, :req_test_exception, %Req.TransportError{
            reason: {:not_sent, {:transport, :econnrefused}}
          })
      end
    end
  end
end
