defmodule AttestoClient.MCPAuthorizationTest do
  use ExUnit.Case, async: true

  alias AttestoClient.MCPAuthorization
  alias AttestoClient.MCPAuthorization.Registration
  alias AttestoClient.RefreshCoordinator
  alias AttestoClient.RefreshResult
  alias AttestoClient.TokenSet

  @resource "https://mcp.example.com/service/mcp"
  @issuer "https://auth.example.com/tenant"
  @redirect "https://client.example.com/callback"

  defp resource_metadata(extra \\ %{}) do
    Map.merge(
      %{
        "resource" => @resource,
        "authorization_servers" => [@issuer],
        "scopes_supported" => ["tools:read"]
      },
      extra
    )
  end

  defp authorization_server(extra \\ %{}) do
    Map.merge(
      %{
        "issuer" => @issuer,
        "authorization_endpoint" => @issuer <> "/authorize",
        "token_endpoint" => @issuer <> "/token",
        "code_challenge_methods_supported" => ["S256"],
        "token_endpoint_auth_methods_supported" => [
          "none",
          "client_secret_basic",
          "client_secret_post",
          "private_key_jwt"
        ]
      },
      extra
    )
  end

  defp context(server_extra \\ %{}, context_extra \\ %{}) do
    struct!(
      MCPAuthorization,
      Map.merge(
        %{
          resource: @resource,
          resource_metadata: resource_metadata(),
          issuer: @issuer,
          authorization_server: authorization_server(server_extra),
          scopes: ["tools:read"]
        },
        context_extra
      )
    )
  end

  defp registration(extra \\ %{}) do
    struct!(
      Registration,
      Map.merge(
        %{
          issuer: @issuer,
          client_id: "mcp-client",
          client_auth: :none,
          source: :pre_registered
        },
        extra
      )
    )
  end

  defp json(conn, status, body) do
    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.send_resp(status, JSON.encode!(body))
  end

  defp form(conn) do
    {:ok, body, conn} = Plug.Conn.read_body(conn)
    {Enum.to_list(URI.query_decoder(body)), conn}
  end

  describe "discover/2" do
    test "rejects malformed outbound options before challenge parsing" do
      plug = fn _conn -> flunk("no request expected") end

      assert {:error, :invalid_outbound} =
               MCPAuthorization.discover(@resource,
                 outbound: :loopback,
                 www_authenticate: ~s(Bearer resource_metadata="https://mcp.example/prm"),
                 req_options: [plug: plug]
               )
    end

    test "treats an explicit nil outbound option as absent" do
      plug = fn conn ->
        case conn.request_path do
          "/.well-known/oauth-protected-resource/service/mcp" ->
            json(conn, 200, resource_metadata())

          "/.well-known/oauth-authorization-server/tenant" ->
            json(conn, 200, authorization_server())
        end
      end

      assert {:ok, %MCPAuthorization{}} =
               MCPAuthorization.discover(@resource,
                 outbound: nil,
                 req_options: [plug: plug]
               )
    end

    test "uses a challenge pointer and scope before protected-resource scopes" do
      challenge =
        ~s(Bearer resource_metadata="https://mcp.example.com/custom/prm", scope="files:write")

      plug = fn conn ->
        case conn.request_path do
          "/custom/prm" ->
            json(conn, 200, resource_metadata())

          "/.well-known/oauth-authorization-server/tenant" ->
            json(conn, 200, authorization_server(%{"scopes_supported" => ["offline_access"]}))
        end
      end

      assert {:ok, discovered} =
               MCPAuthorization.discover(@resource,
                 www_authenticate: challenge,
                 offline_access: true,
                 req_options: [plug: plug]
               )

      assert discovered.issuer == @issuer
      assert discovered.scopes == ["files:write", "offline_access"]
    end

    test "falls back from path-specific resource metadata to the root, then tries every issuer candidate" do
      parent = self()

      plug = fn conn ->
        send(parent, {:request, conn.request_path})

        case conn.request_path do
          "/.well-known/oauth-protected-resource/service/mcp" -> json(conn, 404, %{})
          "/.well-known/oauth-protected-resource" -> json(conn, 200, resource_metadata())
          "/.well-known/oauth-authorization-server/tenant" -> json(conn, 404, %{})
          "/.well-known/openid-configuration/tenant" -> json(conn, 200, authorization_server())
        end
      end

      assert {:ok, discovered} =
               MCPAuthorization.discover(@resource, req_options: [plug: plug])

      assert discovered.scopes == ["tools:read"]

      assert_receive {:request, "/.well-known/oauth-protected-resource/service/mcp"}
      assert_receive {:request, "/.well-known/oauth-protected-resource"}
      assert_receive {:request, "/.well-known/oauth-authorization-server/tenant"}
      assert_receive {:request, "/.well-known/openid-configuration/tenant"}
      refute_receive {:request, _path}
    end

    test "uses an origin identifier published by the root fallback" do
      origin = "https://mcp.example.com"
      root_metadata = resource_metadata(%{"resource" => origin})

      plug = fn conn ->
        case conn.request_path do
          "/.well-known/oauth-protected-resource/service/mcp" ->
            json(conn, 404, %{})

          "/.well-known/oauth-protected-resource" ->
            json(conn, 200, root_metadata)

          "/.well-known/oauth-authorization-server/tenant" ->
            json(conn, 200, authorization_server())
        end
      end

      assert {:ok, %{resource: ^origin, resource_metadata: %{"resource" => ^origin}}} =
               MCPAuthorization.discover(@resource, req_options: [plug: plug])
    end

    test "does not use the root fallback for a challenge pointer" do
      challenge =
        ~s(Bearer resource_metadata="https://mcp.example.com/missing/prm")

      plug = fn conn ->
        assert conn.request_path == "/missing/prm"
        json(conn, 404, %{})
      end

      assert {:error, {:http_status, 404}} =
               MCPAuthorization.discover(@resource,
                 www_authenticate: challenge,
                 req_options: [plug: plug]
               )
    end

    test "honors an explicit path-only protected-resource location" do
      parent = self()

      plug = fn conn ->
        send(parent, {:request, conn.request_path})
        json(conn, 404, %{})
      end

      assert {:error, {:http_status, 404}} =
               MCPAuthorization.discover(@resource,
                 resource_well_known: :path,
                 req_options: [plug: plug]
               )

      assert_receive {:request, "/.well-known/oauth-protected-resource/service/mcp"}
      refute_receive {:request, _path}
    end

    test "requires an explicit S256 advertisement" do
      for methods <- [nil, [], ["plain"]] do
        server =
          if is_nil(methods),
            do: Map.delete(authorization_server(), "code_challenge_methods_supported"),
            else: authorization_server(%{"code_challenge_methods_supported" => methods})

        plug = fn conn ->
          case conn.request_path do
            "/.well-known/oauth-protected-resource/service/mcp" ->
              json(conn, 200, resource_metadata())

            "/.well-known/oauth-authorization-server/tenant" ->
              json(conn, 200, server)
          end
        end

        assert {:error, :missing_pkce_support} =
                 MCPAuthorization.discover(@resource, req_options: [plug: plug])
      end
    end

    test "refuses resource identity mismatch" do
      plug = fn conn ->
        assert conn.request_path == "/.well-known/oauth-protected-resource/service/mcp"

        json(
          conn,
          200,
          resource_metadata(%{"resource" => "https://mcp.example.com/other"})
        )
      end

      assert {:error, :resource_mismatch} =
               MCPAuthorization.discover(@resource, req_options: [plug: plug])
    end

    test "omits scope when undefined and adds offline_access only when advertised" do
      for {server_scopes, expected} <- [
            {[], []},
            {["profile"], []},
            {["profile", "offline_access"], ["offline_access"]}
          ] do
        prm = Map.delete(resource_metadata(), "scopes_supported")
        server = authorization_server(%{"scopes_supported" => server_scopes})

        plug = fn conn ->
          case conn.request_path do
            "/.well-known/oauth-protected-resource/service/mcp" -> json(conn, 200, prm)
            "/.well-known/oauth-authorization-server/tenant" -> json(conn, 200, server)
          end
        end

        assert {:ok, %{scopes: ^expected}} =
                 MCPAuthorization.discover(@resource,
                   offline_access: true,
                   req_options: [plug: plug]
                 )
      end
    end

    test "supports an explicit loopback HTTP development resource and challenge pointer" do
      resource = "http://127.0.0.1:4100/mcp"
      issuer = "http://127.0.0.1:4200/tenant"

      prm = %{
        "resource" => resource,
        "authorization_servers" => [issuer],
        "scopes_supported" => ["mcp:read"]
      }

      server = %{
        "issuer" => issuer,
        "authorization_endpoint" => issuer <> "/authorize",
        "token_endpoint" => issuer <> "/token",
        "code_challenge_methods_supported" => ["S256"],
        "token_endpoint_auth_methods_supported" => ["none"]
      }

      plug = fn conn ->
        case conn.request_path do
          "/custom/prm" -> json(conn, 200, prm)
          "/.well-known/oauth-authorization-server/tenant" -> json(conn, 200, server)
        end
      end

      challenge =
        ~s(Bearer resource_metadata="http://127.0.0.1:4100/custom/prm", scope="mcp:read")

      assert {:ok, %{resource: ^resource, issuer: ^issuer, scopes: ["mcp:read"]}} =
               MCPAuthorization.discover(resource,
                 www_authenticate: challenge,
                 outbound: [allow_loopback_http: true],
                 req_options: [plug: plug]
               )
    end
  end

  describe "select_registration/2" do
    test "prefers issuer-bound pre-registration over CIMD and prompting" do
      parent = self()

      cimd = %{
        client_id: "https://client.example.com/oauth/client.json",
        document: cimd_document()
      }

      assert {:ok,
              %Registration{
                client_id: "registered",
                client_auth: {:client_secret_basic, "secret"},
                source: :pre_registered
              }} =
               MCPAuthorization.select_registration(
                 context(%{"client_id_metadata_document_supported" => true}),
                 pre_registered: %{
                   @issuer => %{
                     client_id: "registered",
                     client_auth: {:client_secret_basic, "secret"}
                   }
                 },
                 client_id_metadata: cimd,
                 prompt: fn _issuer, _metadata ->
                   send(parent, :prompted)
                   %{client_id: "prompted"}
                 end
               )

      refute_receive :prompted
    end

    test "selects and validates a Client ID Metadata Document" do
      assert {:ok,
              %Registration{
                issuer: @issuer,
                client_id: "https://client.example.com/oauth/client.json",
                client_auth: :none,
                source: :client_id_metadata,
                metadata: %{"client_name" => "Example MCP Client"}
              }} =
               MCPAuthorization.select_registration(
                 context(%{"client_id_metadata_document_supported" => true}),
                 client_id_metadata: %{
                   client_id: "https://client.example.com/oauth/client.json",
                   document: cimd_document()
                 }
               )
    end

    test "requires the MCP client_name member in a Client ID Metadata Document" do
      assert {:error, :invalid_client_id_metadata} =
               MCPAuthorization.select_registration(
                 context(%{"client_id_metadata_document_supported" => true}),
                 client_id_metadata: %{
                   client_id: "https://client.example.com/oauth/client.json",
                   document: Map.delete(cimd_document(), "client_name")
                 }
               )
    end

    test "returns an error for incomplete CIMD input instead of raising" do
      cimd_context = context(%{"client_id_metadata_document_supported" => true})

      for incomplete <- [
            %{client_id: "https://client.example.com/oauth/client.json"},
            %{document: cimd_document()},
            %{client_id: nil, document: cimd_document()},
            %{client_id: "https://client.example.com/oauth/client.json", document: nil}
          ] do
        assert {:error, :invalid_client_id_metadata} =
                 MCPAuthorization.select_registration(cimd_context,
                   client_id_metadata: incomplete
                 )
      end

      assert {:error, :invalid_client_id_metadata} =
               MCPAuthorization.select_registration(cimd_context,
                 registration:
                   registration(%{
                     issuer: "https://old.example",
                     source: :client_id_metadata,
                     metadata: nil
                   })
               )
    end

    test "treats nil registration strategies as absent" do
      assert {:error, :client_registration_required} =
               MCPAuthorization.select_registration(
                 context(%{
                   "client_id_metadata_document_supported" => true,
                   "registration_endpoint" => @issuer <> "/register"
                 }),
                 pre_registered: nil,
                 client_id_metadata: nil,
                 dynamic_registration: nil
               )
    end

    test "never reuses issuer-bound credentials after authorization-server migration" do
      previous = registration(%{issuer: "https://old.example", client_id: "old"})

      assert {:error, :authorization_server_changed} =
               MCPAuthorization.select_registration(context(), registration: previous)

      assert {:ok, %Registration{client_id: "new", issuer: @issuer}} =
               MCPAuthorization.select_registration(context(),
                 registration: previous,
                 pre_registered: %{@issuer => %{client_id: "new", client_auth: :none}}
               )
    end

    test "a prior CIMD registration is portable only to a server advertising CIMD" do
      prior =
        registration(%{
          issuer: "https://old.example",
          client_id: "https://client.example.com/oauth/client.json",
          source: :client_id_metadata,
          metadata: cimd_document()
        })

      assert {:ok, %Registration{issuer: @issuer, source: :client_id_metadata}} =
               MCPAuthorization.select_registration(
                 context(%{"client_id_metadata_document_supported" => true}),
                 registration: prior
               )

      assert {:error, :authorization_server_changed} =
               MCPAuthorization.select_registration(context(), registration: prior)
    end

    test "does not reuse same-issuer CIMD after support is withdrawn" do
      prior =
        registration(%{
          client_id: "https://client.example.com/oauth/client.json",
          source: :client_id_metadata,
          metadata: cimd_document()
        })

      assert {:error, :client_registration_required} =
               MCPAuthorization.select_registration(context(), registration: prior)
    end

    test "revalidates a same-issuer CIMD registration before reuse" do
      prior =
        registration(%{
          client_id: "https://client.example.com/oauth/client.json",
          source: :client_id_metadata,
          metadata: nil
        })

      assert {:error, :invalid_client_id_metadata} =
               MCPAuthorization.select_registration(
                 context(%{"client_id_metadata_document_supported" => true}),
                 registration: prior
               )
    end

    test "a pre-registration for the new issuer wins over a portable prior CIMD" do
      prior =
        registration(%{
          issuer: "https://old.example",
          client_id: "https://client.example.com/oauth/client.json",
          source: :client_id_metadata,
          metadata: cimd_document()
        })

      assert {:ok, %Registration{client_id: "new-issuer-client", source: :pre_registered}} =
               MCPAuthorization.select_registration(
                 context(%{"client_id_metadata_document_supported" => true}),
                 registration: prior,
                 pre_registered: %{@issuer => %{client_id: "new-issuer-client"}}
               )
    end

    test "revalidates a portable CIMD client identifier" do
      prior =
        registration(%{
          issuer: "https://old.example",
          client_id: "not-an-https-client-id",
          source: :client_id_metadata,
          metadata: Map.put(cimd_document(), "client_id", "not-an-https-client-id")
        })

      assert {:error, :invalid_client_id_metadata} =
               MCPAuthorization.select_registration(
                 context(%{"client_id_metadata_document_supported" => true}),
                 registration: prior
               )
    end

    test "supports public, basic, and post pre-registrations when advertised" do
      for auth <- [:none, {:client_secret_basic, "s"}, {:client_secret_post, "s"}] do
        assert {:ok, %Registration{client_auth: ^auth}} =
                 MCPAuthorization.select_registration(context(),
                   pre_registered: %{@issuer => %{client_id: "client", client_auth: auth}}
                 )
      end
    end

    test "rejects a client authentication method the server does not advertise" do
      restricted = context(%{"token_endpoint_auth_methods_supported" => ["none"]})

      assert {:error, :unsupported_token_endpoint_auth_method} =
               MCPAuthorization.select_registration(restricted,
                 pre_registered: %{
                   @issuer => %{
                     client_id: "client",
                     client_auth: {:client_secret_basic, "secret"}
                   }
                 }
               )
    end

    test "uses opt-in dynamic registration after CIMD and before prompting" do
      parent = self()

      plug = fn conn ->
        assert conn.request_path == "/tenant/register"
        {:ok, body, conn} = Plug.Conn.read_body(conn)
        metadata = JSON.decode!(body)

        assert metadata == %{
                 "application_type" => "native",
                 "client_name" => "Conformance Client",
                 "grant_types" => ["authorization_code", "refresh_token"],
                 "redirect_uris" => ["http://127.0.0.1:45123/callback"],
                 "response_types" => ["code"],
                 "token_endpoint_auth_method" => "client_secret_basic"
               }

        json(conn, 201, %{
          "client_id" => "dynamic-client",
          "client_secret" => "dynamic-secret"
        })
      end

      assert {:ok,
              %Registration{
                issuer: @issuer,
                client_id: "dynamic-client",
                client_auth: {:client_secret_basic, "dynamic-secret"},
                source: :dynamic
              }} =
               MCPAuthorization.select_registration(
                 context(%{"registration_endpoint" => @issuer <> "/register"}),
                 dynamic_registration: [
                   client_name: "Conformance Client",
                   redirect_uris: ["http://127.0.0.1:45123/callback"],
                   application_type: :native
                 ],
                 prompt: fn _issuer, _metadata ->
                   send(parent, :prompted)
                   %{client_id: "prompted"}
                 end,
                 req_options: [plug: plug]
               )

      refute_receive :prompted
    end

    test "honors the registered token authentication method" do
      for {method, response_method, secret, expected} <- [
            {"none", nil, "ignored", :none},
            {"client_secret_post", "client_secret_post", "secret",
             {:client_secret_post, "secret"}}
          ] do
        plug = fn conn ->
          json(
            conn,
            201,
            %{"client_id" => "dynamic"}
            |> then(fn response ->
              if secret, do: Map.put(response, "client_secret", secret), else: response
            end)
            |> then(fn response ->
              if response_method,
                do: Map.put(response, "token_endpoint_auth_method", response_method),
                else: response
            end)
          )
        end

        assert {:ok, %Registration{client_auth: ^expected}} =
                 MCPAuthorization.select_registration(
                   context(%{
                     "registration_endpoint" => @issuer <> "/register",
                     "token_endpoint_auth_methods_supported" => [method]
                   }),
                   dynamic_registration: %{
                     client_name: "Client",
                     redirect_uris: [@redirect],
                     application_type: "web"
                   },
                   req_options: [plug: plug]
                 )
      end
    end

    test "re-registers dynamically after authorization-server migration" do
      previous = registration(%{issuer: "https://old.example", source: :dynamic})

      plug = fn conn ->
        json(conn, 201, %{
          "client_id" => "new-client",
          "client_secret" => "new-secret"
        })
      end

      assert {:ok, %Registration{issuer: @issuer, client_id: "new-client", source: :dynamic}} =
               MCPAuthorization.select_registration(
                 context(%{"registration_endpoint" => @issuer <> "/register"}),
                 registration: previous,
                 dynamic_registration: [
                   client_name: "Client",
                   redirect_uris: [@redirect],
                   application_type: :web
                 ],
                 req_options: [plug: plug]
               )
    end

    test "does not register unless explicitly configured" do
      plug = fn _conn -> flunk("registration request must not run") end

      assert {:error, :client_registration_required} =
               MCPAuthorization.select_registration(
                 context(%{"registration_endpoint" => @issuer <> "/register"}),
                 req_options: [plug: plug]
               )
    end

    test "rejects incomplete dynamic-registration configuration before transport" do
      plug = fn _conn -> flunk("registration request must not run") end

      assert {:error, :invalid_dynamic_registration} =
               MCPAuthorization.select_registration(
                 context(%{"registration_endpoint" => @issuer <> "/register"}),
                 dynamic_registration: [client_name: "Client", redirect_uris: [@redirect]],
                 req_options: [plug: plug]
               )
    end

    test "rejects custom-scheme redirects and HTTP redirects for web clients" do
      plug = fn _conn -> flunk("registration request must not run") end
      ctx = context(%{"registration_endpoint" => @issuer <> "/register"})

      for {application_type, redirect_uri} <- [
            {:native, "com.example.app:/callback"},
            {:web, "http://127.0.0.1:45123/callback"},
            {:web, "http://client.example.com/callback"}
          ] do
        assert {:error, :invalid_dynamic_registration} =
                 MCPAuthorization.select_registration(ctx,
                   dynamic_registration: [
                     client_name: "Client",
                     redirect_uris: [redirect_uri],
                     application_type: application_type
                   ],
                   req_options: [plug: plug]
                 )
      end
    end

    test "does not let a deployed issuer use a loopback registration exception" do
      plug = fn _conn -> flunk("registration request must not run") end

      assert {:error, :invalid_outbound} =
               MCPAuthorization.select_registration(
                 context(%{"registration_endpoint" => "http://127.0.0.1:45123/register"}),
                 dynamic_registration: [
                   client_name: "Client",
                   redirect_uris: [@redirect],
                   application_type: :web
                 ],
                 outbound: [allow_loopback_http: true],
                 req_options: [plug: plug]
               )
    end
  end

  describe "authorization and refresh" do
    test "rejects DPoP options before authorization state or HTTP" do
      plug = fn _conn -> flunk("request must not run") end

      assert {:error, :unsupported_token_type} =
               MCPAuthorization.start(context(), registration(), :return,
                 redirect_uri: @redirect,
                 browser_binding: "browser",
                 dpop: :not_allowed,
                 req_options: [plug: plug]
               )
    end

    test "pins MCP resource and scopes through authorization and token exchange" do
      ctx = context()
      reg = registration()

      assert {:ok, started} =
               MCPAuthorization.start(ctx, reg, :return,
                 redirect_uri: @redirect,
                 browser_binding: "browser"
               )

      query = started.url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
      assert query["resource"] == @resource
      assert query["scope"] == "tools:read"
      assert query["code_challenge_method"] == "S256"

      plug = fn conn ->
        {pairs, conn} = form(conn)
        assert {"resource", @resource} in pairs
        assert {"client_id", reg.client_id} in pairs
        json(conn, 200, %{"access_token" => "access", "token_type" => "bearer"})
      end

      assert {:ok,
              %{
                tokens: %TokenSet{
                  access_token: "access",
                  scope: "tools:read",
                  resources: [@resource]
                },
                id_token_claims: nil
              }} =
               MCPAuthorization.callback(
                 ctx,
                 reg,
                 :return,
                 %{"state" => started.state, "code" => "code"},
                 transaction: started.transaction,
                 browser_binding: "browser",
                 req_options: [plug: plug]
               )
    end

    test "rejects a non-Bearer token response" do
      ctx = context()
      reg = registration()

      assert {:ok, started} =
               MCPAuthorization.start(ctx, reg, :return,
                 redirect_uri: @redirect,
                 browser_binding: "browser"
               )

      plug = fn conn ->
        json(conn, 200, %{"access_token" => "access", "token_type" => "MAC"})
      end

      assert {:error, :unsupported_token_type} =
               MCPAuthorization.callback(
                 ctx,
                 reg,
                 :return,
                 %{"state" => started.state, "code" => "code"},
                 transaction: started.transaction,
                 browser_binding: "browser",
                 req_options: [plug: plug]
               )
    end

    test "rejects a DPoP callback option before code redemption" do
      ctx = context()
      reg = registration()

      assert {:ok, started} =
               MCPAuthorization.start(ctx, reg, :return,
                 redirect_uri: @redirect,
                 browser_binding: "browser"
               )

      plug = fn _conn -> flunk("token request must not run") end

      assert {:error, :unsupported_token_type} =
               MCPAuthorization.callback(
                 ctx,
                 reg,
                 :return,
                 %{"state" => started.state, "code" => "code"},
                 transaction: started.transaction,
                 browser_binding: "browser",
                 dpop: :not_allowed,
                 req_options: [plug: plug]
               )
    end

    test "rejects a callback under a different MCP context before token HTTP" do
      original_context = context()
      original_registration = registration()

      assert {:ok, started} =
               MCPAuthorization.start(original_context, original_registration, :return,
                 redirect_uri: @redirect,
                 browser_binding: "browser"
               )

      other_issuer = "https://other.example.com"

      other_context =
        context(
          %{
            "issuer" => other_issuer,
            "authorization_endpoint" => other_issuer <> "/authorize",
            "token_endpoint" => other_issuer <> "/token"
          },
          %{
            issuer: other_issuer,
            resource: "https://other-mcp.example.com/mcp"
          }
        )

      other_registration = registration(%{issuer: other_issuer, client_id: "other-client"})
      plug = fn _conn -> flunk("token request must not run") end

      assert {:error, :transaction_binding_mismatch} =
               MCPAuthorization.callback(
                 other_context,
                 other_registration,
                 :return,
                 %{"state" => started.state, "code" => "code"},
                 transaction: started.transaction,
                 browser_binding: "browser",
                 req_options: [plug: plug]
               )
    end

    test "refreshes without OIDC inputs, repeats the resource, and keeps Bearer-only policy" do
      coordinator = start_supervised!(RefreshCoordinator)
      ctx = context()
      reg = registration()

      tokens = %TokenSet{
        access_token: "old",
        token_type: "Bearer",
        refresh_token: "refresh",
        scope: "tools:read",
        resources: [@resource],
        issuer: @issuer,
        client_id: reg.client_id
      }

      plug = fn conn ->
        {pairs, conn} = form(conn)
        assert {"resource", @resource} in pairs
        assert {"client_id", reg.client_id} in pairs
        json(conn, 200, %{"access_token" => "new", "token_type" => "Bearer"})
      end

      assert {:ok,
              %RefreshResult{
                tokens: %TokenSet{
                  access_token: "new",
                  scope: "tools:read",
                  resources: [@resource]
                },
                id_token_claims: nil
              }} =
               MCPAuthorization.refresh(ctx, reg, coordinator, :account, tokens,
                 req_options: [plug: plug]
               )
    end

    test "preflights refresh authentication and Bearer-only policy" do
      coordinator = start_supervised!(RefreshCoordinator)
      plug = fn _conn -> flunk("refresh request must not run") end

      tokens = %TokenSet{
        access_token: "old",
        token_type: "Bearer",
        refresh_token: "refresh",
        resources: [@resource],
        issuer: @issuer,
        client_id: "mcp-client"
      }

      assert {:error, :unsupported_token_endpoint_auth_method} =
               MCPAuthorization.refresh(
                 context(%{"token_endpoint_auth_methods_supported" => ["none"]}),
                 registration(%{client_auth: {:client_secret_basic, "secret"}}),
                 coordinator,
                 :unsupported_auth,
                 tokens,
                 req_options: [plug: plug]
               )

      assert {:error, :unsupported_token_type} =
               MCPAuthorization.refresh(
                 context(),
                 registration(),
                 coordinator,
                 :dpop_token,
                 %{tokens | token_type: "DPoP"},
                 req_options: [plug: plug]
               )

      assert {:error, :unsupported_token_type} =
               MCPAuthorization.refresh(
                 context(),
                 registration(),
                 coordinator,
                 :dpop_option,
                 tokens,
                 dpop: :not_allowed,
                 req_options: [plug: plug]
               )
    end
  end

  describe "transport-facing policy" do
    test "builds a Bearer header and rejects another token type" do
      assert {:ok, {"authorization", "Bearer token"}} =
               MCPAuthorization.authorization_header(
                 context(),
                 %TokenSet{
                   access_token: "token",
                   token_type: "bearer",
                   issuer: @issuer,
                   resources: [@resource]
                 }
               )

      assert {:error, :unsupported_token_type} =
               MCPAuthorization.authorization_header(
                 context(),
                 %TokenSet{
                   access_token: "token",
                   token_type: "DPoP",
                   issuer: @issuer,
                   resources: [@resource]
                 }
               )

      assert {:error, :unsupported_token_type} =
               MCPAuthorization.authorization_header(
                 context(),
                 %TokenSet{
                   access_token: "token",
                   token_type: "Bearer",
                   dpop_jkt: "unexpected-binding",
                   issuer: @issuer,
                   resources: [@resource]
                 }
               )

      assert {:error, :token_binding_mismatch} =
               MCPAuthorization.authorization_header(
                 context(),
                 %TokenSet{
                   access_token: "token",
                   token_type: "Bearer",
                   issuer: @issuer,
                   resources: ["https://other.example/mcp"]
                 }
               )
    end

    test "unions step-up scopes and stops at the retry limit" do
      challenge = ~s(Bearer error="insufficient_scope", scope="files:write tools:read")

      assert {:ok, first} = MCPAuthorization.step_up(context(), challenge)
      assert first.scopes == ["tools:read", "files:write"]
      assert first.scope_attempts == 1

      assert {:ok, second} = MCPAuthorization.step_up(first, challenge)
      assert second.scopes == first.scopes
      assert second.scope_attempts == 2

      assert {:error, :scope_retry_limit} = MCPAuthorization.step_up(second, challenge)

      assert {:error, :not_insufficient_scope} =
               MCPAuthorization.step_up(context(), ~s(Bearer error="invalid_token"))
    end
  end

  defp cimd_document do
    %{
      "client_id" => "https://client.example.com/oauth/client.json",
      "client_name" => "Example MCP Client",
      "redirect_uris" => [@redirect],
      "grant_types" => ["authorization_code", "refresh_token"],
      "response_types" => ["code"],
      "token_endpoint_auth_method" => "none"
    }
  end
end
