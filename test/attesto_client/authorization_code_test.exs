defmodule AttestoClient.AuthorizationCodeTest do
  use ExUnit.Case, async: true

  alias AttestoClient.AuthorizationCode
  alias AttestoClient.AuthorizationTransaction.Store.ETS
  alias AttestoClient.PKCE

  @issuer "https://op.example.com"
  @client_id "client-123"
  @redirect_uri "https://rp.example.com/callback"
  @browser_binding "opaque-browser-binding"
  @now System.system_time(:second)
  @key JOSE.JWK.generate_key({:rsa, 2048})

  defp metadata(overrides \\ %{}) do
    Map.merge(
      %{
        "issuer" => @issuer,
        "authorization_endpoint" => "#{@issuer}/authorize",
        "token_endpoint" => "#{@issuer}/token",
        "jwks_uri" => "#{@issuer}/jwks",
        "response_types_supported" => ["code"],
        "subject_types_supported" => ["public"],
        "id_token_signing_alg_values_supported" => ["RS256"],
        "code_challenge_methods_supported" => ["S256"]
      },
      overrides
    )
  end

  defp start_flow(store, opts \\ []) do
    AuthorizationCode.start(
      {ETS, store},
      Keyword.merge(
        [
          issuer: @issuer,
          client_id: @client_id,
          browser_binding: @browser_binding,
          redirect_uri: @redirect_uri,
          metadata: metadata()
        ],
        opts
      )
    )
  end

  defp callback(store, params, opts \\ []) do
    AuthorizationCode.callback(
      store,
      params,
      Keyword.put_new(opts, :browser_binding, @browser_binding)
    )
  end

  defp public_jwks do
    {_, map} = JOSE.JWK.to_public_map(@key)
    %{"keys" => [Map.merge(map, %{"kid" => "signing", "alg" => "RS256", "use" => "sig"})]}
  end

  defp id_token(nonce, access_token, overrides) do
    claims =
      Map.merge(
        %{
          "iss" => @issuer,
          "sub" => "subject-1",
          "aud" => @client_id,
          "iat" => @now,
          "exp" => @now + 600,
          "nonce" => nonce,
          "at_hash" => hash_claim(access_token)
        },
        overrides
      )

    {_, jwt} =
      @key
      |> JOSE.JWT.sign(%{"alg" => "RS256", "kid" => "signing", "typ" => "JWT"}, claims)
      |> JOSE.JWS.compact()

    jwt
  end

  defp hash_claim(value) do
    :sha256
    |> :crypto.hash(value)
    |> binary_part(0, 16)
    |> Base.url_encode64(padding: false)
  end

  test "starts code flow with unguessable state, nonce, and S256 PKCE" do
    store = start_supervised!(ETS)
    assert {:ok, started} = start_flow(store, scopes: ["openid", "profile"])

    params = started.url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
    assert URI.parse(started.url).path == "/authorize"
    assert params["response_type"] == "code"
    assert params["client_id"] == @client_id
    assert params["redirect_uri"] == @redirect_uri
    assert params["scope"] == "openid profile"
    assert params["code_challenge_method"] == "S256"
    assert byte_size(params["state"]) >= 43
    assert byte_size(params["nonce"]) >= 43
    assert byte_size(params["code_challenge"]) == 43
  end

  test "accepts RS256-free metadata only when the selected ID-token algorithm is advertised" do
    store = start_supervised!(ETS)
    es256_only = metadata(%{"id_token_signing_alg_values_supported" => ["ES256"]})

    assert {:ok, _started} =
             start_flow(store, metadata: es256_only, id_token_alg: "ES256")

    assert {:error, :unsupported_alg} = start_flow(store, metadata: es256_only)
  end

  test "rejects reserved overrides and malformed discovery" do
    store = start_supervised!(ETS)

    assert {:error, :invalid_authorization_params} =
             start_flow(store, authorization_params: %{"state" => "attacker"})

    assert {:error, :invalid_metadata} =
             start_flow(store, metadata: Map.delete(metadata(), "token_endpoint"))

    assert {:error, :issuer_mismatch} =
             start_flow(store, metadata: %{metadata() | "issuer" => "https://other.example"})

    assert {:error, :invalid_metadata} =
             start_flow(store,
               metadata: %{metadata() | "code_challenge_methods_supported" => ["plain"]}
             )

    Enum.each(
      [
        "http://op.example.com",
        "https://user@op.example.com",
        "https://op.example.com?query=1",
        "https://op.example.com#fragment",
        "not-a-url"
      ],
      fn invalid_issuer ->
        assert {:error, :invalid_issuer} =
                 start_flow(store,
                   issuer: invalid_issuer,
                   metadata: %{metadata() | "issuer" => invalid_issuer}
                 )
      end
    )
  end

  test "requires and atomically consumes opaque browser-session binding" do
    store = start_supervised!(ETS)

    assert {:error, :missing_browser_binding} =
             start_flow(store, browser_binding: nil)

    assert {:ok, wrong} = start_flow(store)

    assert {:error, :browser_binding_mismatch} =
             AuthorizationCode.callback(
               {ETS, store},
               %{"state" => wrong.state, "code" => "code"},
               browser_binding: "different-browser-session"
             )

    assert {:error, {:invalid_state, :not_found}} =
             callback({ETS, store}, %{"state" => wrong.state, "code" => "code"})

    assert {:ok, missing} = start_flow(store)

    assert {:error, :missing_browser_binding} =
             AuthorizationCode.callback(
               {ETS, store},
               %{"state" => missing.state, "code" => "code"}
             )

    assert {:error, {:invalid_state, :not_found}} =
             callback({ETS, store}, %{"state" => missing.state, "code" => "code"})
  end

  test "allows HTTP redirect URIs only for loopback hosts" do
    store = start_supervised!(ETS)

    Enum.each(
      [
        "http://127.0.0.1/callback",
        "http://127.255.12.34:49152/callback",
        "http://[::1]:49152/callback",
        "http://localhost:49152/callback",
        "https://rp.example.com/callback"
      ],
      fn redirect_uri ->
        assert {:ok, _started} = start_flow(store, redirect_uri: redirect_uri)
      end
    )

    Enum.each(
      [
        "http://rp.example.com/callback",
        "http://192.168.1.10/callback",
        "http://localhost.example.com/callback",
        "http://[::2]/callback"
      ],
      fn redirect_uri ->
        assert {:error, :invalid_redirect_uri} = start_flow(store, redirect_uri: redirect_uri)
      end
    )
  end

  test "exchanges once and binds issuer, nonce, access token, and PKCE verifier" do
    store = start_supervised!(ETS)
    assert {:ok, started} = start_flow(store)
    query = started.url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
    parent = self()

    plug = fn conn ->
      case conn.request_path do
        "/token" ->
          {:ok, body, conn} = Plug.Conn.read_body(conn)
          form = URI.decode_query(body)
          send(parent, {:token_form, form})
          access_token = "access-1"

          conn
          |> Plug.Conn.put_resp_content_type("application/json")
          |> Plug.Conn.send_resp(
            200,
            JSON.encode!(%{
              "access_token" => access_token,
              "token_type" => "Bearer",
              "refresh_token" => "refresh-1",
              "id_token" =>
                id_token(query["nonce"], access_token, %{"c_hash" => hash_claim("code-1")})
            })
          )

        "/jwks" ->
          conn
          |> Plug.Conn.put_resp_content_type("application/json")
          |> Plug.Conn.send_resp(200, JSON.encode!(public_jwks()))
      end
    end

    assert {:ok, result} =
             callback(
               {ETS, store},
               %{"state" => started.state, "code" => "code-1", "iss" => @issuer},
               req_options: [plug: plug],
               timeout: 30_000
             )

    assert result.tokens.refresh_token == "refresh-1"
    assert result.id_token_claims["sub"] == "subject-1"

    assert_receive {:token_form, form}
    assert form["grant_type"] == "authorization_code"
    assert form["code"] == "code-1"
    assert form["redirect_uri"] == @redirect_uri
    assert byte_size(form["code_verifier"]) == 43
    assert {:ok, query["code_challenge"]} == PKCE.code_challenge(form["code_verifier"])

    assert {:error, {:invalid_state, :not_found}} =
             callback(
               {ETS, store},
               %{"state" => started.state, "code" => "code-1"},
               req_options: [plug: plug]
             )
  end

  test "issuer aliases given at start widen only the ID Token iss check" do
    alias_iss = "op.example.com"

    plug_for = fn nonce ->
      fn conn ->
        case conn.request_path do
          "/token" ->
            conn
            |> Plug.Conn.put_resp_content_type("application/json")
            |> Plug.Conn.send_resp(
              200,
              JSON.encode!(%{
                "access_token" => "access-1",
                "token_type" => "Bearer",
                "id_token" => id_token(nonce, "access-1", %{"iss" => alias_iss})
              })
            )

          "/jwks" ->
            conn
            |> Plug.Conn.put_resp_content_type("application/json")
            |> Plug.Conn.send_resp(200, JSON.encode!(public_jwks()))
        end
      end
    end

    nonce = fn started ->
      started.url
      |> URI.parse()
      |> Map.fetch!(:query)
      |> URI.decode_query()
      |> Map.fetch!("nonce")
    end

    store = start_supervised!(ETS)

    # Without the opt-in, an ID Token whose iss is the alias is refused.
    assert {:ok, strict} = start_flow(store)

    assert {:error, :invalid_issuer} =
             callback(
               {ETS, store},
               %{"state" => strict.state, "code" => "code-1", "iss" => @issuer},
               req_options: [plug: plug_for.(nonce.(strict))],
               timeout: 30_000
             )

    assert {:error, :invalid_issuer_aliases} = start_flow(store, issuer_aliases: "op.example.com")

    # With it, the alias is accepted in the ID Token.
    assert {:ok, started} = start_flow(store, issuer_aliases: [alias_iss])

    assert {:ok, result} =
             callback(
               {ETS, store},
               %{"state" => started.state, "code" => "code-1", "iss" => @issuer},
               req_options: [plug: plug_for.(nonce.(started))],
               timeout: 30_000
             )

    assert result.id_token_claims["iss"] == alias_iss

    # The RFC 9207 authorization-response iss stays pinned to :issuer.
    assert {:ok, pinned} = start_flow(store, issuer_aliases: [alias_iss])

    assert {:error, _issuer_mismatch} =
             callback(
               {ETS, store},
               %{"state" => pinned.state, "code" => "code-1", "iss" => alias_iss},
               req_options: [plug: plug_for.(nonce.(pinned))],
               timeout: 30_000
             )
  end

  test "sends RFC 8707 resource indicators on the authorization and token requests" do
    store = start_supervised!(ETS)
    resources = ["https://rs.example/mcp", "https://files.example/api?tenant=a"]
    parent = self()

    # The stub token endpoint mints an ID Token for the flow's nonce, so each
    # exchange gets a plug that closes over the started request.
    exchange = fn started, callback_opts ->
      nonce =
        started.url
        |> URI.parse()
        |> Map.fetch!(:query)
        |> URI.decode_query()
        |> Map.fetch!("nonce")

      plug = fn conn ->
        case conn.request_path do
          "/token" ->
            {:ok, body, conn} = Plug.Conn.read_body(conn)
            send(parent, {:token_body, body})

            conn
            |> Plug.Conn.put_resp_content_type("application/json")
            |> Plug.Conn.send_resp(
              200,
              JSON.encode!(%{
                "access_token" => "access-1",
                "token_type" => "Bearer",
                "id_token" => id_token(nonce, "access-1", %{"c_hash" => hash_claim("code-1")})
              })
            )

          "/jwks" ->
            conn
            |> Plug.Conn.put_resp_content_type("application/json")
            |> Plug.Conn.send_resp(200, JSON.encode!(public_jwks()))
        end
      end

      callback(
        {ETS, store},
        %{"state" => started.state, "code" => "code-1", "iss" => @issuer},
        [req_options: [plug: plug], timeout: 30_000] ++ callback_opts
      )
    end

    assert {:ok, started} = start_flow(store, resource: resources)
    query = started.url |> URI.parse() |> Map.fetch!(:query)
    assert query_values(query, "resource") == resources

    assert {:ok, _result} = exchange.(started, [])
    assert_receive {:token_body, body}
    assert query_values(body, "resource") == resources
    assert URI.decode_query(body)["grant_type"] == "authorization_code"

    # The token request may narrow to a subset of what was authorized.
    assert {:ok, narrowed} = start_flow(store, resource: resources)
    assert {:ok, _result} = exchange.(narrowed, resource: "https://rs.example/mcp")
    assert_receive {:token_body, body}
    assert query_values(body, "resource") == ["https://rs.example/mcp"]

    # A single indicator is sent once, and a flow without one sends none.
    assert {:ok, single} = start_flow(store, resource: "https://rs.example/mcp")

    assert query_values(single.url |> URI.parse() |> Map.fetch!(:query), "resource") ==
             ["https://rs.example/mcp"]

    assert {:ok, none} = start_flow(store)
    assert query_values(none.url |> URI.parse() |> Map.fetch!(:query), "resource") == []
    assert {:ok, _result} = exchange.(none, [])
    assert_receive {:token_body, body}
    assert query_values(body, "resource") == []

    # A resource passed as an authorization parameter, as earlier releases
    # documented, reaches the token request as well.
    assert {:ok, legacy} =
             start_flow(store, authorization_params: %{"resource" => "https://rs.example/mcp"})

    assert query_values(legacy.url |> URI.parse() |> Map.fetch!(:query), "resource") ==
             ["https://rs.example/mcp"]

    assert {:ok, _result} = exchange.(legacy, [])
    assert_receive {:token_body, body}
    assert query_values(body, "resource") == ["https://rs.example/mcp"]
  end

  test "rejects malformed resource indicators and resource outside the authorized set" do
    store = start_supervised!(ETS)
    no_request = fn _conn -> flunk("no token request expected") end

    for bad <- ["", "not a uri", "https://rs.example/mcp#frag", ["https://rs.example", 1], []] do
      assert {:error, :invalid_resource} = start_flow(store, resource: bad), inspect(bad)
    end

    # An authorization parameter is read as the same indicator, so it is
    # validated too; supplying it in both places is ambiguous.
    assert {:error, :invalid_resource} =
             start_flow(store, authorization_params: %{"resource" => "not a uri"})

    assert {:error, :invalid_authorization_params} =
             start_flow(store,
               resource: "https://rs.example/mcp",
               authorization_params: %{"resource" => "https://rs.example/mcp"}
             )

    assert {:ok, started} = start_flow(store, resource: "https://rs.example/mcp")

    assert {:error, :invalid_resource} =
             callback(
               {ETS, store},
               %{"state" => started.state, "code" => "code-1", "iss" => @issuer},
               resource: "https://other.example/api",
               req_options: [plug: no_request]
             )

    # The transaction was consumed by the refused callback.
    assert {:error, {:invalid_state, :not_found}} =
             callback({ETS, store}, %{"state" => started.state, "code" => "code-1"},
               req_options: [plug: no_request]
             )

    assert {:ok, unpinned} = start_flow(store)

    assert {:error, :invalid_resource} =
             callback(
               {ETS, store},
               %{"state" => unpinned.state, "code" => "code-1", "iss" => @issuer},
               resource: "https://rs.example/mcp",
               req_options: [plug: no_request]
             )
  end

  defp query_values(query, name) do
    query
    |> URI.query_decoder()
    |> Enum.filter(&(elem(&1, 0) == name))
    |> Enum.map(&elem(&1, 1))
  end

  test "forwards the callback resolver to the stored metadata's JWKS fetch" do
    store = start_supervised!(ETS)
    assert {:ok, started} = start_flow(store)
    parent = self()

    resolver = fn host, family ->
      send(parent, {:resolved, List.to_string(host), family})
      {:ok, [{127, 0, 0, 1}]}
    end

    assert {:error, :blocked_host} =
             callback(
               {ETS, store},
               %{"state" => started.state, "code" => "code"},
               resolver: resolver,
               timeout: 1_000
             )

    assert_receive {:resolved, "op.example.com", :inet}
    assert_receive {:resolved, "op.example.com", :inet6}
  end

  test "forwards the callback response-size bound to the stored JWKS fetch" do
    store = start_supervised!(ETS)
    assert {:ok, started} = start_flow(store)

    plug = fn conn ->
      case conn.request_path do
        "/jwks" ->
          body = Map.put(public_jwks(), "padding", String.duplicate("x", 256))

          conn
          |> Plug.Conn.put_resp_content_type("application/json")
          |> Plug.Conn.send_resp(200, JSON.encode!(body))

        "/token" ->
          flunk("the token request must not run after an oversized JWKS response")
      end
    end

    assert {:error, :response_too_large} =
             callback(
               {ETS, store},
               %{"state" => started.state, "code" => "code"},
               req_options: [plug: plug],
               max_response_bytes: 64
             )
  end

  test "validates c_hash when present and permits omission at the token endpoint" do
    store = start_supervised!(ETS)

    Enum.each([{%{}, :ok}, {%{"c_hash" => hash_claim("different-code")}, :invalid_c_hash}], fn
      {claim_overrides, expectation} ->
        assert {:ok, started} = start_flow(store)
        query = started.url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
        access_token = "access"

        plug = fn conn ->
          case conn.request_path do
            "/jwks" ->
              conn
              |> Plug.Conn.put_resp_content_type("application/json")
              |> Plug.Conn.send_resp(200, JSON.encode!(public_jwks()))

            "/token" ->
              json = %{
                "access_token" => access_token,
                "token_type" => "Bearer",
                "id_token" => id_token(query["nonce"], access_token, claim_overrides)
              }

              conn
              |> Plug.Conn.put_resp_content_type("application/json")
              |> Plug.Conn.send_resp(200, JSON.encode!(json))
          end
        end

        result =
          callback(
            {ETS, store},
            %{"state" => started.state, "code" => "code"},
            req_options: [plug: plug]
          )

        case expectation do
          :ok -> assert {:ok, _completed} = result
          error -> assert {:error, ^error} = result
        end
    end)
  end

  test "enforces authorization-request max_age against callback auth_time" do
    store = start_supervised!(ETS)

    assert {:error, :invalid_max_age} =
             start_flow(store, authorization_params: %{"max_age" => "not-a-number"})

    Enum.each([{@now - 30, :ok}, {@now - 120, :max_age_exceeded}], fn
      {auth_time, expectation} ->
        assert {:ok, started} =
                 start_flow(store, authorization_params: %{"max_age" => "60"})

        query = started.url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
        access_token = "access"

        plug = fn conn ->
          case conn.request_path do
            "/jwks" ->
              conn
              |> Plug.Conn.put_resp_content_type("application/json")
              |> Plug.Conn.send_resp(200, JSON.encode!(public_jwks()))

            "/token" ->
              response = %{
                "access_token" => access_token,
                "token_type" => "Bearer",
                "id_token" => id_token(query["nonce"], access_token, %{"auth_time" => auth_time})
              }

              conn
              |> Plug.Conn.put_resp_content_type("application/json")
              |> Plug.Conn.send_resp(200, JSON.encode!(response))
          end
        end

        result =
          callback(
            {ETS, store},
            %{"state" => started.state, "code" => "code"},
            req_options: [plug: plug]
          )

        case expectation do
          :ok -> assert {:ok, _completed} = result
          error -> assert {:error, ^error} = result
        end
    end)
  end

  test "consumes state for authorization errors, mixed responses, issuer confusion, and expiry" do
    store = start_supervised!(ETS)

    assert {:ok, first} = start_flow(store)

    assert {:error, {:authorization_error, "access_denied", nil}} =
             callback(
               {ETS, store},
               %{"state" => first.state, "error" => "access_denied"}
             )

    assert {:error, {:invalid_state, :not_found}} =
             callback(
               {ETS, store},
               %{"state" => first.state, "code" => "code"}
             )

    assert {:ok, mixed} = start_flow(store)

    assert {:error, :mixed_authorization_response} =
             callback(
               {ETS, store},
               %{"state" => mixed.state, "code" => "code", "error" => "denied"}
             )

    assert {:ok, wrong_issuer} = start_flow(store)

    assert {:error, :issuer_mismatch} =
             callback(
               {ETS, store},
               %{"state" => wrong_issuer.state, "code" => "code", "iss" => "https://evil.example"}
             )

    assert {:ok, required_issuer} =
             start_flow(store,
               metadata: metadata(%{"authorization_response_iss_parameter_supported" => true})
             )

    assert {:error, :missing_response_issuer} =
             callback(
               {ETS, store},
               %{"state" => required_issuer.state, "code" => "code"}
             )

    assert {:ok, expired} = start_flow(store, transaction_ttl_ms: 100)
    assert expired.expires_in == 1
    Process.sleep(110)

    assert {:error, {:invalid_state, :expired}} =
             callback(
               {ETS, store},
               %{"state" => expired.state, "code" => "code"}
             )
  end

  test "rejects duplicate parameters in the original callback before consuming state" do
    store = start_supervised!(ETS)
    assert {:ok, started} = start_flow(store)

    callback_uri =
      "https://rp.example.com/callback?state=#{started.state}&code=first&co%64e=second"

    assert {:error, {:duplicate_callback_parameter, "code"}} =
             callback({ETS, store}, callback_uri)

    # Ambiguity is rejected before the one-time transaction is taken.
    assert {:error, :browser_binding_mismatch} =
             AuthorizationCode.callback(
               {ETS, store},
               %{"state" => started.state, "code" => "code"},
               browser_binding: "different-browser"
             )
  end

  test "accepts an unambiguous raw callback query" do
    store = start_supervised!(ETS)
    assert {:ok, started} = start_flow(store)

    assert {:error, :browser_binding_mismatch} =
             AuthorizationCode.callback(
               {ETS, store},
               "state=#{started.state}&code=code",
               browser_binding: "different-browser"
             )

    assert {:error, {:invalid_state, :not_found}} =
             callback({ETS, store}, %{"state" => started.state, "code" => "code"})
  end

  test "rejects duplicate state, error metadata, and nested-name aliases in encoded responses" do
    store = start_supervised!(ETS)

    for encoded <- [
          "state=first&st%61te=second&code=code",
          "state=state&error=denied&error_description=first&error_description=second",
          "state=state&code=first&code[]=second"
        ] do
      assert {:error, {:duplicate_callback_parameter, _parameter}} =
               callback({ETS, store}, encoded)
    end
  end

  test "rejects malformed callback locations and bounds encoded callback input" do
    store = start_supervised!(ETS)

    assert {:error, :invalid_callback} =
             callback({ETS, store}, "https://rp.example.com/callback#code=code&state=state")

    assert {:error, :invalid_callback} =
             callback({ETS, store}, "code=" <> String.duplicate("a", 1_000_000))
  end

  test "a token-endpoint timeout is bounded, never retried, and consumes state" do
    store = start_supervised!(ETS)
    counter = start_supervised!({Agent, fn -> 0 end})
    assert {:ok, started} = start_flow(store)

    plug = fn conn ->
      case conn.request_path do
        "/jwks" ->
          conn
          |> Plug.Conn.put_resp_content_type("application/json")
          |> Plug.Conn.send_resp(200, JSON.encode!(public_jwks()))

        "/token" ->
          Agent.update(counter, &(&1 + 1))
          # See token_test's "deadline wakes all waiters": the plug sleeps far
          # longer than the deadline so the deadline (not the response) always
          # wins, and the deadline stays short so `:timeout` is reliable under load.
          Process.sleep(30_000)
          Plug.Conn.send_resp(conn, 500, "late")
      end
    end

    assert {:error, :timeout} =
             callback(
               {ETS, store},
               %{"state" => started.state, "code" => "code"},
               req_options: [plug: plug],
               timeout: 500
             )

    # At most one = not retried; load-immune (a starved worker killed by the
    # deadline before reaching the plug leaves the counter at 0, so `== 1` flakes).
    assert Agent.get(counter, & &1) <= 1

    assert {:error, {:invalid_state, :not_found}} =
             callback(
               {ETS, store},
               %{"state" => started.state, "code" => "code"}
             )
  end

  describe "a transaction kept by the caller (start/2 with :return)" do
    defp token_plug(nonce, overrides \\ %{}) do
      parent = self()

      fn conn ->
        case conn.request_path do
          "/token" ->
            {:ok, body, conn} = Plug.Conn.read_body(conn)
            send(parent, {:token_request, URI.decode_query(body)})

            conn
            |> Plug.Conn.put_resp_content_type("application/json")
            |> Plug.Conn.send_resp(
              200,
              JSON.encode!(%{
                "access_token" => "access-1",
                "token_type" => "Bearer",
                "id_token" => id_token(nonce, "access-1", overrides)
              })
            )

          "/jwks" ->
            conn
            |> Plug.Conn.put_resp_content_type("application/json")
            |> Plug.Conn.send_resp(200, JSON.encode!(public_jwks()))
        end
      end
    end

    defp start_returned(opts \\ []) do
      AuthorizationCode.start(
        :return,
        Keyword.merge(
          [
            issuer: @issuer,
            client_id: @client_id,
            browser_binding: @browser_binding,
            redirect_uri: @redirect_uri,
            metadata: metadata()
          ],
          opts
        )
      )
    end

    test "start returns the transaction and callback completes from it with no store" do
      assert {:ok, %{transaction: transaction} = started} = start_returned()
      assert transaction.state == started.state
      assert is_integer(transaction.expires_at)

      # It survives the serialization a host would seal.
      transaction = transaction |> :erlang.term_to_binary() |> :erlang.binary_to_term()

      assert {:ok, result} =
               callback(:return, %{"state" => started.state, "code" => "code-1"},
                 transaction: transaction,
                 req_options: [plug: token_plug(transaction.nonce)],
                 timeout: 30_000
               )

      assert result.id_token_claims["sub"] == "subject-1"
      assert_received {:token_request, form}
      assert form["code"] == "code-1"
      assert form["code_verifier"] == transaction.code_verifier
      assert form["redirect_uri"] == @redirect_uri
    end

    test "a stored start result carries no transaction" do
      store = start_supervised!(ETS)
      assert {:ok, started} = start_flow(store)
      refute Map.has_key?(started, :transaction)
    end

    test "the same checks apply as on the stored path" do
      assert {:ok, %{transaction: transaction} = started} = start_returned()
      response = %{"state" => started.state, "code" => "code-1"}

      opts = [
        transaction: transaction,
        req_options: [plug: token_plug(transaction.nonce)],
        timeout: 30_000
      ]

      assert {:error, {:invalid_state, :not_found}} =
               callback(:return, %{response | "state" => "another-state"}, opts)

      assert {:error, :browser_binding_mismatch} =
               callback(:return, response, Keyword.put(opts, :browser_binding, "other-browser"))

      assert {:error, :issuer_mismatch} =
               callback(:return, Map.put(response, "iss", "https://other.example"), opts)

      wrong_nonce = Keyword.put(opts, :req_options, plug: token_plug("another-nonce"))
      assert {:error, :nonce_mismatch} = callback(:return, response, wrong_nonce)
    end

    test "an expired or malformed transaction is refused before the token request" do
      assert {:ok, %{transaction: transaction} = started} = start_returned()
      response = %{"state" => started.state, "code" => "code-1"}
      expired = %{transaction | expires_at: System.system_time(:millisecond) - 1}

      assert {:error, {:invalid_state, :expired}} =
               callback(:return, response, transaction: expired)

      assert {:error, :invalid_transaction} =
               callback(:return, response, transaction: %{state: started.state})

      assert {:error, :invalid_transaction} =
               callback(:return, response, transaction: %{transaction | expires_at: "soon"})

      assert {:error, :missing_transaction} = callback(:return, response)
      refute_received {:token_request, _form}
    end

    test "a returned transaction is not single use; the host owns that" do
      assert {:ok, %{transaction: transaction} = started} = start_returned()
      response = %{"state" => started.state, "code" => "code-1"}

      opts = [
        transaction: transaction,
        req_options: [plug: token_plug(transaction.nonce)],
        timeout: 30_000
      ]

      assert {:ok, _first} = callback(:return, response, opts)
      assert {:ok, _second} = callback(:return, response, opts)
    end

    test "transaction: takes precedence over a store and leaves it untouched" do
      store = start_supervised!(ETS)
      assert {:ok, stored} = start_flow(store)
      assert {:ok, %{transaction: transaction} = started} = start_returned()

      assert {:ok, _result} =
               callback({ETS, store}, %{"state" => started.state, "code" => "code-1"},
                 transaction: transaction,
                 req_options: [plug: token_plug(transaction.nonce)],
                 timeout: 30_000
               )

      # The stored transaction is still there to be taken.
      assert {:error, :missing_code} = callback({ETS, store}, %{"state" => stored.state})
    end

    test "callback forwards :max_token_age_seconds and :require_auth_time to ID Token verification" do
      assert {:ok, %{transaction: transaction} = started} = start_returned()
      response = %{"state" => started.state, "code" => "code-1"}

      old = [
        transaction: transaction,
        req_options: [plug: token_plug(transaction.nonce, %{"iat" => @now - 400})],
        timeout: 30_000
      ]

      assert {:ok, _result} = callback(:return, response, old)

      assert {:error, :token_too_old} =
               callback(:return, response, Keyword.put(old, :max_token_age_seconds, 60))

      assert {:error, :auth_time_required} =
               callback(:return, response, Keyword.put(old, :require_auth_time, true))
    end
  end

  describe "exchange/2" do
    test "sends the authorization-code token request and returns the token set" do
      parent = self()

      plug = fn conn ->
        {:ok, body, conn} = Plug.Conn.read_body(conn)
        send(parent, {:exchange, conn.request_path, URI.decode_query(body)})

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(
          200,
          JSON.encode!(%{
            "access_token" => "access-1",
            "token_type" => "Bearer",
            "refresh_token" => "refresh-1"
          })
        )
      end

      {:ok, verifier} = {:ok, PKCE.code_verifier()}

      assert {:ok, %AttestoClient.TokenSet{access_token: "access-1", refresh_token: "refresh-1"}} =
               AuthorizationCode.exchange("code-1",
                 token_endpoint: "#{@issuer}/token",
                 issuer: @issuer,
                 client_id: @client_id,
                 redirect_uri: @redirect_uri,
                 code_verifier: verifier,
                 resource: "https://rs.example/api",
                 req_options: [plug: plug],
                 timeout: 30_000
               )

      assert_received {:exchange, "/token", form}

      assert form == %{
               "grant_type" => "authorization_code",
               "code" => "code-1",
               "redirect_uri" => @redirect_uri,
               "code_verifier" => verifier,
               "client_id" => @client_id,
               "resource" => "https://rs.example/api"
             }
    end

    test "validates its inputs before any request" do
      base = [
        token_endpoint: "#{@issuer}/token",
        issuer: @issuer,
        client_id: @client_id,
        redirect_uri: @redirect_uri,
        code_verifier: PKCE.code_verifier(),
        req_options: [plug: fn _conn -> flunk("no request expected") end]
      ]

      assert {:error, :missing_code} = AuthorizationCode.exchange("", base)
      assert {:error, :invalid_options} = AuthorizationCode.exchange("code-1", %{})

      for {key, error} <- [
            token_endpoint: :missing_token_endpoint,
            issuer: :missing_issuer,
            client_id: :missing_client_id,
            redirect_uri: :missing_redirect_uri,
            code_verifier: :missing_code_verifier
          ] do
        assert {:error, ^error} = AuthorizationCode.exchange("code-1", Keyword.delete(base, key))
      end

      assert {:error, :invalid_resource} =
               AuthorizationCode.exchange("code-1", Keyword.put(base, :resource, "not a uri"))
    end
  end
end
