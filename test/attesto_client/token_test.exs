defmodule AttestoClient.TokenTest do
  use ExUnit.Case, async: true

  alias AttestoClient.RefreshCoordinator
  alias AttestoClient.RefreshResult
  alias AttestoClient.Test.RefreshFlight
  alias AttestoClient.Token
  alias AttestoClient.TokenSet

  @endpoint "https://op.example.com/token"
  @issuer "https://op.example.com"
  @client_id "client"
  @now System.system_time(:second)
  @key JOSE.JWK.generate_key({:rsa, 2048})

  defp tokens(refresh \\ "refresh-old", scope \\ nil, resources \\ nil) do
    %TokenSet{
      access_token: "access-old",
      token_type: "Bearer",
      refresh_token: refresh,
      scope: scope,
      resources: resources
    }
  end

  defp json(conn, status, body) do
    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.send_resp(status, JSON.encode!(body))
  end

  test "single-flights concurrent refresh and shares the rotated token" do
    coordinator = start_supervised!(RefreshCoordinator)
    counter = start_supervised!({Agent, fn -> 0 end})

    plug = fn conn ->
      Agent.update(counter, &(&1 + 1))
      Process.sleep(50)

      json(conn, 200, %{
        "access_token" => "access-new",
        "token_type" => "Bearer",
        "refresh_token" => "refresh-new"
      })
    end

    opts = [
      token_endpoint: @endpoint,
      issuer: @issuer,
      client_id: "client",
      subject: "subject-1",
      jwks: public_jwks(),
      req_options: [plug: plug],
      timeout: 30_000
    ]

    results =
      1..12
      |> Task.async_stream(fn _ -> Token.refresh(coordinator, :account, tokens(), opts) end,
        max_concurrency: 12,
        ordered: false,
        timeout: 30_000
      )
      |> Enum.map(fn {:ok, result} -> result end)

    assert Enum.uniq(results) == [
             {:ok,
              %RefreshResult{
                tokens: %TokenSet{
                  access_token: "access-new",
                  token_type: "Bearer",
                  client_id: "client",
                  issuer: @issuer,
                  id_token_alg: "RS256",
                  refresh_token: "refresh-new"
                }
              }}
           ]

    assert Agent.get(counter, & &1) == 1
  end

  test "single-flights discovery and JWKS preflight inside the refresh deadline" do
    coordinator = start_supervised!(RefreshCoordinator)
    counts = start_supervised!({Agent, fn -> %{} end})

    plug = fn conn ->
      Agent.update(counts, &Map.update(&1, conn.request_path, 1, fn count -> count + 1 end))

      case conn.request_path do
        "/.well-known/openid-configuration" ->
          json(conn, 200, %{"issuer" => @issuer, "jwks_uri" => "#{@issuer}/jwks"})

        "/jwks" ->
          json(conn, 200, public_jwks())

        "/token" ->
          Process.sleep(25)
          json(conn, 200, %{"access_token" => "new", "token_type" => "Bearer"})
      end
    end

    opts = [
      token_endpoint: @endpoint,
      issuer: @issuer,
      client_id: @client_id,
      subject: "subject-1",
      req_options: [plug: plug],
      timeout: 30_000
    ]

    1..6
    |> Task.async_stream(fn _ -> Token.refresh(coordinator, :discovered, tokens(), opts) end,
      max_concurrency: 6
    )
    |> Enum.each(fn {:ok, result} -> assert {:ok, %RefreshResult{}} = result end)

    assert Agent.get(counts, & &1) == %{
             "/.well-known/openid-configuration" => 1,
             "/jwks" => 1,
             "/token" => 1
           }
  end

  test "preserves an unrotated refresh token and sends different keys independently" do
    coordinator = start_supervised!(RefreshCoordinator)
    parent = self()

    plug = fn conn ->
      send(parent, {:started, self()})

      receive do
        :continue -> json(conn, 200, %{"access_token" => "new", "token_type" => "Bearer"})
      end
    end

    opts = [
      token_endpoint: @endpoint,
      issuer: @issuer,
      client_id: "client",
      subject: "subject-1",
      jwks: public_jwks(),
      req_options: [plug: plug],
      timeout: 30_000
    ]

    first =
      Task.async(fn ->
        Token.refresh(coordinator, :first, tokens("refresh-1", "openid profile"), opts)
      end)

    second =
      Task.async(fn ->
        Token.refresh(coordinator, :second, tokens("refresh-2", "openid email"), opts)
      end)

    assert_receive {:started, first_worker}, 10_000
    assert_receive {:started, second_worker}, 10_000
    send(first_worker, :continue)
    send(second_worker, :continue)

    assert {:ok,
            %RefreshResult{
              tokens: %TokenSet{refresh_token: "refresh-1", scope: "openid profile"}
            }} =
             Task.await(first)

    assert {:ok,
            %RefreshResult{
              tokens: %TokenSet{refresh_token: "refresh-2", scope: "openid email"}
            }} =
             Task.await(second)
  end

  test "uses a replacement scope returned by refresh" do
    coordinator = start_supervised!(RefreshCoordinator)

    plug = fn conn ->
      json(conn, 200, %{
        "access_token" => "new",
        "token_type" => "Bearer",
        "scope" => "openid"
      })
    end

    assert {:ok, %RefreshResult{tokens: %TokenSet{scope: "openid"}}} =
             Token.refresh(coordinator, :scope, tokens("refresh", "openid profile"),
               token_endpoint: @endpoint,
               issuer: @issuer,
               client_id: @client_id,
               subject: "subject-1",
               jwks: public_jwks(),
               req_options: [plug: plug]
             )
  end

  test "deadline wakes all waiters, clears the flight, and does not retry" do
    coordinator = start_supervised!(RefreshCoordinator)
    counter = start_supervised!({Agent, fn -> 0 end})

    slow = fn conn ->
      Agent.update(counter, &(&1 + 1))
      # Far longer than the deadline so the deadline (not the response) always
      # wins; the deadline stays short so `:timeout` is reliable regardless of
      # load.
      Process.sleep(30_000)
      json(conn, 200, %{"access_token" => "too-late", "token_type" => "Bearer"})
    end

    opts = [
      token_endpoint: @endpoint,
      issuer: @issuer,
      client_id: "client",
      subject: "subject-1",
      jwks: public_jwks(),
      req_options: [plug: slow],
      timeout: 500
    ]

    results =
      1..5
      |> Task.async_stream(fn _ -> Token.refresh(coordinator, :same, tokens(), opts) end,
        max_concurrency: 5,
        ordered: false
      )
      |> Enum.map(fn {:ok, result} -> result end)

    assert Enum.uniq(results) == [{:error, :timeout}]
    # "Does not retry" = AT MOST one request reaches the endpoint. Requiring
    # exactly one is load-fragile (a starved worker may be killed by the deadline
    # before it reaches the plug, leaving the counter at 0); `<= 1` still catches
    # a retry (which would make it 2) and cannot flake.
    assert Agent.get(counter, & &1) <= 1

    fast = fn conn ->
      json(conn, 200, %{"access_token" => "recovered", "token_type" => "Bearer"})
    end

    assert {:ok, %RefreshResult{tokens: %TokenSet{access_token: "recovered"}}} =
             Token.refresh(coordinator, :same, tokens(),
               token_endpoint: @endpoint,
               issuer: @issuer,
               client_id: "client",
               subject: "subject-1",
               jwks: public_jwks(),
               req_options: [plug: fast],
               timeout: 30_000
             )
  end

  test "stopping the coordinator kills an in-flight refresh request" do
    {:ok, coordinator} = RefreshCoordinator.start_link()
    Process.unlink(coordinator)
    parent = self()

    plug = fn conn ->
      send(parent, {:refresh_request_started, self()})

      receive do
        :complete_rotation ->
          send(parent, :rotation_completed)
          json(conn, 200, %{"access_token" => "new", "token_type" => "Bearer"})
      end
    end

    task =
      Task.async(fn ->
        Token.refresh(coordinator, :crash, tokens(),
          token_endpoint: @endpoint,
          issuer: @issuer,
          client_id: @client_id,
          subject: "subject-1",
          jwks: public_jwks(),
          req_options: [plug: plug],
          timeout: 30_000
        )
      end)

    assert_receive {:refresh_request_started, request_pid}, 10_000
    request_monitor = Process.monitor(request_pid)
    :ok = GenServer.stop(coordinator, :shutdown)

    assert_receive {:DOWN, ^request_monitor, :process, ^request_pid, _reason}, 10_000
    assert {:error, {:coordinator_exit, _reason}} = Task.await(task)
    refute_receive :rotation_completed
  end

  test "verifies an ID token returned by refresh and binds its subject" do
    coordinator = start_supervised!(RefreshCoordinator)
    access_token = "access-new"
    id_token = refresh_id_token("subject-1", access_token)

    plug = fn conn ->
      json(conn, 200, %{
        "access_token" => access_token,
        "token_type" => "Bearer",
        "id_token" => id_token
      })
    end

    opts = [
      token_endpoint: @endpoint,
      issuer: @issuer,
      client_id: @client_id,
      subject: "subject-1",
      id_token_alg: "RS256",
      jwks: public_jwks(),
      req_options: [plug: plug],
      timeout: 30_000
    ]

    assert {:ok, %RefreshResult{id_token_claims: %{"sub" => "subject-1"}}} =
             Token.refresh(coordinator, :verified, tokens(), opts)

    assert {:error, :subject_mismatch} =
             Token.refresh(
               coordinator,
               :wrong_subject,
               tokens(),
               Keyword.put(opts, :subject, "other-subject")
             )
  end

  test "rejects malformed token responses" do
    coordinator = start_supervised!(RefreshCoordinator)
    plug = fn conn -> json(conn, 200, %{"access_token" => "new"}) end

    assert {:error, :invalid_token_response} =
             Token.refresh(coordinator, :malformed, tokens(),
               token_endpoint: @endpoint,
               issuer: @issuer,
               client_id: @client_id,
               subject: "subject-1",
               jwks: public_jwks(),
               req_options: [plug: plug]
             )
  end

  test "revocation accepts an empty 200 and does not retry failures" do
    counter = start_supervised!({Agent, fn -> 0 end})

    ok_plug = fn conn ->
      Agent.update(counter, &(&1 + 1))
      Plug.Conn.send_resp(conn, 200, "")
    end

    assert :ok =
             Token.revoke("refresh-secret",
               revocation_endpoint: "https://op.example.com/revoke",
               client_id: "client",
               token_type_hint: "refresh_token",
               req_options: [plug: ok_plug]
             )

    assert Agent.get(counter, & &1) == 1

    error_plug = fn conn ->
      Agent.update(counter, &(&1 + 1))
      json(conn, 503, %{"error" => "temporarily_unavailable"})
    end

    assert {:error, {:oauth_error, 503, %{"error" => "temporarily_unavailable"}}} =
             Token.revoke("token",
               revocation_endpoint: "https://op.example.com/revoke",
               client_id: "client",
               req_options: [plug: error_plug]
             )

    assert Agent.get(counter, & &1) == 2
  end

  test "revocation still requires the client identity" do
    assert {:error, :missing_client_id} =
             Token.revoke("token",
               revocation_endpoint: "https://op.example.com/revoke",
               req_options: [plug: fn conn -> Plug.Conn.send_resp(conn, 200, "") end]
             )
  end

  test "exchanges an OID4VCI pre-authorized code for an access token" do
    parent = self()

    plug = fn conn ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      send(parent, {:request, URI.decode_query(body)})
      json(conn, 200, %{"access_token" => "wallet-access-token", "token_type" => "Bearer"})
    end

    assert {:ok, %TokenSet{access_token: "wallet-access-token", token_type: "Bearer"}} =
             Token.exchange_pre_authorized_code("pre-auth-code-123",
               token_endpoint: @endpoint,
               client_id: @client_id,
               tx_code: "1234",
               req_options: [plug: plug]
             )

    assert_receive {:request, form}
    assert form["grant_type"] == "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    assert form["pre-authorized_code"] == "pre-auth-code-123"
    assert form["tx_code"] == "1234"
    assert form["client_id"] == @client_id
  end

  test "exchanges a pre-authorized code anonymously when client authentication is none" do
    parent = self()

    plug = fn conn ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      send(parent, {:anonymous_request, URI.decode_query(body)})
      json(conn, 200, %{"access_token" => "anonymous-access-token", "token_type" => "Bearer"})
    end

    assert {:ok, %TokenSet{access_token: "anonymous-access-token"}} =
             Token.exchange_pre_authorized_code("pre-auth-code-123",
               token_endpoint: @endpoint,
               req_options: [plug: plug]
             )

    assert_receive {:anonymous_request, form}
    refute Map.has_key?(form, "client_id")
    assert form["pre-authorized_code"] == "pre-auth-code-123"
  end

  test "the pre-authorized_code exchange omits tx_code when none is supplied" do
    plug = fn conn ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      refute URI.decode_query(body) |> Map.has_key?("tx_code")
      json(conn, 200, %{"access_token" => "at", "token_type" => "Bearer"})
    end

    assert {:ok, %TokenSet{}} =
             Token.exchange_pre_authorized_code("pre-auth-code-123",
               token_endpoint: @endpoint,
               client_id: @client_id,
               req_options: [plug: plug]
             )
  end

  test "rejects an empty pre-authorized code" do
    assert {:error, :invalid_pre_authorized_code} =
             Token.exchange_pre_authorized_code("",
               token_endpoint: @endpoint,
               client_id: @client_id
             )
  end

  test "revocation has a bounded deadline" do
    slow = fn conn ->
      Process.sleep(200)
      Plug.Conn.send_resp(conn, 200, "")
    end

    assert {:error, :timeout} =
             Token.revoke("token",
               revocation_endpoint: "https://op.example.com/revoke",
               client_id: @client_id,
               req_options: [plug: slow],
               timeout: 20
             )
  end

  test "repeats retained resource indicators on the refresh request" do
    coordinator = start_supervised!(RefreshCoordinator)
    resources = ["https://api.example/a", "https://api.example/b"]

    plug = fn conn ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      pairs = Enum.to_list(URI.query_decoder(body))
      assert {"grant_type", "refresh_token"} in pairs
      assert {"refresh_token", "refresh-old"} in pairs

      assert Enum.filter(pairs, &(elem(&1, 0) == "resource")) == [
               {"resource", "https://api.example/a"},
               {"resource", "https://api.example/b"}
             ]

      json(conn, 200, %{"access_token" => "access-new", "token_type" => "Bearer"})
    end

    opts = [
      token_endpoint: @endpoint,
      issuer: @issuer,
      client_id: @client_id,
      subject: "subject-1",
      jwks: public_jwks(),
      req_options: [plug: plug],
      timeout: 30_000
    ]

    assert {:ok,
            %RefreshResult{
              tokens: %TokenSet{access_token: "access-new", resources: ^resources}
            }} = Token.refresh(coordinator, :account, tokens("refresh-old", nil, resources), opts)
  end

  test "an explicit resource may narrow a retained grant but not exceed it" do
    coordinator = start_supervised!(RefreshCoordinator)
    resources = ["https://api.example/a", "https://api.example/b"]
    owner = self()

    plug = fn conn ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      send(owner, {:refresh_form, Enum.to_list(URI.query_decoder(body))})
      json(conn, 200, %{"access_token" => "access-new", "token_type" => "Bearer"})
    end

    opts = [
      token_endpoint: @endpoint,
      issuer: @issuer,
      client_id: @client_id,
      subject: "subject-1",
      jwks: public_jwks(),
      req_options: [plug: plug]
    ]

    old_tokens = tokens("refresh-old", nil, resources)

    assert {:ok, %RefreshResult{tokens: %TokenSet{resources: ^resources}}} =
             Token.refresh(
               coordinator,
               :narrowed,
               old_tokens,
               Keyword.put(opts, :resource, "https://api.example/a")
             )

    assert_received {:refresh_form, pairs}

    assert Enum.filter(pairs, &(elem(&1, 0) == "resource")) == [
             {"resource", "https://api.example/a"}
           ]

    assert {:error, :invalid_resource} =
             Token.refresh(
               coordinator,
               :outside,
               old_tokens,
               Keyword.put(opts, :resource, "https://other.example/api")
             )

    refute_received {:refresh_form, _pairs}
  end

  test "omits the resource parameter when no indicators are given" do
    coordinator = start_supervised!(RefreshCoordinator)

    plug = fn conn ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      pairs = Enum.to_list(URI.query_decoder(body))
      refute Enum.any?(pairs, &(elem(&1, 0) == "resource"))

      json(conn, 200, %{"access_token" => "access-new", "token_type" => "Bearer"})
    end

    opts = [
      token_endpoint: @endpoint,
      issuer: @issuer,
      client_id: @client_id,
      subject: "subject-1",
      jwks: public_jwks(),
      req_options: [plug: plug],
      timeout: 30_000
    ]

    assert {:ok, %RefreshResult{tokens: %TokenSet{access_token: "access-new"}}} =
             Token.refresh(coordinator, :account, tokens(), opts)
  end

  test "refuses a malformed resource indicator before any request" do
    coordinator = start_supervised!(RefreshCoordinator)

    plug = fn _conn -> flunk("no request expected") end

    opts = [
      token_endpoint: @endpoint,
      issuer: @issuer,
      client_id: @client_id,
      subject: "subject-1",
      jwks: public_jwks(),
      resource: "not a uri",
      req_options: [plug: plug],
      timeout: 30_000
    ]

    assert {:error, :invalid_resource} = Token.refresh(coordinator, :account, tokens(), opts)
  end

  test "refuses malformed retained resource metadata before any request" do
    coordinator = start_supervised!(RefreshCoordinator)
    plug = fn _conn -> flunk("no request expected") end

    opts = [
      token_endpoint: @endpoint,
      issuer: @issuer,
      client_id: @client_id,
      subject: "subject-1",
      jwks: public_jwks(),
      req_options: [plug: plug]
    ]

    assert {:error, :invalid_token_set} =
             Token.refresh(coordinator, :account, tokens("refresh-old", nil, ["not a uri"]), opts)
  end

  test "sends a narrowed scope and retains it when the response omits scope" do
    coordinator = start_supervised!(RefreshCoordinator)

    plug = fn conn ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      assert URI.decode_query(body)["scope"] == "openid email"
      json(conn, 200, %{"access_token" => "access-new", "token_type" => "Bearer"})
    end

    opts = [
      token_endpoint: @endpoint,
      issuer: @issuer,
      client_id: @client_id,
      subject: "subject-1",
      jwks: public_jwks(),
      scopes: ["openid", "email", "openid"],
      req_options: [plug: plug]
    ]

    assert {:ok, %RefreshResult{tokens: %TokenSet{scope: "openid email"}}} =
             Token.refresh(
               coordinator,
               :scope,
               tokens("refresh-old", "openid email profile"),
               opts
             )
  end

  test "refuses malformed refresh scopes before any request" do
    coordinator = start_supervised!(RefreshCoordinator)
    plug = fn _conn -> flunk("no request expected") end

    opts = [
      token_endpoint: @endpoint,
      issuer: @issuer,
      client_id: @client_id,
      subject: "subject-1",
      jwks: public_jwks(),
      req_options: [plug: plug]
    ]

    for scopes <- ["openid", ["two scopes"], ["openid", 1]] do
      assert {:error, :invalid_scopes} =
               Token.refresh(coordinator, :scope, tokens(), Keyword.put(opts, :scopes, scopes))
    end
  end

  test "a caller naming other resources does not adopt a shared refresh" do
    coordinator = start_supervised!(RefreshCoordinator)
    owner = self()

    plug = fn conn ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      resources = for {"resource", resource} <- URI.query_decoder(body), do: resource
      send(owner, {:http_started, self(), resources})

      receive do
        :complete -> json(conn, 200, %{"access_token" => "access-new", "token_type" => "Bearer"})
      end
    end

    opts = [
      token_endpoint: @endpoint,
      issuer: @issuer,
      client_id: @client_id,
      subject: "subject-1",
      jwks: public_jwks(),
      req_options: [plug: plug],
      timeout: 30_000
    ]

    refresh = fn resource, scopes ->
      Task.async(fn ->
        Token.refresh(
          coordinator,
          :shared,
          tokens(),
          opts |> Keyword.put(:resource, resource) |> Keyword.put(:scopes, scopes)
        )
      end)
    end

    first =
      refresh.(["https://api.example/a", "https://api.example/b"], ["read", "write"])

    assert_receive {:http_started, worker, ["https://api.example/a", "https://api.example/b"]},
                   10_000

    reordered =
      refresh.(["https://api.example/b", "https://api.example/a"], ["write", "read"])

    other_resource = refresh.("https://api.example/c", ["read", "write"])

    other_scopes =
      refresh.(["https://api.example/a", "https://api.example/b"], ["read"])

    unnamed = Task.async(fn -> Token.refresh(coordinator, :shared, tokens(), opts) end)
    RefreshFlight.await_waiters(coordinator, :shared, 5)

    # A malformed value is refused without joining the refresh in flight.
    assert {:error, :invalid_resource} =
             Token.refresh(
               coordinator,
               :shared,
               tokens(),
               Keyword.put(opts, :resource, "not a uri")
             )

    send(worker, :complete)

    assert {:ok, %RefreshResult{tokens: %TokenSet{access_token: "access-new"}}} =
             Task.await(first)

    assert {:ok, %RefreshResult{tokens: %TokenSet{access_token: "access-new"}}} =
             Task.await(reordered)

    assert {:error, :refresh_request_mismatch} = Task.await(other_resource)
    assert {:error, :refresh_request_mismatch} = Task.await(other_scopes)
    assert {:error, :refresh_request_mismatch} = Task.await(unnamed)
    refute_received {:http_started, _another_worker, _resources}
  end

  test "a caller naming other resources does not adopt a shared failure" do
    coordinator = start_supervised!(RefreshCoordinator)
    owner = self()

    plug = fn conn ->
      send(owner, {:http_started, self()})

      receive do
        :complete -> json(conn, 400, %{"error" => "invalid_target"})
      end
    end

    opts = [
      token_endpoint: @endpoint,
      issuer: @issuer,
      client_id: @client_id,
      subject: "subject-1",
      jwks: public_jwks(),
      req_options: [plug: plug],
      timeout: 30_000
    ]

    refresh = fn resource ->
      Task.async(fn ->
        Token.refresh(coordinator, :shared, tokens(), Keyword.put(opts, :resource, resource))
      end)
    end

    first = refresh.("https://api.example/a")
    assert_receive {:http_started, worker}, 10_000
    same = refresh.("https://api.example/a")
    other = refresh.("https://api.example/b")
    RefreshFlight.await_waiters(coordinator, :shared, 3)
    send(worker, :complete)

    assert {:error, {:oauth_error, 400, %{"error" => "invalid_target"}}} = Task.await(first)
    assert {:error, {:oauth_error, 400, %{"error" => "invalid_target"}}} = Task.await(same)
    assert {:error, :refresh_request_mismatch} = Task.await(other)
  end

  defp public_jwks do
    {_, map} = JOSE.JWK.to_public_map(@key)
    %{"keys" => [Map.merge(map, %{"kid" => "refresh-signing", "alg" => "RS256"})]}
  end

  defp refresh_id_token(subject, access_token) do
    at_hash =
      :sha256
      |> :crypto.hash(access_token)
      |> binary_part(0, 16)
      |> Base.url_encode64(padding: false)

    claims = %{
      "iss" => @issuer,
      "sub" => subject,
      "aud" => @client_id,
      "iat" => @now,
      "exp" => @now + 600,
      "at_hash" => at_hash
    }

    {_, jwt} =
      @key
      |> JOSE.JWT.sign(%{"alg" => "RS256", "kid" => "refresh-signing", "typ" => "JWT"}, claims)
      |> JOSE.JWS.compact()

    jwt
  end
end
