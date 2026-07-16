defmodule AttestoClient.TokenTest do
  use ExUnit.Case, async: true

  alias AttestoClient.RefreshCoordinator
  alias AttestoClient.RefreshResult
  alias AttestoClient.Token
  alias AttestoClient.TokenSet

  @endpoint "https://op.example.com/token"
  @issuer "https://op.example.com"
  @client_id "client"
  @now System.system_time(:second)
  @key JOSE.JWK.generate_key({:rsa, 2048})

  defp tokens(refresh \\ "refresh-old", scope \\ nil) do
    %TokenSet{
      access_token: "access-old",
      token_type: "Bearer",
      refresh_token: refresh,
      scope: scope
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
      timeout: 1_000
    ]

    results =
      1..12
      |> Task.async_stream(fn _ -> Token.refresh(coordinator, :account, tokens(), opts) end,
        max_concurrency: 12,
        ordered: false,
        timeout: 2_000
      )
      |> Enum.map(fn {:ok, result} -> result end)

    assert Enum.uniq(results) == [
             {:ok,
              %RefreshResult{
                tokens: %TokenSet{
                  access_token: "access-new",
                  token_type: "Bearer",
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
      timeout: 1_000
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
      timeout: 1_000
    ]

    first =
      Task.async(fn ->
        Token.refresh(coordinator, :first, tokens("refresh-1", "openid profile"), opts)
      end)

    second =
      Task.async(fn ->
        Token.refresh(coordinator, :second, tokens("refresh-2", "openid email"), opts)
      end)

    assert_receive {:started, first_worker}
    assert_receive {:started, second_worker}
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
      Process.sleep(200)
      json(conn, 200, %{"access_token" => "too-late", "token_type" => "Bearer"})
    end

    opts = [
      token_endpoint: @endpoint,
      issuer: @issuer,
      client_id: "client",
      subject: "subject-1",
      jwks: public_jwks(),
      req_options: [plug: slow],
      timeout: 25
    ]

    results =
      1..5
      |> Task.async_stream(fn _ -> Token.refresh(coordinator, :same, tokens(), opts) end,
        max_concurrency: 5,
        ordered: false
      )
      |> Enum.map(fn {:ok, result} -> result end)

    assert Enum.uniq(results) == [{:error, :timeout}]
    assert Agent.get(counter, & &1) == 1

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
               timeout: 1_000
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
          timeout: 1_000
        )
      end)

    assert_receive {:refresh_request_started, request_pid}
    request_monitor = Process.monitor(request_pid)
    :ok = GenServer.stop(coordinator, :shutdown)

    assert_receive {:DOWN, ^request_monitor, :process, ^request_pid, _reason}
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
      timeout: 1_000
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
