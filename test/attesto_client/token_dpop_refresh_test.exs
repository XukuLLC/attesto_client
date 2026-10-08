defmodule AttestoClient.TokenDPoPRefreshTest do
  use ExUnit.Case, async: true

  alias Attesto.Thumbprint
  alias AttestoClient.RefreshCoordinator
  alias AttestoClient.Token
  alias AttestoClient.TokenSet
  alias Plug.Conn.Query

  @issuer "https://issuer.example"
  @endpoint @issuer <> "/token"

  defp token_set do
    %TokenSet{
      access_token: "old-access",
      token_type: "dPoP",
      refresh_token: "old-refresh",
      scope: "credential"
    }
  end

  defp options(extra) do
    Keyword.merge(
      [token_endpoint: @endpoint, issuer: @issuer, client_id: "client", subject: "subject"],
      extra
    )
  end

  defp thumbprint(key) do
    {_, public} = JOSE.JWK.to_public_map(key)
    {:ok, jkt} = Thumbprint.of_jwk(public)
    jkt
  end

  test "prior DPoP requires signing material before discovery or any HTTP" do
    coordinator = start_supervised!(RefreshCoordinator)
    owner = self()

    spy = fn conn ->
      send(owner, :unexpected_http)
      Req.Test.json(conn, %{"access_token" => "new", "token_type" => "Bearer"})
    end

    assert {:error, :missing_dpop_key} =
             Token.refresh(coordinator, :missing, token_set(), options(req_options: [plug: spy]))

    refute_receive :unexpected_http
  end

  test "public-only, symmetric and malformed keys fail before discovery or HTTP" do
    coordinator = start_supervised!(RefreshCoordinator)
    key = JOSE.JWK.generate_key({:ec, "P-256"})
    {_, public} = JOSE.JWK.to_public_map(key)
    owner = self()

    spy = fn conn ->
      send(owner, :unexpected_http)
      Req.Test.json(conn, %{"access_token" => "new", "token_type" => "DPoP"})
    end

    for invalid <- [public, JOSE.JWK.generate_key({:oct, 32}), %{"kty" => "EC"}, :invalid] do
      assert {:error, :invalid_dpop_key} =
               Token.refresh(
                 coordinator,
                 make_ref(),
                 token_set(),
                 options(dpop: invalid, req_options: [plug: spy])
               )
    end

    refute_receive :unexpected_http
  end

  test "a changed key is rejected before discovery or HTTP" do
    coordinator = start_supervised!(RefreshCoordinator)
    original = JOSE.JWK.generate_key({:ec, "P-256"})
    other = JOSE.JWK.generate_key({:ec, "P-256"})
    bound = Map.put(token_set(), :dpop_jkt, thumbprint(original))
    owner = self()

    spy = fn conn ->
      send(owner, :unexpected_http)
      Req.Test.json(conn, %{"access_token" => "new", "token_type" => "DPoP"})
    end

    assert {:error, :dpop_key_mismatch} =
             Token.refresh(
               coordinator,
               :changed,
               bound,
               options(dpop: other, req_options: [plug: spy])
             )

    refute_receive :unexpected_http
  end

  test "prior or requested DPoP cannot accept Bearer or a missing token type" do
    coordinator = start_supervised!(RefreshCoordinator)
    key = JOSE.JWK.generate_key({:ec, "P-256"})
    {_, public} = JOSE.JWK.to_public_map(key)

    for old_type <- ["DPoP", "Bearer"], returned <- ["Bearer", nil] do
      response = %{"access_token" => "new", "refresh_token" => "rotated"}
      response = if returned, do: Map.put(response, "token_type", returned), else: response
      spy = fn conn -> Req.Test.json(conn, response) end
      error = if returned, do: :invalid_token_type, else: :invalid_token_response

      assert {:error, ^error} =
               Token.refresh(
                 coordinator,
                 make_ref(),
                 %{token_set() | token_type: old_type},
                 options(dpop: key, jwks: %{"keys" => [public]}, req_options: [plug: spy])
               )
    end
  end

  test "legacy DPoP binds locally after successful rotation and preserves same-key nonce retry" do
    coordinator = start_supervised!(RefreshCoordinator)
    key = JOSE.JWK.generate_key({:ec, "P-256"})
    {_, public} = JOSE.JWK.to_public_map(key)
    expected = thumbprint(key)
    requests = start_supervised!({Agent, fn -> [] end})

    spy = fn conn ->
      [proof] = Plug.Conn.get_req_header(conn, "dpop")
      assert {:ok, claims} = Attesto.JWS.peek_json(proof, :payload)
      assert {:ok, header} = Attesto.JWS.peek_json(proof, :protected)
      assert {:ok, ^expected} = Thumbprint.of_jwk(header["jwk"])
      {:ok, bytes, conn} = Plug.Conn.read_body(conn)
      form = Query.decode(bytes)
      assert form["refresh_token"] in ["old-refresh", "rotated"]
      Agent.update(requests, &[claims | &1])

      if claims["nonce"] == "refresh-nonce" do
        Req.Test.json(conn, %{
          "access_token" => "new",
          "token_type" => "dPoP",
          "refresh_token" => "rotated",
          "dpop_jkt" => "untrusted-server-value"
        })
      else
        conn
        |> Plug.Conn.put_resp_header("dpop-nonce", "refresh-nonce")
        |> Plug.Conn.put_status(400)
        |> Req.Test.json(%{"error" => "use_dpop_nonce"})
      end
    end

    opts = options(dpop: key, jwks: %{"keys" => [public]}, req_options: [plug: spy])
    legacy = Map.delete(token_set(), :dpop_jkt)
    assert {:ok, first} = Token.refresh(coordinator, :same, legacy, opts)
    assert first.tokens.refresh_token == "rotated"
    assert first.tokens.scope == "credential"
    assert Map.get(first.tokens, :dpop_jkt) == expected
    assert first.tokens.extra["dpop_jkt"] == "untrusted-server-value"
    assert {:ok, second} = Token.refresh(coordinator, :same, first.tokens, opts)
    assert Map.get(second.tokens, :dpop_jkt) == expected
    assert length(Agent.get(requests, & &1)) == 4
  end

  test "pre-authorized issuance stores locally verified DPoP provenance" do
    key = JOSE.JWK.generate_key({:ec, "P-256"})
    expected = thumbprint(key)

    spy = fn conn ->
      assert [_proof] = Plug.Conn.get_req_header(conn, "dpop")
      Req.Test.json(conn, %{"access_token" => "access", "token_type" => "DPoP"})
    end

    assert {:ok, tokens} =
             Token.exchange_pre_authorized_code("code",
               token_endpoint: @endpoint,
               client_id: "client",
               dpop: key,
               req_options: [plug: spy]
             )

    assert Map.get(tokens, :dpop_jkt) == expected
  end

  test "DPoP single-flight shares the locally bound rotated token and retains omitted refresh data" do
    coordinator = start_supervised!(RefreshCoordinator)
    key = JOSE.JWK.generate_key({:ec, "P-256"})
    {_, public} = JOSE.JWK.to_public_map(key)
    expected = thumbprint(key)
    requests = start_supervised!({Agent, fn -> 0 end})
    bound = Map.put(token_set(), :dpop_jkt, expected)

    spy = fn conn ->
      Agent.update(requests, &(&1 + 1))
      Process.sleep(50)
      Req.Test.json(conn, %{"access_token" => "new", "token_type" => "DPoP"})
    end

    opts = options(dpop: key, jwks: %{"keys" => [public]}, req_options: [plug: spy])

    results =
      1..6
      |> Task.async_stream(fn _ -> Token.refresh(coordinator, :same, bound, opts) end,
        max_concurrency: 6
      )
      |> Enum.map(fn {:ok, result} -> result end)

    assert [{:ok, result}] = Enum.uniq(results)
    assert result.tokens.refresh_token == "old-refresh"
    assert result.tokens.scope == "credential"
    assert result.tokens.dpop_jkt == expected
    assert Agent.get(requests, & &1) == 1
  end

  test "pre-authorized issuance rejects downgrade and cannot invent provenance without a key" do
    key = JOSE.JWK.generate_key({:ec, "P-256"})

    bearer = fn conn ->
      Req.Test.json(conn, %{"access_token" => "access", "token_type" => "Bearer"})
    end

    assert {:error, :invalid_token_type} =
             Token.exchange_pre_authorized_code("code",
               token_endpoint: @endpoint,
               client_id: "client",
               dpop: key,
               req_options: [plug: bearer]
             )

    assert {:ok, tokens} =
             Token.exchange_pre_authorized_code("code",
               token_endpoint: @endpoint,
               client_id: "client",
               req_options: [plug: bearer]
             )

    assert tokens.dpop_jkt == nil
  end

  test "requested DPoP can bind a previous unbound Bearer token set" do
    coordinator = start_supervised!(RefreshCoordinator)
    key = JOSE.JWK.generate_key({:ec, "P-256"})
    {_, public} = JOSE.JWK.to_public_map(key)
    expected = thumbprint(key)
    spy = fn conn -> Req.Test.json(conn, %{"access_token" => "new", "token_type" => "DPoP"}) end

    assert {:ok, result} =
             Token.refresh(
               coordinator,
               :bind,
               %{token_set() | token_type: "Bearer"},
               options(dpop: key, jwks: %{"keys" => [public]}, req_options: [plug: spy])
             )

    assert result.tokens.dpop_jkt == expected
    assert result.tokens.refresh_token == "old-refresh"
  end

  test "coalesced results are checked against every caller's own key before adoption" do
    coordinator = start_supervised!(RefreshCoordinator)
    key = JOSE.JWK.generate_key({:ec, "P-256"})
    other = JOSE.JWK.generate_key({:ec, "P-256"})
    {_, public} = JOSE.JWK.to_public_map(key)
    expected = thumbprint(key)
    owner = self()

    spy = fn conn ->
      send(owner, {:http_started, self()})

      receive do
        :complete -> Req.Test.json(conn, %{"access_token" => "new", "token_type" => "DPoP"})
      end
    end

    opts = options(dpop: key, jwks: %{"keys" => [public]}, req_options: [plug: spy])
    legacy = Map.delete(token_set(), :dpop_jkt)
    first = Task.async(fn -> Token.refresh(coordinator, :shared, legacy, opts) end)
    assert_receive {:http_started, worker}, 10_000

    different =
      Task.async(fn ->
        Token.refresh(coordinator, :shared, legacy, Keyword.put(opts, :dpop, other))
      end)

    unbound =
      Task.async(fn ->
        Token.refresh(
          coordinator,
          :shared,
          %{legacy | token_type: "Bearer"},
          Keyword.delete(opts, :dpop)
        )
      end)

    await_waiters(coordinator, 3, 500)
    send(worker, :complete)
    assert {:ok, result} = Task.await(first)
    assert result.tokens.dpop_jkt == expected
    assert {:error, :dpop_key_mismatch} = Task.await(different)
    assert {:error, :dpop_key_mismatch} = Task.await(unbound)
    refute_received {:http_started, _another_worker}
  end

  defp await_waiters(coordinator, count, attempts) do
    waiters = :sys.get_state(coordinator) |> Map.fetch!(:shared) |> Map.fetch!(:waiters)

    cond do
      length(waiters) == count ->
        :ok

      attempts == 0 ->
        flunk("concurrent refresh callers did not enter the shared flight")

      true ->
        Process.sleep(10)
        await_waiters(coordinator, count, attempts - 1)
    end
  end
end
