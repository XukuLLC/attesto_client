defmodule AttestoClient.TokenIDTokenAlgorithmTest do
  use ExUnit.Case, async: true

  alias AttestoClient.AuthorizationCode
  alias AttestoClient.AuthorizationTransaction.Store.ETS
  alias AttestoClient.Builder
  alias AttestoClient.RefreshCoordinator
  alias AttestoClient.Token
  alias AttestoClient.TokenSet

  @issuer "https://issuer.example"

  defp generic_tokens(alg) do
    %TokenSet{
      access_token: "access",
      token_type: "Bearer",
      refresh_token: "refresh",
      id_token_alg: alg
    }
  end

  defp refresh_options(extra) do
    Keyword.merge(
      [
        token_endpoint: @issuer <> "/token",
        issuer: @issuer,
        client_id: "client",
        subject: "subject"
      ],
      extra
    )
  end

  defp provider_response(conn, key, public, provider) do
    case conn.request_path do
      "/jwks" ->
        Req.Test.json(conn, %{"keys" => [public]})

      "/par" ->
        {:ok, body, conn} = Plug.Conn.read_body(conn)
        form = URI.decode_query(body)
        assert form["client_assertion"]
        assert [_proof] = Plug.Conn.get_req_header(conn, "dpop")
        Agent.update(provider, &%{&1 | nonce: form["nonce"]})

        conn
        |> Plug.Conn.put_status(201)
        |> Req.Test.json(%{"request_uri" => "urn:example:request", "expires_in" => 90})

      "/token" ->
        {:ok, body, conn} = Plug.Conn.read_body(conn)
        form = URI.decode_query(body)
        assert form["client_assertion"]
        assert [_proof] = Plug.Conn.get_req_header(conn, "dpop")

        round = refresh_round(form, provider)

        now = System.system_time(:second)

        {:ok, jwt} =
          Builder.sign(key, %{"alg" => "ES256", "typ" => "JWT"}, %{
            "iss" => @issuer,
            "sub" => "subject",
            "aud" => "client",
            "iat" => now,
            "exp" => now + 60,
            "nonce" => Agent.get(provider, & &1.nonce)
          })

        response = %{
          "access_token" => "access-#{round}",
          "refresh_token" => "refresh-#{round}",
          "token_type" => "DPoP",
          "id_token_alg" => "PS256"
        }

        response = if round == 2, do: response, else: Map.put(response, "id_token", jwt)
        Req.Test.json(conn, response)
    end
  end

  defp refresh_round(%{"grant_type" => "refresh_token"}, provider) do
    Agent.get_and_update(provider, fn state ->
      {state.refreshes + 1, %{state | refreshes: state.refreshes + 1}}
    end)
  end

  defp refresh_round(_form, _provider), do: 0

  defp fapi_tokens do
    key = JOSE.JWK.generate_key({:ec, "P-256"})
    {_, public} = JOSE.JWK.to_public_map(key)
    provider = start_supervised!({Agent, fn -> %{nonce: nil, refreshes: 0} end})
    store = {ETS, start_supervised!(ETS)}
    plug = &provider_response(&1, key, public, provider)

    opts = [
      fapi?: true,
      issuer: @issuer,
      client_id: "client",
      redirect_uri: "https://client.example/callback",
      browser_binding: "browser",
      client_auth: {:private_key_jwt, key},
      dpop: key,
      req_options: [plug: plug],
      metadata: %{
        "issuer" => @issuer,
        "authorization_endpoint" => @issuer <> "/authorize",
        "token_endpoint" => @issuer <> "/token",
        "pushed_authorization_request_endpoint" => @issuer <> "/par",
        "jwks_uri" => @issuer <> "/jwks",
        "id_token_signing_alg_values_supported" => ["ES256", "PS256"],
        "response_types_supported" => ["code"],
        "subject_types_supported" => ["public"],
        "code_challenge_methods_supported" => ["S256"]
      }
    ]

    assert {:ok, started} = AuthorizationCode.start(store, opts)

    assert {:ok, %{tokens: tokens}} =
             AuthorizationCode.callback(
               store,
               %{"state" => started.state, "code" => "code", "iss" => @issuer},
               opts
             )

    {tokens, Keyword.merge(opts, refresh_options([]))}
  end

  test "FAPI default ES256 survives implicit and successive refreshes, including no ID Token" do
    {tokens, opts} = fapi_tokens()
    coordinator = start_supervised!(RefreshCoordinator)
    assert tokens.id_token_alg == "ES256"
    assert tokens.extra["id_token_alg"] == "PS256"
    refute Keyword.has_key?(opts, :id_token_alg)

    Enum.reduce(1..3, tokens, fn round, previous ->
      opts = if round == 3, do: Keyword.put(opts, :id_token_alg, "ES256"), else: opts
      assert {:ok, result} = Token.refresh(coordinator, :session, previous, opts)
      assert result.tokens.id_token_alg == "ES256"
      assert result.tokens.profile == :fapi
      assert result.tokens.extra["id_token_alg"] == "PS256"

      if round == 2,
        do: assert(result.id_token_claims == nil),
        else: assert(result.id_token_claims["sub"] == "subject")

      result.tokens
    end)
  end

  test "an explicit mismatch fails before discovery, JWKS or token HTTP" do
    {tokens, opts} = fapi_tokens()
    coordinator = start_supervised!(RefreshCoordinator)
    owner = self()

    spy = fn conn ->
      send(owner, :unexpected_http)
      Req.Test.json(conn, %{})
    end

    opts =
      opts
      |> Keyword.delete(:metadata)
      |> Keyword.put(:req_options, plug: spy)

    for mismatch <- ["PS256", "RS256", "PS25X", nil, [], :ES256] do
      assert {:error, :id_token_alg_mismatch} =
               Token.refresh(
                 coordinator,
                 make_ref(),
                 tokens,
                 Keyword.put(opts, :id_token_alg, mismatch)
               )
    end

    refute_receive :unexpected_http
  end

  test "invalid retained algorithms reject before any HTTP" do
    coordinator = start_supervised!(RefreshCoordinator)
    owner = self()

    spy = fn conn ->
      send(owner, :unexpected_http)
      Req.Test.json(conn, %{})
    end

    for invalid <- ["none", "PS25X", [], :ES256, %{}] do
      assert {:error, :unsupported_alg} =
               Token.refresh(
                 coordinator,
                 make_ref(),
                 generic_tokens(invalid),
                 refresh_options(req_options: [plug: spy])
               )
    end

    refute_receive :unexpected_http
  end

  test "legacy missing policy uses explicit selection or generic default and then retains it" do
    coordinator = start_supervised!(RefreshCoordinator)
    key = JOSE.JWK.generate_key({:ec, "P-256"})
    {_, public} = JOSE.JWK.to_public_map(key)

    plug = fn conn ->
      Req.Test.json(conn, %{"access_token" => "new", "token_type" => "Bearer"})
    end

    opts = refresh_options(jwks: %{"keys" => [public]}, req_options: [plug: plug])

    for legacy <- [generic_tokens(nil), Map.delete(generic_tokens(nil), :id_token_alg)] do
      assert {:ok, default} = Token.refresh(coordinator, make_ref(), legacy, opts)
      assert default.tokens.id_token_alg == "RS256"

      assert {:ok, explicit} =
               Token.refresh(
                 coordinator,
                 make_ref(),
                 legacy,
                 Keyword.put(opts, :id_token_alg, "ES256")
               )

      assert explicit.tokens.id_token_alg == "ES256"
      assert {:ok, next} = Token.refresh(coordinator, make_ref(), explicit.tokens, opts)
      assert next.tokens.id_token_alg == "ES256"
    end
  end

  test "wire metadata cannot establish a local ID Token algorithm" do
    assert {:ok, tokens} =
             TokenSet.from_response(
               %{"access_token" => "access", "token_type" => "Bearer", "id_token_alg" => "none"},
               nil
             )

    assert tokens.id_token_alg == nil
    assert tokens.extra["id_token_alg"] == "none"
  end

  test "coalesced refresh results must match each caller even without a returned ID Token" do
    coordinator = start_supervised!(RefreshCoordinator)
    key = JOSE.JWK.generate_key({:ec, "P-256"})
    {_, public} = JOSE.JWK.to_public_map(key)
    owner = self()

    plug = fn conn ->
      send(owner, {:http_started, self()})

      receive do
        :complete -> Req.Test.json(conn, %{"access_token" => "new", "token_type" => "Bearer"})
      end
    end

    opts = refresh_options(jwks: %{"keys" => [public]}, req_options: [plug: plug])

    first =
      Task.async(fn -> Token.refresh(coordinator, :shared, generic_tokens("ES256"), opts) end)

    assert_receive {:http_started, worker}, 10_000

    second =
      Task.async(fn -> Token.refresh(coordinator, :shared, generic_tokens("PS256"), opts) end)

    await_waiters(coordinator, 2, 500)
    send(worker, :complete)
    assert {:ok, result} = Task.await(first)
    assert result.tokens.id_token_alg == "ES256"
    assert {:error, :id_token_alg_mismatch} = Task.await(second)
    refute_received {:http_started, _another_worker}
  end

  defp await_waiters(coordinator, count, attempts) do
    waiters = :sys.get_state(coordinator) |> Map.fetch!(:shared) |> Map.fetch!(:waiters)

    cond do
      length(waiters) == count ->
        :ok

      attempts == 0 ->
        flunk("concurrent callers did not join the shared refresh")

      true ->
        Process.sleep(10)
        await_waiters(coordinator, count, attempts - 1)
    end
  end
end
