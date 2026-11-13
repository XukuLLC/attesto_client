defmodule AttestoClient.AuthorizationVerificationOptionsTest do
  use ExUnit.Case, async: true

  alias AttestoClient.{AuthorizationCode, Issuer, RefreshCoordinator, Token, TokenSet}
  alias AttestoClient.AuthorizationTransaction.Store.ETS

  @issuer "https://issuer.example"
  @client "client"
  @binding "browser-binding"
  @now 1_700_000_000
  @key JOSE.JWK.generate_key({:ec, "P-256"})

  defp metadata do
    %{
      "issuer" => @issuer,
      "authorization_endpoint" => "#{@issuer}/authorize",
      "token_endpoint" => "#{@issuer}/token",
      "jwks_uri" => "#{@issuer}/jwks",
      "response_types_supported" => ["code"],
      "subject_types_supported" => ["public"],
      "id_token_signing_alg_values_supported" => ["ES256"],
      "code_challenge_methods_supported" => ["S256"]
    }
  end

  defp start_opts(extra \\ []) do
    Keyword.merge(
      [
        issuer: @issuer,
        client_id: @client,
        redirect_uri: "https://client.example/callback",
        browser_binding: @binding,
        metadata: metadata(),
        id_token_alg: "ES256"
      ],
      extra
    )
  end

  defp jwks(kid \\ "signing") do
    {_, key} = JOSE.JWK.to_public_map(@key)
    %{"keys" => [Map.merge(key, %{"kid" => kid, "alg" => "ES256", "use" => "sig"})]}
  end

  defp sign(nonce, overrides, typ) do
    claims =
      Map.merge(
        %{
          "iss" => @issuer,
          "sub" => "subject",
          "aud" => @client,
          "nonce" => nonce,
          "iat" => @now,
          "exp" => @now + 60,
          "auth_time" => @now - 10
        },
        overrides
      )

    header = %{"alg" => "ES256", "kid" => "signing"}
    header = if typ == :absent, do: header, else: Map.put(header, "typ", typ)
    {_, jwt} = @key |> JOSE.JWS.sign(JSON.encode!(claims), header) |> JOSE.JWS.compact()
    jwt
  end

  defp json(conn, body) do
    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.send_resp(200, JSON.encode!(body))
  end

  defp transport(nonce, overrides, typ, parent) do
    fn conn ->
      send(parent, {:request, conn.request_path})

      case conn.request_path do
        "/jwks" ->
          json(conn, jwks())

        "/token" ->
          dpop = Plug.Conn.get_req_header(conn, "dpop")

          Enum.each(dpop, &send(parent, {:dpop_claims, JOSE.JWT.peek_payload(&1).fields}))

          json(conn, %{
            "access_token" => "access",
            "token_type" => if(dpop == [], do: "Bearer", else: "DPoP"),
            "id_token" => sign(nonce, overrides, typ)
          })
      end
    end
  end

  defp flow(:callback, opts, claims, typ) do
    {:ok, %{transaction: transaction}} = AuthorizationCode.start(:return, start_opts())

    AuthorizationCode.callback(
      :return,
      %{"state" => transaction.state, "code" => "code"},
      [
        transaction: transaction,
        browser_binding: @binding,
        req_options: [plug: transport(transaction.nonce, claims, typ, self())]
      ] ++ opts
    )
  end

  defp flow({:refresh, coordinator}, opts, claims, typ) do
    Token.refresh(
      coordinator,
      make_ref(),
      tokens(),
      [
        issuer: @issuer,
        client_id: @client,
        subject: "subject",
        token_endpoint: "#{@issuer}/token",
        jwks_uri: "#{@issuer}/jwks",
        req_options: [plug: transport(nil, claims, typ, self())]
      ] ++ opts
    )
  end

  defp tokens do
    %TokenSet{
      access_token: "old",
      token_type: "Bearer",
      refresh_token: "refresh",
      id_token_alg: "ES256"
    }
  end

  setup do
    %{coordinator: start_supervised!(RefreshCoordinator)}
  end

  test "callback and refresh apply integer and function clocks to every ID Token time rule",
       ctx do
    cases = [
      {%{}, [], :ok},
      {%{"exp" => @now}, [], :expired},
      {%{"iat" => @now + 61}, [], :not_yet_valid},
      {%{"nbf" => @now + 61}, [], :not_yet_valid},
      {%{"iat" => @now - 121}, [max_token_age_seconds: 60], :token_too_old},
      {%{"auth_time" => @now + 61}, [], :invalid_auth_time},
      {%{"auth_time" => 0}, [require_auth_time: true], :auth_time_required},
      {%{"auth_time" => -1}, [require_auth_time: true], :auth_time_required}
    ]

    for path <- [:callback, {:refresh, ctx.coordinator}],
        clock <- [@now, fn -> @now end],
        {claims, extra, expected} <- cases do
      result = flow(path, [now: clock] ++ extra, claims, "JWT")

      if expected == :ok,
        do: assert({:ok, _} = result),
        else: assert(result == {:error, expected})
    end
  end

  test "callback applies the injected clock to max_age and the transaction deadline" do
    {:ok, %{transaction: transaction}} =
      AuthorizationCode.start(:return, start_opts(authorization_params: %{"max_age" => 5}))

    transaction = %{transaction | expires_at: (@now + 60) * 1_000}
    response = %{"state" => transaction.state, "code" => "code"}

    opts = [
      transaction: transaction,
      browser_binding: @binding,
      req_options: [plug: transport(transaction.nonce, %{}, "JWT", self())]
    ]

    for clock <- [@now, fn -> @now end] do
      assert {:error, :max_age_exceeded} =
               AuthorizationCode.callback(:return, response, [now: clock] ++ opts)
    end

    for clock <- [@now + 60, fn -> @now + 60 end] do
      assert {:error, {:invalid_state, :expired}} =
               AuthorizationCode.callback(:return, response, [now: clock] ++ opts)
    end
  end

  test "callback and refresh forward require_typ and retain the default", ctx do
    for path <- [:callback, {:refresh, ctx.coordinator}] do
      assert {:ok, _} = flow(path, [now: @now], %{}, :absent)
      assert {:error, :unexpected_typ} = flow(path, [now: @now, require_typ: true], %{}, :absent)

      for typ <- ["JWT", "jwt", "application/jwt", "Application/JWT"] do
        assert {:ok, _} = flow(path, [now: @now, require_typ: true], %{}, typ)
      end

      assert {:error, :unexpected_typ} = flow(path, [now: @now], %{}, "at+jwt")
    end
  end

  test "invalid options are refused before callback state is taken or refresh makes requests",
       ctx do
    store = start_supervised!(ETS)
    {:ok, started} = AuthorizationCode.start({ETS, store}, start_opts())
    response = %{"state" => started.state, "code" => "code"}

    for {key, value, error} <- [
          {:now, nil, :invalid_time},
          {:now, "now", :invalid_time},
          {:now, 1.5, :invalid_time},
          {:now, fn _ -> @now end, :invalid_time},
          {:now, DateTime.from_unix!(@now), :invalid_time},
          {:require_typ, nil, :invalid_require_typ},
          {:require_typ, "true", :invalid_require_typ}
        ] do
      assert {:error, ^error} = AuthorizationCode.callback({ETS, store}, response, [{key, value}])
      assert {:error, ^error} = flow({:refresh, ctx.coordinator}, [{key, value}], %{}, "JWT")
    end

    assert {:ok, _transaction} = ETS.take(store, started.state)
    refute_received {:request, _}
  end

  test "invalid function results fail closed", ctx do
    for path <- [:callback, {:refresh, ctx.coordinator}] do
      assert {:error, :invalid_time} = flow(path, [now: fn -> "now" end], %{}, "JWT")
    end
  end

  test "function clocks also supply DPoP proof times on callback and refresh", ctx do
    for path <- [:callback, {:refresh, ctx.coordinator}] do
      assert {:ok, _} = flow(path, [now: fn -> @now end, dpop: @key], %{}, "JWT")
      assert_received {:dpop_claims, %{"iat" => @now}}
    end
  end

  test "refresh waiters enforce their own clock, typ and auth_time requirements", ctx do
    parent = self()

    plug = fn
      %{request_path: "/jwks"} = conn ->
        json(conn, jwks())

      %{request_path: "/token"} = conn ->
        send(parent, {:refresh_waiting, self()})

        receive do
          :continue ->
            json(conn, %{
              "access_token" => "access",
              "token_type" => "Bearer",
              "id_token" => sign(nil, %{"auth_time" => 0}, :absent)
            })
        end
    end

    opts = [
      issuer: @issuer,
      client_id: @client,
      subject: "subject",
      token_endpoint: "#{@issuer}/token",
      jwks_uri: "#{@issuer}/jwks",
      now: @now,
      req_options: [plug: plug]
    ]

    for {extra, expected} <- [
          {[require_typ: true], :unexpected_typ},
          {[now: @now + 60], :expired},
          {[require_auth_time: true], :auth_time_required}
        ] do
      leader = Task.async(fn -> Token.refresh(ctx.coordinator, :shared, tokens(), opts) end)
      assert_receive {:refresh_waiting, request}, 5_000

      waiter =
        Task.async(fn ->
          Token.refresh(ctx.coordinator, :shared, tokens(), Keyword.merge(opts, extra))
        end)

      await_waiters(ctx.coordinator, 2, System.monotonic_time(:millisecond) + 5_000)
      send(request, :continue)

      assert {:ok, _} = Task.await(leader)
      assert {:error, ^expected} = Task.await(waiter)
      refute_received {:refresh_waiting, _}
    end
  end

  defp await_waiters(coordinator, count, deadline) do
    state = :sys.get_state(coordinator)

    if length(state.shared.waiters) != count do
      assert System.monotonic_time(:millisecond) < deadline
      Process.sleep(5)
      await_waiters(coordinator, count, deadline)
    end
  end

  test "function clocks are read after initial key lookup and again after cache rotation", ctx do
    state = start_supervised!({Agent, fn -> 0 end})
    parent = self()

    plug = fn conn ->
      count = Agent.get_and_update(state, fn count -> {count + 1, count + 1} end)
      json(conn, jwks(if rem(count, 2) == 1, do: "old", else: "signing"))
    end

    for path <- [:callback, :refresh] do
      issuer =
        start_supervised!(
          {Issuer,
           issuer: @issuer,
           metadata: metadata(),
           req_options: [plug: plug],
           unknown_kid_refresh_interval: 0},
          id: path
        )

      assert :ok = Issuer.warm(issuer)
      before = Agent.get(state, & &1)

      clock = fn ->
        send(parent, {:clock_after_fetch, Agent.get(state, & &1) - before})
        @now
      end

      if path == :callback do
        {:ok, %{transaction: transaction}} = AuthorizationCode.start(:return, start_opts())

        assert {:ok, _} =
                 AuthorizationCode.callback(
                   :return,
                   %{"state" => transaction.state, "code" => "code"},
                   transaction: transaction,
                   browser_binding: @binding,
                   issuer: {Issuer, issuer},
                   now: clock,
                   req_options: [plug: transport(transaction.nonce, %{}, "JWT", self())]
                 )

        assert_received {:clock_after_fetch, 0}
      else
        assert {:ok, _} =
                 Token.refresh(ctx.coordinator, make_ref(), tokens(),
                   issuer: {Issuer, issuer},
                   client_id: @client,
                   subject: "subject",
                   token_endpoint: "#{@issuer}/token",
                   now: clock,
                   req_options: [plug: transport(nil, %{}, "JWT", self())]
                 )
      end

      assert_received {:clock_after_fetch, 1}
      refute_received {:clock_after_fetch, _}
    end
  end

  test "require_response_issuer rejects unsupported metadata before storing state or sending PAR" do
    for document <- [
          metadata(),
          Map.put(metadata(), "authorization_response_iss_parameter_supported", false)
        ] do
      assert {:error, :response_issuer_not_supported} =
               AuthorizationCode.start(
                 {ETS, :must_not_be_called},
                 start_opts(require_response_issuer: true, metadata: document, par: true)
               )
    end

    for value <- [nil, 1, "true"] do
      assert {:error, :invalid_require_response_issuer} =
               AuthorizationCode.start(:return, start_opts(require_response_issuer: value))
    end

    assert {:ok, _} = AuthorizationCode.start(:return, start_opts())
    assert {:ok, _} = AuthorizationCode.start(:return, start_opts(require_response_issuer: false))
  end

  test "advertised or explicitly required response issuer is enforced for success and error responses" do
    for required <- [false, true], protocol <- [:oidc, :oauth] do
      {:ok, %{transaction: transaction}} =
        AuthorizationCode.start(
          :return,
          start_opts(
            require_response_issuer: required,
            protocol: protocol,
            metadata: Map.put(metadata(), "authorization_response_iss_parameter_supported", true)
          )
        )

      assert transaction.require_response_issuer == required
      assert transaction.profile == :generic

      for response <- [%{"code" => "code"}, %{"error" => "access_denied"}] do
        response = Map.put(response, "state", transaction.state)

        opts = [
          transaction: transaction,
          browser_binding: @binding,
          require_response_issuer: false
        ]

        assert {:error, :missing_response_issuer} =
                 AuthorizationCode.callback(:return, response, opts)

        assert {:error, :issuer_mismatch} =
                 AuthorizationCode.callback(
                   :return,
                   Map.put(response, "iss", "https://other.example"),
                   opts
                 )
      end

      assert {:error, {:authorization_error, "access_denied", nil}} =
               AuthorizationCode.callback(
                 :return,
                 %{"state" => transaction.state, "error" => "access_denied", "iss" => @issuer},
                 transaction: transaction,
                 browser_binding: @binding
               )
    end
  end

  test "the retained issuer requirement applies even without the metadata flag" do
    {:ok, %{transaction: transaction}} =
      AuthorizationCode.start(
        :return,
        start_opts(
          require_response_issuer: true,
          metadata: Map.put(metadata(), "authorization_response_iss_parameter_supported", true)
        )
      )

    transaction = %{transaction | metadata: metadata()}

    assert {:error, :missing_response_issuer} =
             AuthorizationCode.callback(
               :return,
               %{"state" => transaction.state, "code" => "code"},
               transaction: transaction,
               browser_binding: @binding
             )
  end
end
