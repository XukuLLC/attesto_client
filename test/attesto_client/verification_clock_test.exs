defmodule AttestoClient.VerificationClockTest do
  use ExUnit.Case, async: true

  alias AttestoClient.{IDToken, Issuer, ResourceServer, SignedIntrospection, UserInfo}

  @issuer "https://issuer.example"
  @client "client"
  @key JOSE.JWK.generate_key({:ec, "P-256"})
  @now 1_700_000_000

  defp jwks(kid \\ "new") do
    {_, key} = JOSE.JWK.to_public_map(@key)
    %{"keys" => [Map.merge(key, %{"kid" => kid, "alg" => "ES256", "use" => "sig"})]}
  end

  defp claims(now, overrides \\ %{}) do
    Map.merge(
      %{"iss" => @issuer, "sub" => "subject", "aud" => @client, "iat" => now, "exp" => now + 60},
      overrides
    )
  end

  defp sign(claims, typ \\ "JWT") do
    header = %{"alg" => "ES256", "kid" => "new"}
    header = if typ == :absent, do: header, else: Map.put(header, "typ", typ)
    {_, jwt} = @key |> JOSE.JWS.sign(JSON.encode!(claims), header) |> JOSE.JWS.compact()
    jwt
  end

  defp opts(extra \\ []) do
    Keyword.merge([issuer: @issuer, client_id: @client, jwks: jwks(), now: @now], extra)
  end

  defp json(conn, value) do
    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.send_resp(200, JSON.encode!(value))
  end

  # The fetch begins while exp is still in the future, then takes longer than
  # the one-second leeway and returns after exp + leeway. No fixed short sleep
  # is used as a proxy for crossing a whole-second JWT deadline.
  defp slow_keys(exp, leeway) do
    parent = self()

    fn conn ->
      send(parent, {:fetch_started, System.system_time(:second)})
      Process.sleep(max((exp + leeway) * 1_000 + 100 - System.system_time(:millisecond), 0))
      json(conn, jwks())
    end
  end

  for {module, typ, extra} <- [
        {IDToken, "JWT", %{}},
        {UserInfo, "JWT", %{}},
        {SignedIntrospection, "token-introspection+jwt",
         %{"token_introspection" => %{"active" => true}}}
      ] do
    @tag :clock_regression
    test "#{inspect(module)} rejects expiry reached while fetching keys" do
      now = System.system_time(:second)
      exp = now + 2
      jwt = sign(claims(now, Map.put(unquote(Macro.escape(extra)), "exp", exp)), unquote(typ))
      leeway = if unquote(module) == IDToken, do: 1, else: 0

      verify_opts = [
        issuer: @issuer,
        client_id: @client,
        audience: @client,
        jwks_uri: "#{@issuer}/jwks",
        expiry_leeway_seconds: leeway,
        req_options: [plug: slow_keys(exp, leeway)],
        timeout: 15_000
      ]

      assert {:error, :expired} = unquote(module).verify(jwt, verify_opts)
      assert_received {:fetch_started, started}
      assert started < exp
      assert System.system_time(:second) >= exp + leeway
    end
  end

  for module <- [IDToken, ResourceServer] do
    @tag :clock_regression
    test "#{inspect(module)} checks expiry after an unknown-kid cache refresh" do
      state = start_supervised!({Agent, fn -> {jwks("old"), nil} end})

      plug = fn conn ->
        {keys, slow} = Agent.get(state, & &1)
        if slow, do: slow.(conn), else: json(conn, keys)
      end

      server =
        start_supervised!(
          {Issuer, issuer: @issuer, jwks_uri: "#{@issuer}/jwks", req_options: [plug: plug]}
        )

      assert :ok = Issuer.warm(server)
      now = System.system_time(:second)
      exp = now + 2
      slow = slow_keys(exp, 1)
      Agent.update(state, fn _ -> {jwks(), slow} end)

      if unquote(module) == IDToken do
        assert {:error, :expired} =
                 IDToken.verify(sign(claims(now, %{"exp" => exp})),
                   issuer: {Issuer, server},
                   client_id: @client,
                   expiry_leeway_seconds: 1
                 )
      else
        # ResourceServer owns its verification policy; warm a separate server
        # with the old kid, then rotate it through the same transport.
        Agent.update(state, fn _ -> {jwks("old"), nil} end)

        resource_server =
          start_supervised!(
            {ResourceServer,
             issuer: @issuer,
             jwks_uri: "#{@issuer}/jwks",
             audience: @client,
             expiry_leeway_seconds: 1,
             accepted_algs: ["ES256"],
             req_options: [plug: plug]}
          )

        assert :ok = ResourceServer.warm(resource_server)
        now = System.system_time(:second)
        exp = now + 2
        slow = slow_keys(exp, 1)
        Agent.update(state, fn _ -> {jwks(), slow} end)
        jwt = sign(claims(now, %{"exp" => exp, "client_id" => @client, "jti" => "id"}), "at+jwt")
        assert {:error, :expired} = ResourceServer.verify(resource_server, jwt)
      end

      assert_received {:fetch_started, started}
      assert started < exp
    end
  end

  test "a function clock runs once after key fetch and successful signature verification" do
    parent = self()
    state = start_supervised!({Agent, fn -> false end})

    plug = fn conn ->
      Agent.update(state, fn _ -> true end)
      json(conn, jwks())
    end

    clock = fn ->
      send(parent, {:clock, Agent.get(state, & &1)})
      @now
    end

    verify_opts = [
      issuer: @issuer,
      client_id: @client,
      jwks_uri: "#{@issuer}/jwks",
      now: clock,
      req_options: [plug: plug]
    ]

    assert {:ok, _claims} = IDToken.verify(sign(claims(@now)), verify_opts)
    assert_received {:clock, true}
    refute_received {:clock, _}

    [header, payload, _signature] = String.split(sign(claims(@now)), ".")
    invalid = Enum.join([header, payload, Base.url_encode64(<<0::512>>, padding: false)], ".")
    assert {:error, :invalid_signature} = IDToken.verify(invalid, verify_opts)
    refute_received {:clock, _}
  end

  test "validates clock options and results while preserving DateTime overrides" do
    jwt = sign(claims(@now))
    assert {:ok, _} = IDToken.verify(jwt, opts(now: DateTime.from_unix!(@now)))
    assert {:ok, _} = IDToken.verify(jwt, opts(now: fn -> @now end))

    for invalid <- [nil, "now", 1.5, true, fn _ -> @now end] do
      assert {:error, :invalid_time} = IDToken.verify(jwt, opts(now: invalid))
    end

    for clock <- [fn -> nil end, fn -> "now" end, fn -> raise "clock unavailable" end] do
      assert {:error, :invalid_time} = IDToken.verify(jwt, opts(now: clock))
    end
  end

  test "require_typ is optional, boolean, and uses core media-type comparison" do
    jwt = sign(claims(@now), :absent)
    assert {:ok, _} = IDToken.verify(jwt, opts())
    assert {:ok, _} = IDToken.verify(jwt, opts(require_typ: false))
    assert {:error, :unexpected_typ} = IDToken.verify(jwt, opts(require_typ: true))

    for typ <- ["JWT", "jwt", "application/jwt", "Application/JwT"], required <- [false, true] do
      assert {:ok, _} = IDToken.verify(sign(claims(@now), typ), opts(require_typ: required))
    end

    for typ <- [
          nil,
          1,
          "",
          "at+jwt",
          "logout+jwt",
          "application/at+jwt",
          "application/application/jwt"
        ],
        required <- [false, true] do
      assert {:error, :unexpected_typ} =
               IDToken.verify(sign(claims(@now), typ), opts(require_typ: required))
    end

    for invalid <- [nil, "true", 1] do
      assert {:error, :invalid_require_typ} = IDToken.verify(jwt, opts(require_typ: invalid))
    end
  end

  test "require_typ applies to explicitly permitted unsigned ID Tokens too" do
    encode = &Base.url_encode64(JSON.encode!(&1), padding: false)
    jwt = encode.(%{"alg" => "none"}) <> "." <> encode.(claims(@now)) <> "."
    assert {:ok, _} = IDToken.verify(jwt, opts(allow_unsigned: true))

    assert {:error, :unexpected_typ} =
             IDToken.verify(jwt, opts(allow_unsigned: true, require_typ: true))
  end

  test "require_auth_time treats non-positive integers as missing, including with max_age" do
    for value <- [0, -1], extra <- [[], [max_age: @now + 100]] do
      assert {:error, :auth_time_required} =
               IDToken.verify(
                 sign(claims(@now, %{"auth_time" => value})),
                 opts([require_auth_time: true] ++ extra)
               )
    end

    assert {:ok, _} = IDToken.verify(sign(claims(@now, %{"auth_time" => 0})), opts())

    assert {:error, :invalid_auth_time} =
             IDToken.verify(sign(claims(@now, %{"auth_time" => -1})), opts())

    for value <- [nil, "0", 0.0, @now + 61] do
      assert {:error, :invalid_auth_time} =
               IDToken.verify(
                 sign(claims(@now, %{"auth_time" => value})),
                 opts(require_auth_time: true)
               )
    end

    assert {:ok, _} =
             IDToken.verify(
               sign(claims(@now, %{"auth_time" => @now})),
               opts(require_auth_time: true)
             )

    assert {:error, :invalid_require_auth_time} =
             IDToken.verify(sign(claims(@now)), opts(require_auth_time: "true", max_age: 60))
  end
end
