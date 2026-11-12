defmodule AttestoClient.IssuerTest do
  use ExUnit.Case, async: true

  alias AttestoClient.AuthorizationCode
  alias AttestoClient.AuthorizationTransaction.Store.ETS
  alias AttestoClient.IDToken
  alias AttestoClient.Issuer
  alias AttestoClient.Issuer.Cache
  alias AttestoClient.RefreshCoordinator
  alias AttestoClient.RefreshResult
  alias AttestoClient.ResourceServer
  alias AttestoClient.Token
  alias AttestoClient.TokenSet

  @issuer "https://issuer.example"
  @client_id "client-123"
  @redirect_uri "https://rp.example.com/callback"
  @browser_binding "opaque-browser-binding"
  @now System.system_time(:second)

  describe "Cache" do
    setup do
      cache =
        Cache.new(%{
          fresh_ttl: 100,
          stale_ttl: 200,
          unknown_kid_refresh_interval: 50,
          refresh_retry_interval: 10
        })

      %{cache: cache}
    end

    test "an empty cache asks for an initial refresh and admits one fetch", %{cache: cache} do
      assert Cache.lookup(nil, 0) == {:refresh, nil, :initial}
      assert {:fetch, ^cache} = Cache.admit(cache, nil, :initial, 0, false)
      assert Cache.admit(cache, nil, :initial, 0, true) == :join
    end

    test "a snapshot is fresh, then expired, and counts generations", %{cache: cache} do
      {snapshot, cache} = Cache.put(cache, %{keys: [%{"kid" => "a"}]}, 1_000)

      assert snapshot.generation == 1
      assert snapshot.fresh_until == 1_100
      assert snapshot.stale_until == 1_300
      assert Cache.lookup(snapshot, 1_099) == {:ok, snapshot}
      assert Cache.lookup(snapshot, 1_100) == {:refresh, 1, :expired}
      assert Cache.usable?(snapshot, 1_299)
      refute Cache.usable?(snapshot, 1_300)
      refute Cache.usable?(nil, 0)

      {next, _cache} = Cache.put(cache, %{keys: []}, 2_000)
      assert next.generation == 2
    end

    test "a reader that observed an older generation gets the newer snapshot", %{cache: cache} do
      {first, cache} = Cache.put(cache, %{keys: []}, 0)
      {second, cache} = Cache.put(cache, %{keys: []}, 500)

      assert Cache.admit(cache, first.generation, :expired, 600, true) == {:reply, {:ok, second}}
      assert {:fetch, _cache} = Cache.admit(cache, second.generation, :forced, 600, false)
    end

    test "a reader that observed the empty cache gets the snapshot fetched since", %{cache: cache} do
      {snapshot, cache} = Cache.put(cache, %{keys: []}, 0)

      for reason <- [:initial, :forced] do
        assert Cache.admit(cache, nil, reason, 1, false) == {:reply, {:ok, snapshot}}
      end
    end

    test "an unknown kid refreshes once per interval", %{cache: cache} do
      {snapshot, cache} = Cache.put(cache, %{keys: [%{"kid" => "a"}]}, 0)

      assert Cache.unknown_kid?(snapshot, "b")
      refute Cache.unknown_kid?(snapshot, "a")
      refute Cache.unknown_kid?(snapshot, nil)
      refute Cache.unknown_kid?(snapshot, "")

      assert {:fetch, cache} = Cache.admit(cache, 1, :unknown_kid, 10, false)
      assert cache.next_unknown_refresh_at == 60
      assert Cache.admit(cache, 1, :unknown_kid, 59, false) == {:reply, {:ok, snapshot}}
      assert {:fetch, _cache} = Cache.admit(cache, 1, :unknown_kid, 60, false)
    end

    test "a transient failure serves the stale snapshot during the stale interval", %{
      cache: cache
    } do
      {snapshot, cache} = Cache.put(cache, %{keys: []}, 0)

      assert Cache.stale_fallback(snapshot, 150, {:http_status, 503}) == {:ok, snapshot}

      assert Cache.stale_fallback(snapshot, 150, {:http_status, 404}) ==
               {:error, {:http_status, 404}}

      assert Cache.stale_fallback(snapshot, 300, {:http_status, 503}) ==
               {:error, {:http_status, 503}}

      cache = Cache.fail(cache, {:http_status, 503}, 150)
      failed = cache.snapshot
      assert failed.retry_after == 160

      # Inside the cooldown the answer is remembered and no fetch starts.
      assert Cache.lookup(failed, 155) == {:ok, failed}
      assert Cache.admit(cache, 1, :expired, 155, false) == {:reply, {:ok, failed}}

      # After it, the reader asks again and a fetch is admitted.
      assert Cache.lookup(failed, 160) == {:refresh, 1, :expired}
      assert {:fetch, _cache} = Cache.admit(cache, 1, :expired, 160, false)
    end

    test "a hard failure is remembered for the cooldown and never served stale", %{cache: cache} do
      {_snapshot, cache} = Cache.put(cache, %{keys: []}, 0)
      cache = Cache.fail(cache, :invalid_jwks, 150)

      assert Cache.lookup(cache.snapshot, 155) == {:error, :invalid_jwks}
      assert Cache.admit(cache, 1, :expired, 155, false) == {:reply, {:error, :invalid_jwks}}
    end

    test "a failure before the first snapshot suppresses initial refreshes only", %{cache: cache} do
      cache = Cache.fail(cache, {:http_status, 503}, 0)

      assert Cache.admit(cache, nil, :initial, 9, false) ==
               {:reply, {:error, {:http_status, 503}}}

      assert {:fetch, _cache} = Cache.admit(cache, nil, :initial, 10, false)
      assert {:fetch, _cache} = Cache.admit(cache, nil, :forced, 9, false)
    end

    test "classifies transient refresh failures" do
      for reason <- [
            {:transport, :closed},
            :timeout,
            :refresh_timeout,
            {:refresh_task_exit, :killed},
            {:http_status, 429},
            {:http_status, 500}
          ] do
        assert Cache.transient?(reason)
      end

      for reason <- [{:http_status, 404}, :invalid_jwks, :issuer_mismatch] do
        refute Cache.transient?(reason)
      end
    end
  end

  describe "process" do
    setup :start_issuer

    test "serves the issuer, metadata, and keys from one fetch", ctx do
      refute Issuer.ready?(ctx.issuer)
      assert Issuer.issuer(ctx.issuer) == {:ok, @issuer}
      assert requests(ctx.state) == []

      assert {:ok, %{"issuer" => @issuer, "token_endpoint" => _}} = Issuer.metadata(ctx.issuer)
      assert {:ok, [%{"kid" => "key-1"}]} = Issuer.keys(ctx.issuer)
      assert Issuer.ready?(ctx.issuer)
      assert requests(ctx.state) == ["/.well-known/openid-configuration", "/jwks"]

      assert :ok = Issuer.refresh(ctx.issuer)
      assert length(requests(ctx.state)) == 4
    end

    test "concurrent readers of an empty cache share one fetch", ctx do
      results =
        1..20
        |> Enum.map(fn _n -> Task.async(fn -> Issuer.keys(ctx.issuer) end) end)
        |> Task.await_many()

      assert Enum.all?(results, &match?({:ok, [_key]}, &1))
      assert requests(ctx.state) == ["/.well-known/openid-configuration", "/jwks"]
    end

    test "reports a refresh failure and a process that is not running", ctx do
      Agent.update(ctx.state, &%{&1 | mode: :unavailable})

      assert Issuer.keys(ctx.issuer) == {:error, {:jwks_refresh_failed, {:http_status, 503}}}
      assert Issuer.warm(ctx.issuer) == {:error, {:jwks_refresh_failed, {:http_status, 503}}}

      assert Issuer.issuer(:no_such_issuer_cache) ==
               {:error, {:jwks_refresh_failed, :server_not_running}}

      assert Issuer.keys(:no_such_issuer_cache) ==
               {:error, {:jwks_refresh_failed, :server_not_running}}
    end

    test "holds no metadata when started with only a jwks_uri", ctx do
      server =
        start_supervised!(
          {Issuer,
           name: :jwks_uri_only_issuer,
           issuer: @issuer,
           jwks_uri: "#{@issuer}/jwks",
           req_options: [plug: issuer_plug(ctx.state)]}
        )

      assert {:ok, [_key]} = Issuer.keys(server)
      assert Issuer.metadata(server) == {:error, :metadata_unavailable}
      assert requests(ctx.state) == ["/jwks"]
    end

    test "validates its options at start" do
      for {opts, message} <- [
            {[issuer: "http://issuer.example"], "Issuer requires an HTTPS :issuer"},
            {[fresh_ttl: -1], "Issuer :fresh_ttl must be a non-negative integer"},
            {[refresh_timeout: 0], "Issuer :refresh_timeout must be a positive integer"},
            {[jwks_uri: ""], "Issuer :jwks_uri must be a non-empty string"},
            {[metadata: []], "Issuer :metadata must be a map"},
            {[req_options: %{}], "Issuer :req_options must be a keyword list"},
            {[accepted_algs: ["HS256"]],
             "Issuer :accepted_algs contains an unsupported algorithm"},
            {[accepted_algs: []], "Issuer requires :accepted_algs as a non-empty list"}
          ] do
        assert_raise ArgumentError, message, fn ->
          Issuer.start_link(Keyword.merge([issuer: @issuer], opts))
        end
      end
    end
  end

  describe "AttestoClient.IDToken.verify/2 with an issuer cache" do
    setup :start_issuer

    test "verifies against the cached keys without fetching again", ctx do
      opts = [issuer: {Issuer, ctx.issuer}, client_id: @client_id]

      assert {:ok, %{"sub" => "subject-1"}} = IDToken.verify(id_token(ctx.key), opts)
      assert {:ok, _claims} = IDToken.verify(id_token(ctx.key), opts)
      assert requests(ctx.state) == ["/.well-known/openid-configuration", "/jwks"]
    end

    test "expects the issuer the cache was started with", ctx do
      token = id_token(ctx.key, %{"iss" => "https://other.example"})

      assert {:error, :invalid_issuer} =
               IDToken.verify(token, issuer: {Issuer, ctx.issuer}, client_id: @client_id)
    end

    test "refreshes once for an unknown kid, then honors the cooldown", ctx do
      opts = [issuer: {Issuer, ctx.issuer}, client_id: @client_id]
      assert {:ok, _claims} = IDToken.verify(id_token(ctx.key), opts)

      rotated = JOSE.JWK.generate_key({:rsa, 2048})
      Agent.update(ctx.state, &%{&1 | jwks: %{"keys" => [public_jwk(rotated, "key-2")]}})

      assert {:ok, _claims} = IDToken.verify(id_token(rotated, %{}, "key-2"), opts)
      assert length(requests(ctx.state)) == 4

      # A second unknown kid inside the interval does not fetch.
      other = JOSE.JWK.generate_key({:rsa, 2048})
      assert {:error, :invalid_signature} = IDToken.verify(id_token(other, %{}, "key-3"), opts)
      assert length(requests(ctx.state)) == 4
    end

    test "a caller-supplied :jwks is used instead of the cache", ctx do
      other = JOSE.JWK.generate_key({:rsa, 2048})

      assert {:ok, _claims} =
               IDToken.verify(id_token(other, %{}, "other"),
                 issuer: {Issuer, ctx.issuer},
                 client_id: @client_id,
                 jwks: %{"keys" => [public_jwk(other, "other")]}
               )

      assert requests(ctx.state) == []
    end

    test "an :issuer_cache option is ignored unless the issuer names the cache", ctx do
      other = JOSE.JWK.generate_key({:rsa, 2048})
      other_issuer = "https://other.example"
      token = id_token(other, %{"iss" => other_issuer}, "other")

      # The cache of one issuer never supplies keys for a string issuer.
      assert {:ok, _claims} =
               IDToken.verify(token,
                 issuer: other_issuer,
                 issuer_cache: ctx.issuer,
                 client_id: @client_id,
                 jwks: %{"keys" => [public_jwk(other, "other")]}
               )

      assert {:error, _fetch_failed} =
               IDToken.verify(id_token(ctx.key, %{"iss" => other_issuer}),
                 issuer: other_issuer,
                 issuer_cache: ctx.issuer,
                 client_id: @client_id,
                 jwks_uri: "#{@issuer}/unreachable",
                 req_options: [plug: fn conn -> Plug.Conn.send_resp(conn, 404, "") end]
               )

      assert requests(ctx.state) == []
    end

    test "reports a cache that is not running", ctx do
      assert {:error, {:jwks_refresh_failed, :server_not_running}} =
               IDToken.verify(id_token(ctx.key),
                 issuer: {Issuer, :no_such_issuer_cache},
                 client_id: @client_id
               )
    end

    test "a ResourceServer process serves ID Token verification too", ctx do
      server =
        start_supervised!(
          {ResourceServer,
           name: :shared_resource_server,
           issuer: @issuer,
           audience: "https://api.example",
           accepted_algs: ["RS256"],
           req_options: [plug: issuer_plug(ctx.state)]}
        )

      assert :ok = ResourceServer.warm(server)

      assert {:ok, _claims} =
               IDToken.verify(id_token(ctx.key),
                 issuer: {Issuer, :shared_resource_server},
                 client_id: @client_id
               )

      assert requests(ctx.state) == ["/.well-known/openid-configuration", "/jwks"]
    end
  end

  describe "AttestoClient.AuthorizationCode with an issuer cache" do
    setup :start_issuer

    test "start/2 takes the metadata and callback/3 the keys from the cache", ctx do
      store = {ETS, start_supervised!(ETS)}
      parent = self()

      assert {:ok, started} =
               AuthorizationCode.start(store,
                 issuer: {Issuer, ctx.issuer},
                 client_id: @client_id,
                 browser_binding: @browser_binding,
                 redirect_uri: @redirect_uri
               )

      assert URI.parse(started.url).path == "/authorize"
      assert requests(ctx.state) == ["/.well-known/openid-configuration", "/jwks"]

      nonce =
        started.url
        |> URI.parse()
        |> Map.fetch!(:query)
        |> URI.decode_query()
        |> Map.fetch!("nonce")

      token_plug = fn conn ->
        send(parent, {:callback_request, conn.request_path})

        json(conn, 200, %{
          "access_token" => "access-1",
          "token_type" => "Bearer",
          "id_token" =>
            id_token(ctx.key, %{"nonce" => nonce, "at_hash" => hash_claim("access-1")})
        })
      end

      assert {:ok, %{id_token_claims: %{"sub" => "subject-1"}}} =
               AuthorizationCode.callback(
                 store,
                 %{"state" => started.state, "code" => "code-1", "iss" => @issuer},
                 issuer: {Issuer, ctx.issuer},
                 browser_binding: @browser_binding,
                 req_options: [plug: token_plug],
                 timeout: 30_000
               )

      # The callback made the token request only; the keys came from the cache.
      assert_received {:callback_request, "/token"}
      refute_received {:callback_request, _other}
      assert requests(ctx.state) == ["/.well-known/openid-configuration", "/jwks"]
    end

    test "callback/3 refuses the cache of another issuer before the token request", ctx do
      store = {ETS, start_supervised!(ETS)}
      parent = self()
      other_issuer = "https://other.example"

      other =
        start_supervised!(
          {Issuer,
           name: :other_issuer_cache,
           issuer: other_issuer,
           jwks_uri: "#{other_issuer}/jwks",
           req_options: [plug: issuer_plug(ctx.state)]}
        )

      assert {:ok, started} =
               AuthorizationCode.start(store,
                 issuer: {Issuer, ctx.issuer},
                 client_id: @client_id,
                 browser_binding: @browser_binding,
                 redirect_uri: @redirect_uri
               )

      spy = fn conn ->
        send(parent, :unexpected_http)
        json(conn, 200, %{})
      end

      assert {:error, :issuer_mismatch} =
               AuthorizationCode.callback(
                 store,
                 %{"state" => started.state, "code" => "code-1", "iss" => @issuer},
                 issuer: {Issuer, other},
                 browser_binding: @browser_binding,
                 req_options: [plug: spy],
                 timeout: 30_000
               )

      refute_received :unexpected_http
    end

    test "start/2 reports a cache that is not running" do
      store = {ETS, start_supervised!(ETS)}

      assert {:error, {:jwks_refresh_failed, :server_not_running}} =
               AuthorizationCode.start(store,
                 issuer: {Issuer, :no_such_issuer_cache},
                 client_id: @client_id,
                 browser_binding: @browser_binding,
                 redirect_uri: @redirect_uri
               )
    end
  end

  describe "AttestoClient.Token.refresh/4 with an issuer cache" do
    setup :start_issuer

    test "verifies the returned ID Token against the cached keys", ctx do
      coordinator = start_supervised!(RefreshCoordinator)

      plug = fn conn ->
        json(conn, 200, %{
          "access_token" => "access-new",
          "token_type" => "Bearer",
          "id_token" => id_token(ctx.key, %{"at_hash" => hash_claim("access-new")})
        })
      end

      tokens = %TokenSet{
        access_token: "access-old",
        token_type: "Bearer",
        refresh_token: "refresh-old"
      }

      opts = [
        token_endpoint: "#{@issuer}/token",
        issuer: {Issuer, ctx.issuer},
        client_id: @client_id,
        subject: "subject-1",
        id_token_alg: "RS256",
        req_options: [plug: plug],
        timeout: 30_000
      ]

      assert {:ok, %RefreshResult{id_token_claims: %{"sub" => "subject-1"}, tokens: refreshed}} =
               Token.refresh(coordinator, :cached, tokens, opts)

      assert refreshed.access_token == "access-new"
      assert requests(ctx.state) == ["/.well-known/openid-configuration", "/jwks"]
    end

    test "forwards :trusted_audiences to ID Token verification", ctx do
      coordinator = start_supervised!(RefreshCoordinator)

      plug = fn conn ->
        json(conn, 200, %{
          "access_token" => "access-new",
          "token_type" => "Bearer",
          "id_token" =>
            id_token(ctx.key, %{
              "at_hash" => hash_claim("access-new"),
              "aud" => [@client_id, "https://api.example"],
              "azp" => @client_id
            })
        })
      end

      tokens = %TokenSet{
        access_token: "access-old",
        token_type: "Bearer",
        refresh_token: "refresh-old"
      }

      opts = [
        token_endpoint: "#{@issuer}/token",
        issuer: {Issuer, ctx.issuer},
        client_id: @client_id,
        subject: "subject-1",
        id_token_alg: "RS256",
        req_options: [plug: plug],
        timeout: 30_000
      ]

      assert {:error, :untrusted_audience} = Token.refresh(coordinator, :strict, tokens, opts)

      assert {:ok, %RefreshResult{}} =
               Token.refresh(
                 coordinator,
                 :trusted,
                 tokens,
                 Keyword.put(opts, :trusted_audiences, ["https://api.example"])
               )
    end
  end

  describe "process with :protocol" do
    defp start_validating(document, protocol) do
      key = JOSE.JWK.generate_key({:rsa, 2048})
      jwks = %{"keys" => [public_jwk(key, "key-1")]}

      state = start_supervised!({Agent, fn -> %{document: document, requests: []} end})

      plug = fn conn ->
        current =
          Agent.get_and_update(state, fn current ->
            {current, %{current | requests: current.requests ++ [conn.request_path]}}
          end)

        case conn.request_path do
          "/jwks" -> json(conn, 200, jwks)
          _well_known -> json(conn, 200, current.document)
        end
      end

      opts =
        [
          issuer: @issuer,
          req_options: [plug: plug],
          fresh_ttl: 0,
          stale_ttl: 60_000,
          refresh_retry_interval: 0
        ]
        |> Keyword.merge(if(protocol, do: [protocol: protocol], else: []))

      %{issuer: start_supervised!({Issuer, opts}), state: state}
    end

    test "a document start/2 would refuse is a refresh failure" do
      bad = Map.put(metadata(), "authorization_endpoint", "#{@issuer}/authorize?client_id=evil")
      ctx = start_validating(bad, :oidc)

      assert {:error, {:jwks_refresh_failed, reason}} = Issuer.keys(ctx.issuer)
      assert {:error, ^reason} = AttestoClient.Discovery.validate_metadata(bad, @issuer)
      refute Issuer.ready?(ctx.issuer)
      # The JWKS is not fetched for a document that was refused.
      assert Agent.get(ctx.state, & &1.requests) == ["/.well-known/openid-configuration"]
    end

    test "a good document becomes a snapshot, and a later bad one does not replace it" do
      ctx = start_validating(metadata(), :oidc)
      assert {:ok, [%{"kid" => "key-1"}]} = Issuer.keys(ctx.issuer)

      Agent.update(
        ctx.state,
        &%{&1 | document: Map.delete(metadata(), "subject_types_supported")}
      )

      assert Issuer.refresh(ctx.issuer) == {:error, {:jwks_refresh_failed, :invalid_metadata}}
      assert {:ok, %{"subject_types_supported" => ["public"]}} = snapshot_metadata(ctx.issuer)
    end

    test "without :protocol only the issuer and jwks_uri are checked, as for a resource server" do
      # An RFC 8414 document from a server with no authorization endpoint.
      document = %{"issuer" => @issuer, "jwks_uri" => "#{@issuer}/jwks"}

      assert {:ok, [_key]} = Issuer.keys(start_validating(document, nil).issuer)
    end

    test ":oauth accepts authorization-server metadata that :oidc refuses" do
      document =
        Map.drop(metadata(), ["subject_types_supported", "id_token_signing_alg_values_supported"])

      assert {:ok, [_key]} = Issuer.keys(start_validating(document, :oauth).issuer)
    end

    test "an unknown :protocol is refused at start" do
      assert_raise ArgumentError, ~r/:protocol must be :oidc or :oauth/, fn ->
        Issuer.config!([issuer: @issuer, protocol: :saml], "AttestoClient.Issuer")
      end
    end

    defp snapshot_metadata(issuer) do
      case :sys.get_state(issuer) do
        %{cache: %{snapshot: %{metadata: metadata}}} -> {:ok, metadata}
        _other -> :error
      end
    end
  end

  defp start_issuer(_ctx) do
    key = JOSE.JWK.generate_key({:rsa, 2048})

    state =
      start_supervised!(
        {Agent,
         fn -> %{jwks: %{"keys" => [public_jwk(key, "key-1")]}, mode: :ok, requests: []} end}
      )

    issuer =
      start_supervised!(
        {Issuer,
         issuer: @issuer,
         req_options: [plug: issuer_plug(state)],
         fresh_ttl: 60_000,
         stale_ttl: 60_000,
         unknown_kid_refresh_interval: 60_000}
      )

    %{key: key, issuer: issuer, state: state}
  end

  defp issuer_plug(state) do
    fn conn ->
      current =
        Agent.get_and_update(state, fn current ->
          {current, %{current | requests: current.requests ++ [conn.request_path]}}
        end)

      case {conn.request_path, current.mode} do
        {"/.well-known/openid-configuration", _mode} -> json(conn, 200, metadata())
        {"/jwks", :ok} -> json(conn, 200, current.jwks)
        {"/jwks", :unavailable} -> json(conn, 503, %{"error" => "unavailable"})
      end
    end
  end

  defp metadata do
    %{
      "issuer" => @issuer,
      "authorization_endpoint" => "#{@issuer}/authorize",
      "token_endpoint" => "#{@issuer}/token",
      "jwks_uri" => "#{@issuer}/jwks",
      "response_types_supported" => ["code"],
      "subject_types_supported" => ["public"],
      "id_token_signing_alg_values_supported" => ["RS256"],
      "code_challenge_methods_supported" => ["S256"]
    }
  end

  defp json(conn, status, body) do
    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.send_resp(status, JSON.encode!(body))
  end

  defp requests(state), do: Agent.get(state, & &1.requests)

  defp public_jwk(key, kid) do
    key
    |> JOSE.JWK.to_public_map()
    |> elem(1)
    |> Map.merge(%{"alg" => "RS256", "kid" => kid, "use" => "sig"})
  end

  defp id_token(key, overrides \\ %{}, kid \\ "key-1") do
    claims =
      Map.merge(
        %{
          "iss" => @issuer,
          "sub" => "subject-1",
          "aud" => @client_id,
          "iat" => @now,
          "exp" => @now + 600
        },
        overrides
      )

    {_, jwt} =
      key
      |> JOSE.JWT.sign(%{"alg" => "RS256", "kid" => kid, "typ" => "JWT"}, claims)
      |> JOSE.JWS.compact()

    jwt
  end

  defp hash_claim(value) do
    :sha256
    |> :crypto.hash(value)
    |> binary_part(0, 16)
    |> Base.url_encode64(padding: false)
  end
end
