defmodule AttestoClient.ResourceServerTest do
  use ExUnit.Case, async: true

  alias AttestoClient.ResourceServer

  @issuer "https://issuer.example"
  @audience "https://api.example"
  @now 1_700_000_000

  setup do
    key = JOSE.JWK.generate_key({:rsa, 2048})
    jwk = public_jwk(key, "key-1")

    state =
      start_supervised!(
        {Agent,
         fn ->
           %{
             jwks: %{"keys" => [jwk]},
             metadata_issuer: @issuer,
             mode: :ok,
             requests: []
           }
         end}
      )

    plug = issuer_plug(state)

    server =
      start_supervised!(
        {ResourceServer,
         issuer: @issuer,
         audience: @audience,
         accepted_algs: ["RS256"],
         req_options: [plug: plug],
         fresh_ttl: 60_000,
         stale_ttl: 60_000,
         unknown_kid_refresh_interval: 60_000}
      )

    %{key: key, server: server, state: state}
  end

  test "discovers keys, verifies RFC 9068 claims and scopes, and caches the result", ctx do
    token = access_token(ctx.key)

    assert {:ok, claims} =
             ResourceServer.verify(ctx.server, token,
               now: @now,
               required_scopes: ["documents.read"]
             )

    assert claims["sub"] == "user-123"
    assert requests(ctx.state) == ["/.well-known/openid-configuration", "/jwks"]

    assert {:ok, _claims} = ResourceServer.verify(ctx.server, token, now: @now)
    assert requests(ctx.state) == ["/.well-known/openid-configuration", "/jwks"]
  end

  test "warms explicitly and exposes readiness", ctx do
    refute ResourceServer.ready?(ctx.server)
    assert :ok = ResourceServer.warm(ctx.server)
    assert ResourceServer.ready?(ctx.server)
    assert requests(ctx.state) == ["/.well-known/openid-configuration", "/jwks"]

    stop_supervised!({ResourceServer, @issuer})
    refute ResourceServer.ready?(ctx.server)
  end

  test "rejects token-purpose, issuer, audience, time, claim, and scope confusion", ctx do
    checks = [
      {%{"iss" => "https://other.example"}, :invalid_issuer, []},
      {%{"aud" => "https://other-api.example"}, :invalid_audience, []},
      {%{"exp" => @now}, :expired, []},
      {%{"nbf" => @now + 61}, :not_yet_valid, []},
      {%{"iat" => @now + 61}, :not_yet_valid, []},
      {%{"client_id" => nil}, :invalid_claims, []},
      {%{"scope" => ~s(bad"scope)}, :invalid_scope, []},
      {%{}, :insufficient_scope, [required_scopes: ["admin"]]}
    ]

    Enum.each(checks, fn {overrides, expected, extra_opts} ->
      token = access_token(ctx.key, overrides)

      assert {:error, ^expected} =
               ResourceServer.verify(ctx.server, token, [now: @now] ++ extra_opts)
    end)

    wrong_typ = access_token(ctx.key, %{}, typ: "JWT")
    assert {:error, :unexpected_typ} = ResourceServer.verify(ctx.server, wrong_typ, now: @now)
  end

  test "accepts both RFC 9068 media types case-insensitively", ctx do
    for typ <- ["AT+JWT", "application/at+jwt", "Application/AT+JWT"] do
      token = access_token(ctx.key, %{}, typ: typ)
      assert {:ok, _claims} = ResourceServer.verify(ctx.server, token, now: @now)
    end
  end

  test "supports string-array audiences but rejects malformed arrays", ctx do
    accepted = access_token(ctx.key, %{"aud" => ["https://other.example", @audience]})
    malformed = access_token(ctx.key, %{"aud" => [@audience, 123]})

    assert {:ok, _claims} = ResourceServer.verify(ctx.server, accepted, now: @now)
    assert {:error, :invalid_audience} = ResourceServer.verify(ctx.server, malformed, now: @now)
  end

  test "accepts an absent optional scope claim only when the route requires none", ctx do
    claims = token_claims() |> Map.delete("scope")
    token = sign_token(ctx.key, claims, [])

    assert {:ok, _claims} = ResourceServer.verify(ctx.server, token, now: @now)

    assert {:error, :insufficient_scope} =
             ResourceServer.verify(ctx.server, token,
               now: @now,
               required_scopes: ["documents.read"]
             )
  end

  test "applies optional subject, client, age, and lifetime policy", ctx do
    token = access_token(ctx.key)

    assert {:ok, _claims} =
             ResourceServer.verify(ctx.server, token,
               now: @now,
               allowed_subjects: ["user-123"],
               allowed_client_ids: ["client-123"],
               max_token_age_seconds: 60,
               max_token_lifetime_seconds: 4_000
             )

    checks = [
      {[allowed_subjects: ["other"]], :subject_not_allowed},
      {[allowed_client_ids: ["other"]], :client_not_allowed},
      {[max_token_lifetime_seconds: 60], :token_lifetime_exceeded},
      {[max_token_age_seconds: -1], :invalid_policy},
      {[allowed_subjects: ["user-123", 123]], :invalid_policy}
    ]

    for {policy, expected} <- checks do
      assert {:error, ^expected} = ResourceServer.verify(ctx.server, token, [now: @now] ++ policy)
    end

    old_token = access_token(ctx.key, %{"iat" => @now - 100})

    assert {:error, :token_too_old} =
             ResourceServer.verify(ctx.server, old_token,
               now: @now,
               max_token_age_seconds: 1
             )
  end

  test "rejects non-SP scope delimiters", ctx do
    token = access_token(ctx.key, %{"scope" => "documents.read\tadmin"})
    assert {:error, :invalid_scope} = ResourceServer.verify(ctx.server, token, now: @now)
  end

  test "fails closed for confirmation claims and accepts a matching DPoP key", ctx do
    jkt = Base.url_encode64(:crypto.hash(:sha256, "proof-key"), padding: false)
    token = access_token(ctx.key, %{"cnf" => %{"jkt" => jkt}})

    assert {:error, :dpop_proof_required} = ResourceServer.verify(ctx.server, token, now: @now)

    assert {:ok, _claims} =
             ResourceServer.verify(ctx.server, token, now: @now, dpop_jkt: jkt)

    other = Base.url_encode64(:crypto.hash(:sha256, "other-key"), padding: false)

    assert {:error, :dpop_key_mismatch} =
             ResourceServer.verify(ctx.server, token, now: @now, dpop_jkt: other)

    unbound = access_token(ctx.key)

    assert {:error, :dpop_proof_unexpected} =
             ResourceServer.verify(ctx.server, unbound, now: @now, dpop_jkt: jkt)

    mtls_thumbprint = Base.url_encode64(:crypto.hash(:sha256, "certificate"), padding: false)

    assert {:ok, _claims} =
             ResourceServer.verify(ctx.server, token,
               now: @now,
               dpop_jkt: jkt,
               mtls_cert_thumbprint: mtls_thumbprint
             )
  end

  test "fails closed for mTLS and unsupported confirmation objects", ctx do
    thumbprint = Base.url_encode64(:crypto.hash(:sha256, "certificate"), padding: false)
    token = access_token(ctx.key, %{"cnf" => %{"x5t#S256" => thumbprint}})

    assert {:error, :mtls_certificate_required} =
             ResourceServer.verify(ctx.server, token, now: @now)

    assert {:ok, _claims} =
             ResourceServer.verify(ctx.server, token,
               now: @now,
               mtls_cert_thumbprint: thumbprint
             )

    unsupported = access_token(ctx.key, %{"cnf" => %{"jku" => "https://evil.example/jwks"}})

    assert {:error, :unsupported_confirmation} =
             ResourceServer.verify(ctx.server, unsupported, now: @now)

    unbound = access_token(ctx.key)

    assert {:ok, _claims} =
             ResourceServer.verify(ctx.server, unbound,
               now: @now,
               mtls_cert_thumbprint: thumbprint
             )
  end

  test "coordinates concurrent unknown-kid refreshes", ctx do
    assert {:ok, _claims} = ResourceServer.verify(ctx.server, access_token(ctx.key), now: @now)

    rotated_key = JOSE.JWK.generate_key({:rsa, 2048})
    rotated_jwk = public_jwk(rotated_key, "key-2")
    Agent.update(ctx.state, &%{&1 | jwks: %{"keys" => [rotated_jwk]}})
    rotated_token = access_token(rotated_key, %{}, kid: "key-2")

    results =
      1..16
      |> Task.async_stream(
        fn _ -> ResourceServer.verify(ctx.server, rotated_token, now: @now) end,
        max_concurrency: 16,
        ordered: false
      )
      |> Enum.to_list()

    assert Enum.all?(results, &match?({:ok, {:ok, _claims}}, &1))

    assert requests(ctx.state) == [
             "/.well-known/openid-configuration",
             "/jwks",
             "/.well-known/openid-configuration",
             "/jwks"
           ]
  end

  test "rate-limits refreshes for attacker-selected unknown key ids", ctx do
    assert {:ok, _claims} = ResourceServer.verify(ctx.server, access_token(ctx.key), now: @now)

    attacker = JOSE.JWK.generate_key({:rsa, 2048})
    unknown = access_token(attacker, %{}, kid: "attacker-key")

    assert {:error, :invalid_signature} = ResourceServer.verify(ctx.server, unknown, now: @now)
    assert {:error, :invalid_signature} = ResourceServer.verify(ctx.server, unknown, now: @now)

    assert length(requests(ctx.state)) == 4
  end

  test "uses stale known keys for transient refresh failure", ctx do
    stop_supervised!({ResourceServer, @issuer})

    server =
      start_supervised!(
        {ResourceServer,
         issuer: @issuer,
         audience: @audience,
         accepted_algs: ["RS256"],
         req_options: [plug: issuer_plug(ctx.state)],
         fresh_ttl: 1,
         stale_ttl: 60_000}
      )

    token = access_token(ctx.key)
    assert {:ok, _claims} = ResourceServer.verify(server, token, now: @now)
    Process.sleep(5)
    Agent.update(ctx.state, &%{&1 | mode: :unavailable})

    assert {:ok, _claims} = ResourceServer.verify(server, token, now: @now)
  end

  test "uses stale keys after refresh timeout and suppresses repeated outage fetches", ctx do
    stop_supervised!({ResourceServer, @issuer})

    server =
      start_supervised!(
        {ResourceServer,
         issuer: @issuer,
         audience: @audience,
         accepted_algs: ["RS256"],
         req_options: [plug: issuer_plug(ctx.state)],
         fresh_ttl: 1,
         stale_ttl: 60_000,
         refresh_timeout: 50,
         refresh_retry_interval: 60_000}
      )

    token = access_token(ctx.key)
    assert {:ok, _claims} = ResourceServer.verify(server, token, now: @now)
    Process.sleep(5)
    Agent.update(ctx.state, &%{&1 | mode: :slow})

    assert {:ok, _claims} = ResourceServer.verify(server, token, now: @now)
    assert {:ok, _claims} = ResourceServer.verify(server, token, now: @now)
    assert length(requests(ctx.state)) == 4
  end

  test "does not use stale keys after the stale interval expires", ctx do
    stop_supervised!({ResourceServer, @issuer})

    server =
      start_supervised!(
        {ResourceServer,
         issuer: @issuer,
         audience: @audience,
         accepted_algs: ["RS256"],
         req_options: [plug: issuer_plug(ctx.state)],
         fresh_ttl: 1,
         stale_ttl: 1}
      )

    token = access_token(ctx.key)
    assert {:ok, _claims} = ResourceServer.verify(server, token, now: @now)
    Process.sleep(5)
    Agent.update(ctx.state, &%{&1 | mode: :unavailable})

    assert {:error, {:jwks_refresh_failed, {:http_status, 503}}} =
             ResourceServer.verify(server, token, now: @now)
  end

  test "does not use stale keys after a hard metadata validation failure", ctx do
    stop_supervised!({ResourceServer, @issuer})

    server =
      start_supervised!(
        {ResourceServer,
         issuer: @issuer,
         audience: @audience,
         accepted_algs: ["RS256"],
         req_options: [plug: issuer_plug(ctx.state)],
         fresh_ttl: 1,
         stale_ttl: 60_000}
      )

    token = access_token(ctx.key)
    assert {:ok, _claims} = ResourceServer.verify(server, token, now: @now)
    Process.sleep(5)
    Agent.update(ctx.state, &%{&1 | metadata_issuer: "https://evil.example"})

    assert {:error, {:jwks_refresh_failed, :issuer_mismatch}} =
             ResourceServer.verify(server, token, now: @now)
  end

  test "bounds the number of cached JWKS keys", ctx do
    stop_supervised!({ResourceServer, @issuer})

    second = JOSE.JWK.generate_key({:rsa, 2048}) |> public_jwk("key-2")
    Agent.update(ctx.state, &%{&1 | jwks: %{"keys" => [hd(&1.jwks["keys"]), second]}})

    server =
      start_supervised!(
        {ResourceServer,
         issuer: @issuer,
         audience: @audience,
         accepted_algs: ["RS256"],
         max_jwks_keys: 1,
         req_options: [plug: issuer_plug(ctx.state)]}
      )

    assert {:error, {:jwks_refresh_failed, :invalid_jwks}} =
             ResourceServer.verify(server, access_token(ctx.key), now: @now)
  end

  test "does not become ready without a usable allowed signing key", ctx do
    stop_supervised!({ResourceServer, @issuer})

    Agent.update(ctx.state, fn state ->
      key = hd(state.jwks["keys"]) |> Map.put("use", "enc")
      %{state | jwks: %{"keys" => [key]}}
    end)

    server =
      start_supervised!(
        {ResourceServer,
         issuer: @issuer,
         audience: @audience,
         accepted_algs: ["RS256"],
         req_options: [plug: issuer_plug(ctx.state)]}
      )

    refute ResourceServer.ready?(server)
    assert {:error, {:jwks_refresh_failed, :invalid_jwks}} = ResourceServer.warm(server)
    refute ResourceServer.ready?(server)
  end

  test "bounds discovery and JWKS response bytes before JSON decoding", ctx do
    stop_supervised!({ResourceServer, @issuer})

    oversized_plug = fn conn ->
      Plug.Conn.send_resp(
        conn,
        200,
        JSON.encode!(%{"keys" => [], "padding" => String.duplicate("x", 256)})
      )
    end

    server =
      start_supervised!(
        {ResourceServer,
         issuer: @issuer,
         audience: @audience,
         accepted_algs: ["RS256"],
         metadata: %{"issuer" => @issuer, "jwks_uri" => "#{@issuer}/jwks"},
         max_response_bytes: 64,
         req_options: [plug: oversized_plug]}
      )

    assert {:error, {:jwks_refresh_failed, :response_too_large}} =
             ResourceServer.verify(server, access_token(ctx.key), now: @now)
  end

  test "rejects none, symmetric, and critical-header algorithm confusion", ctx do
    claims = token_claims()
    none = unsigned_token(%{"alg" => "none", "kid" => "key-1", "typ" => "at+jwt"}, claims)

    symmetric_key = JOSE.JWK.from_oct("not-a-public-signing-key")

    {_, symmetric} =
      symmetric_key
      |> JOSE.JWT.sign(%{"alg" => "HS256", "kid" => "key-1", "typ" => "at+jwt"}, claims)
      |> JOSE.JWS.compact()

    critical =
      sign_token(ctx.key, claims,
        header: %{
          "alg" => "RS256",
          "kid" => "key-1",
          "typ" => "at+jwt",
          "crit" => ["example"],
          "example" => true
        }
      )

    assert {:error, :invalid_signature} = ResourceServer.verify(ctx.server, none, now: @now)
    assert {:error, :invalid_signature} = ResourceServer.verify(ctx.server, symmetric, now: @now)

    assert {:error, :unsupported_critical_header} =
             ResourceServer.verify(ctx.server, critical, now: @now)
  end

  test "bounds a stalled refresh by the configured deadline", ctx do
    stop_supervised!({ResourceServer, @issuer})

    slow_plug = fn conn ->
      Process.sleep(200)
      json(conn, 200, %{"issuer" => @issuer, "jwks_uri" => "#{@issuer}/jwks"})
    end

    server =
      start_supervised!(
        {ResourceServer,
         issuer: @issuer,
         audience: @audience,
         accepted_algs: ["RS256"],
         refresh_timeout: 50,
         req_options: [plug: slow_plug]}
      )

    assert {:error, {:jwks_refresh_failed, :refresh_timeout}} =
             ResourceServer.verify(server, access_token(ctx.key), now: @now)
  end

  test "validates required startup configuration" do
    assert_raise ArgumentError, fn ->
      ResourceServer.start_link(issuer: "http://issuer.example", audience: @audience)
    end

    assert_raise ArgumentError, fn ->
      ResourceServer.start_link(issuer: @issuer, audience: [], accepted_algs: ["none"])
    end

    assert_raise ArgumentError, fn ->
      ResourceServer.start_link(issuer: @issuer, audience: @audience)
    end
  end

  describe "cross-language parity" do
    test "accepts an RFC 9068 token signed by PyJWT", ctx do
      case python_pyjwt() do
        {:ok, python} ->
          now = System.system_time(:second)
          {_, private_jwk} = JOSE.JWK.to_map(ctx.key)

          assert {:ok, %{"token" => token}} =
                   run_pyjwt(python, %{
                     operation: "sign",
                     private_jwk: private_jwk,
                     alg: "RS256",
                     headers: %{"kid" => "key-1", "typ" => "at+jwt"},
                     claims: interop_claims(now)
                   })

          assert {:ok, claims} = ResourceServer.verify(ctx.server, token, now: now)
          assert claims["sub"] == "python-subject"

        {:skip, reason} ->
          IO.puts("Skipping PyJWT resource-server signer parity: #{reason}")
      end
    end

    test "PyJWT accepts an RFC 9068 token accepted by the resource server", ctx do
      case python_pyjwt() do
        {:ok, python} ->
          now = System.system_time(:second)
          token = sign_token(ctx.key, interop_claims(now), [])

          assert {:ok, _claims} = ResourceServer.verify(ctx.server, token, now: now)

          assert {:ok, %{"claims" => claims, "header" => header}} =
                   run_pyjwt(python, %{
                     operation: "verify",
                     token: token,
                     public_jwk: public_jwk(ctx.key, "key-1"),
                     alg: "RS256",
                     issuer: @issuer,
                     audience: @audience
                   })

          assert header["typ"] == "at+jwt"
          assert claims["client_id"] == "python-client"

        {:skip, reason} ->
          IO.puts("Skipping PyJWT resource-server verifier parity: #{reason}")
      end
    end

    test "refreshes an unknown key for a PyJWT-signed rotation token", ctx do
      case python_pyjwt() do
        {:ok, python} ->
          assert {:ok, _claims} =
                   ResourceServer.verify(ctx.server, access_token(ctx.key), now: @now)

          now = System.system_time(:second)
          rotated_key = JOSE.JWK.generate_key({:rsa, 2048})
          {_, private_jwk} = JOSE.JWK.to_map(rotated_key)
          rotated_jwk = public_jwk(rotated_key, "python-key-2")
          Agent.update(ctx.state, &%{&1 | jwks: %{"keys" => [rotated_jwk]}})

          assert {:ok, %{"token" => token}} =
                   run_pyjwt(python, %{
                     operation: "sign",
                     private_jwk: private_jwk,
                     alg: "RS256",
                     headers: %{"kid" => "python-key-2", "typ" => "application/at+jwt"},
                     claims: interop_claims(now)
                   })

          assert {:ok, _claims} = ResourceServer.verify(ctx.server, token, now: now)
          assert length(requests(ctx.state)) == 4

        {:skip, reason} ->
          IO.puts("Skipping PyJWT resource-server rotation parity: #{reason}")
      end
    end
  end

  defp issuer_plug(state) do
    fn conn ->
      snapshot =
        Agent.get_and_update(state, fn current ->
          {current, %{current | requests: current.requests ++ [conn.request_path]}}
        end)

      case {conn.request_path, snapshot.mode} do
        {"/.well-known/openid-configuration", _mode} ->
          json(conn, 200, %{"issuer" => snapshot.metadata_issuer, "jwks_uri" => "#{@issuer}/jwks"})

        {"/jwks", :ok} ->
          json(conn, 200, snapshot.jwks)

        {"/jwks", :unavailable} ->
          json(conn, 503, %{"error" => "unavailable"})

        {"/jwks", :slow} ->
          Process.sleep(200)
          json(conn, 200, snapshot.jwks)
      end
    end
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

  defp access_token(key, overrides \\ %{}, header_opts \\ []) do
    claims = Map.merge(token_claims(), overrides)

    sign_token(key, claims, header_opts)
  end

  defp token_claims do
    %{
      "iss" => @issuer,
      "aud" => @audience,
      "sub" => "user-123",
      "client_id" => "client-123",
      "exp" => @now + 3_600,
      "iat" => @now - 10,
      "jti" => "token-123",
      "scope" => "documents.read documents.write"
    }
  end

  defp interop_claims(now) do
    %{
      "iss" => @issuer,
      "aud" => @audience,
      "sub" => "python-subject",
      "client_id" => "python-client",
      "exp" => now + 300,
      "iat" => now - 5,
      "jti" => "python-token",
      "scope" => "documents.read"
    }
  end

  defp sign_token(key, claims, header_opts) do
    header =
      Keyword.get(header_opts, :header, %{
        "alg" => "RS256",
        "kid" => Keyword.get(header_opts, :kid, "key-1"),
        "typ" => Keyword.get(header_opts, :typ, "at+jwt")
      })

    {_, token} = key |> JOSE.JWT.sign(header, claims) |> JOSE.JWS.compact()
    token
  end

  defp unsigned_token(header, claims) do
    encoded_header = header |> JSON.encode!() |> Base.url_encode64(padding: false)
    encoded_claims = claims |> JSON.encode!() |> Base.url_encode64(padding: false)
    encoded_header <> "." <> encoded_claims <> "."
  end

  defp python_pyjwt do
    python = System.get_env("ATTESTO_CLIENT_PYTHON") || System.find_executable("python3")

    cond do
      is_nil(python) -> {:skip, "python3 not found"}
      not File.exists?(resource_server_python_script()) -> {:skip, "parity helper not found"}
      true -> ensure_pyjwt(python)
    end
  end

  defp ensure_pyjwt(python) do
    case System.cmd(python, ["-c", "import jwt"], stderr_to_stdout: true) do
      {_output, 0} -> {:ok, python}
      {output, _status} -> {:skip, "PyJWT unavailable: #{String.trim(output)}"}
    end
  end

  defp run_pyjwt(python, payload) do
    path =
      Path.join(
        System.tmp_dir!(),
        "attesto_client_resource_server_#{System.unique_integer([:positive])}.json"
      )

    File.write!(path, JSON.encode!(payload))

    try do
      case System.cmd(python, [resource_server_python_script(), path], stderr_to_stdout: true) do
        {output, 0} -> {:ok, output |> last_json_line!() |> JSON.decode!()}
        {output, _status} -> {:error, String.trim(output)}
      end
    after
      File.rm(path)
    end
  end

  defp resource_server_python_script do
    Path.expand("../../test_support/python/resource_server_jwt.py", __DIR__)
  end

  defp last_json_line!(output) do
    output
    |> String.split("\n", trim: true)
    |> Enum.reverse()
    |> Enum.find(&String.starts_with?(&1, "{"))
    |> case do
      nil -> raise "python parity helper emitted no JSON: #{output}"
      line -> line
    end
  end
end
