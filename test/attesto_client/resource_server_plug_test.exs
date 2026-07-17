defmodule AttestoClient.ResourceServerPlugTest do
  use ExUnit.Case, async: true

  import Plug.Conn
  import Plug.Test

  alias AttestoClient.ResourceServer
  alias AttestoClient.ResourceServer.Plug, as: ResourceServerPlug

  @issuer "https://issuer.example"
  @audience "https://api.example"
  @now 1_700_000_000

  setup do
    key = JOSE.JWK.generate_key({:rsa, 2048})
    public = key |> JOSE.JWK.to_public_map() |> elem(1)
    jwk = Map.merge(public, %{"alg" => "RS256", "kid" => "key-1", "use" => "sig"})

    plug = fn conn ->
      body =
        case conn.request_path do
          "/.well-known/openid-configuration" ->
            %{"issuer" => @issuer, "jwks_uri" => "#{@issuer}/jwks"}

          "/jwks" ->
            %{"keys" => [jwk]}
        end

      conn
      |> put_resp_content_type("application/json")
      |> send_resp(200, JSON.encode!(body))
    end

    server =
      start_supervised!(
        {ResourceServer,
         issuer: @issuer, audience: @audience, accepted_algs: ["RS256"], req_options: [plug: plug]}
      )

    %{key: key, server: server}
  end

  test "assigns verified claims and enforces route scopes", ctx do
    token = access_token(ctx.key)

    conn =
      :get
      |> conn("/documents")
      |> put_req_header("authorization", "Bearer #{token}")
      |> ResourceServerPlug.call(
        ResourceServerPlug.init(
          server: ctx.server,
          required_scopes: ["documents.read"],
          now: @now
        )
      )

    refute conn.halted,
           inspect({conn.status, conn.resp_body, get_resp_header(conn, "www-authenticate")})

    assert conn.assigns.attesto_claims["sub"] == "user-123"
  end

  test "forwards route token policy", ctx do
    token = access_token(ctx.key)

    accepted =
      :get
      |> conn("/documents")
      |> put_req_header("authorization", "Bearer #{token}")
      |> ResourceServerPlug.call(
        ResourceServerPlug.init(
          server: ctx.server,
          allowed_subjects: ["user-123"],
          allowed_client_ids: ["client-123"],
          max_token_age_seconds: 60,
          max_token_lifetime_seconds: 4_000,
          now: @now
        )
      )

    refute accepted.halted

    rejected =
      :get
      |> conn("/documents")
      |> put_req_header("authorization", "Bearer #{token}")
      |> ResourceServerPlug.call(
        ResourceServerPlug.init(server: ctx.server, allowed_subjects: ["other"], now: @now)
      )

    assert rejected.status == 401
  end

  test "returns an RFC 6750 insufficient_scope response", ctx do
    token = access_token(ctx.key)

    conn =
      :get
      |> conn("/admin")
      |> put_req_header("authorization", "Bearer #{token}")
      |> ResourceServerPlug.call(
        ResourceServerPlug.init(
          server: ctx.server,
          required_scopes: ["admin"],
          now: @now
        )
      )

    assert conn.halted
    assert conn.status == 403
    assert [challenge] = get_resp_header(conn, "www-authenticate")
    assert challenge =~ ~s(Bearer error="insufficient_scope")
    assert challenge =~ ~s(scope="admin")
  end

  test "rejects malformed or absent authorization", ctx do
    opts = ResourceServerPlug.init(server: ctx.server, now: @now)

    missing = ResourceServerPlug.call(conn(:get, "/"), opts)
    assert missing.halted
    assert missing.status == 401
    assert get_resp_header(missing, "www-authenticate") == ["Bearer"]
    assert JSON.decode!(missing.resp_body) == %{}

    malformed =
      conn(:get, "/")
      |> put_req_header("authorization", "Basic abc")
      |> ResourceServerPlug.call(opts)

    assert malformed.halted
    assert malformed.status == 401
    assert [challenge] = get_resp_header(malformed, "www-authenticate")
    assert challenge =~ ~s(Bearer error="invalid_token")
  end

  test "verifies DPoP proof, replay callback, and token binding", ctx do
    proof_key = JOSE.JWK.generate_key({:ec, "P-256"})
    jkt = Attesto.DPoP.compute_jkt(proof_key)
    token = access_token(ctx.key, %{"cnf" => %{"jkt" => jkt}})
    htu = "https://api.example/documents"
    proof = dpop_proof(proof_key, token, htu)
    parent = self()

    conn =
      :get
      |> conn("/documents")
      |> external_https_conn()
      |> put_req_header("authorization", "DPoP #{token}")
      |> put_req_header("dpop", proof)
      |> ResourceServerPlug.call(
        ResourceServerPlug.init(
          server: ctx.server,
          required_scopes: ["documents.read"],
          replay_check: fn jti, ttl ->
            send(parent, {:replay_check, jti, ttl})
            :ok
          end,
          now: @now
        )
      )

    refute conn.halted,
           inspect({conn.status, conn.resp_body, get_resp_header(conn, "www-authenticate")})

    assert_receive {:replay_check, "proof-123", ttl}
    assert ttl > 0
  end

  test "accepts a DPoP-bound token when the request also has authenticated mTLS", ctx do
    proof_key = JOSE.JWK.generate_key({:ec, "P-256"})
    jkt = Attesto.DPoP.compute_jkt(proof_key)
    token = access_token(ctx.key, %{"cnf" => %{"jkt" => jkt}})
    proof = dpop_proof(proof_key, token, "https://api.example/documents")
    cert = cert_der("attesto-client-dpop-with-mtls")

    conn =
      :get
      |> conn("/documents")
      |> external_https_conn()
      |> put_req_header("authorization", "DPoP #{token}")
      |> put_req_header("dpop", proof)
      |> ResourceServerPlug.call(
        ResourceServerPlug.init(
          server: ctx.server,
          replay_check: fn _jti, _ttl -> :ok end,
          cert_der: fn _conn -> cert end,
          now: @now
        )
      )

    refute conn.halted
  end

  test "verifies mTLS certificate binding and rejects absent or invalid certificates", ctx do
    cert = cert_der("attesto-client-mtls")
    {:ok, thumbprint} = Attesto.MTLS.compute_thumbprint(cert)
    token = access_token(ctx.key, %{"cnf" => %{"x5t#S256" => thumbprint}})

    opts = ResourceServerPlug.init(server: ctx.server, cert_der: fn _conn -> cert end, now: @now)

    conn =
      :get
      |> conn("/documents")
      |> put_req_header("authorization", "Bearer #{token}")
      |> ResourceServerPlug.call(opts)

    refute conn.halted

    missing =
      :get
      |> conn("/documents")
      |> put_req_header("authorization", "Bearer #{token}")
      |> ResourceServerPlug.call(ResourceServerPlug.init(server: ctx.server, now: @now))

    assert missing.status == 401

    invalid =
      :get
      |> conn("/documents")
      |> put_req_header("authorization", "Bearer #{token}")
      |> ResourceServerPlug.call(
        ResourceServerPlug.init(
          server: ctx.server,
          cert_der: fn _conn -> "not DER" end,
          now: @now
        )
      )

    assert invalid.status == 401
  end

  test "accepts an unbound bearer token when an ambient mTLS certificate is present", ctx do
    token = access_token(ctx.key)
    cert = cert_der("attesto-client-ambient-mtls")

    conn =
      :get
      |> conn("/documents")
      |> put_req_header("authorization", "Bearer #{token}")
      |> ResourceServerPlug.call(
        ResourceServerPlug.init(
          server: ctx.server,
          cert_der: fn _conn -> cert end,
          now: @now
        )
      )

    refute conn.halted
  end

  test "returns a DPoP nonce challenge", ctx do
    proof_key = JOSE.JWK.generate_key({:ec, "P-256"})
    jkt = Attesto.DPoP.compute_jkt(proof_key)
    token = access_token(ctx.key, %{"cnf" => %{"jkt" => jkt}})
    proof = dpop_proof(proof_key, token, "https://api.example/documents")

    conn =
      :get
      |> conn("/documents")
      |> external_https_conn()
      |> put_req_header("authorization", "DPoP #{token}")
      |> put_req_header("dpop", proof)
      |> ResourceServerPlug.call(
        ResourceServerPlug.init(
          server: ctx.server,
          replay_check: fn _jti, _ttl -> :ok end,
          nonce_check: fn _nonce -> {:error, :use_dpop_nonce} end,
          nonce_issue: fn -> "next-nonce" end,
          now: @now
        )
      )

    assert conn.status == 401
    assert get_resp_header(conn, "dpop-nonce") == ["next-nonce"]
    assert [challenge] = get_resp_header(conn, "www-authenticate")
    assert challenge =~ ~s(DPoP error="use_dpop_nonce")
  end

  test "maps invalid callback return values to OAuth errors", ctx do
    proof_key = JOSE.JWK.generate_key({:ec, "P-256"})
    jkt = Attesto.DPoP.compute_jkt(proof_key)
    token = access_token(ctx.key, %{"cnf" => %{"jkt" => jkt}})
    proof = dpop_proof(proof_key, token, "https://api.example/documents")

    invalid_htu =
      :get
      |> conn("/documents")
      |> external_https_conn()
      |> put_req_header("authorization", "DPoP #{token}")
      |> put_req_header("dpop", proof)
      |> ResourceServerPlug.call(
        ResourceServerPlug.init(
          server: ctx.server,
          replay_check: fn _jti, _ttl -> :ok end,
          htu: fn _conn -> nil end,
          now: @now
        )
      )

    assert invalid_htu.status == 401

    invalid_nonce =
      :get
      |> conn("/documents")
      |> external_https_conn()
      |> put_req_header("authorization", "DPoP #{token}")
      |> put_req_header("dpop", proof)
      |> ResourceServerPlug.call(
        ResourceServerPlug.init(
          server: ctx.server,
          replay_check: fn _jti, _ttl -> :ok end,
          nonce_check: fn _nonce -> {:error, :use_dpop_nonce} end,
          nonce_issue: fn -> nil end,
          now: @now
        )
      )

    assert invalid_nonce.status == 401
    assert get_resp_header(invalid_nonce, "dpop-nonce") == []
    assert [challenge] = get_resp_header(invalid_nonce, "www-authenticate")
    assert challenge =~ ~s(DPoP error="invalid_dpop_proof")
  end

  test "passes a configured maximum DPoP proof age", ctx do
    proof_key = JOSE.JWK.generate_key({:ec, "P-256"})
    jkt = Attesto.DPoP.compute_jkt(proof_key)
    token = access_token(ctx.key, %{"cnf" => %{"jkt" => jkt}})
    proof = dpop_proof(proof_key, token, "https://api.example/documents", iat: @now - 90)

    conn =
      :get
      |> conn("/documents")
      |> external_https_conn()
      |> put_req_header("authorization", "DPoP #{token}")
      |> put_req_header("dpop", proof)
      |> ResourceServerPlug.call(
        ResourceServerPlug.init(
          server: ctx.server,
          replay_check: fn _jti, _ttl -> :ok end,
          dpop_max_age_seconds: 120,
          now: @now
        )
      )

    refute conn.halted
  end

  test "rejects presentation downgrade and duplicated security headers", ctx do
    token = access_token(ctx.key)
    proof_key = JOSE.JWK.generate_key({:ec, "P-256"})
    proof = dpop_proof(proof_key, token, "https://api.example/documents")
    opts = ResourceServerPlug.init(server: ctx.server, now: @now)

    downgrade =
      :get
      |> conn("/documents")
      |> put_req_header("authorization", "Bearer #{token}")
      |> put_req_header("dpop", proof)
      |> ResourceServerPlug.call(opts)

    assert downgrade.status == 401

    duplicated_authorization =
      conn(:get, "/documents")
      |> Map.put(:req_headers, [
        {"authorization", "Bearer #{token}"},
        {"authorization", "Bearer #{token}"}
      ])
      |> ResourceServerPlug.call(opts)

    assert duplicated_authorization.status == 401

    duplicated_dpop =
      conn(:get, "/documents")
      |> external_https_conn()
      |> Map.put(:req_headers, [
        {"authorization", "DPoP #{token}"},
        {"dpop", proof},
        {"dpop", proof}
      ])
      |> ResourceServerPlug.call(opts)

    assert duplicated_dpop.status == 401
  end

  test "returns a private 503 when issuer keys are unavailable" do
    dead_server = spawn(fn -> :ok end)
    ref = Process.monitor(dead_server)
    assert_receive {:DOWN, ^ref, :process, ^dead_server, :normal}

    conn =
      :get
      |> conn("/documents")
      |> put_req_header("authorization", "Bearer token")
      |> ResourceServerPlug.call(ResourceServerPlug.init(server: dead_server))

    assert conn.status == 503
    assert JSON.decode!(conn.resp_body) == %{"error" => "temporarily_unavailable"}
    assert get_resp_header(conn, "www-authenticate") == []
    assert get_resp_header(conn, "cache-control") == ["no-store"]
  end

  test "fails closed when DPoP replay protection is unwired", ctx do
    proof_key = JOSE.JWK.generate_key({:ec, "P-256"})
    jkt = Attesto.DPoP.compute_jkt(proof_key)
    token = access_token(ctx.key, %{"cnf" => %{"jkt" => jkt}})
    proof = dpop_proof(proof_key, token, "https://api.example/documents")

    conn =
      :get
      |> conn("/documents")
      |> external_https_conn()
      |> put_req_header("authorization", "DPoP #{token}")
      |> put_req_header("dpop", proof)
      |> ResourceServerPlug.call(
        ResourceServerPlug.init(
          server: ctx.server,
          dpop_replay_unprotected_acknowledged?: true,
          now: @now
        )
      )

    assert conn.halted
    assert conn.status == 401
    assert [challenge] = get_resp_header(conn, "www-authenticate")
    assert challenge =~ ~s(DPoP error="invalid_dpop_proof")
    refute challenge =~ "replay_check_unconfigured"
    assert JSON.decode!(conn.resp_body) == %{"error" => "invalid_dpop_proof"}
  end

  test "does not expose token-verification reasons in OAuth errors", ctx do
    expired = access_token(ctx.key, %{"exp" => @now - 1})

    conn =
      :get
      |> conn("/documents")
      |> put_req_header("authorization", "Bearer #{expired}")
      |> ResourceServerPlug.call(ResourceServerPlug.init(server: ctx.server, now: @now))

    assert conn.status == 401
    assert JSON.decode!(conn.resp_body) == %{"error" => "invalid_token"}
    assert [challenge] = get_resp_header(conn, "www-authenticate")
    refute challenge =~ "expired"
    refute challenge =~ "error_description"
  end

  test "validates plug options at initialization", ctx do
    assert_raise ArgumentError, fn -> ResourceServerPlug.init([]) end

    assert_raise ArgumentError, fn ->
      ResourceServerPlug.init(server: ctx.server, nonce_check: fn _ -> :ok end)
    end

    assert_raise ArgumentError, fn ->
      ResourceServerPlug.init(server: ctx.server, required_scopes: ["bad scope"])
    end

    for {key, callback} <- [
          htu: fn -> :wrong_arity end,
          nonce_issue: fn _nonce -> :wrong_arity end,
          nonce_check: fn -> :wrong_arity end,
          cert_der: fn -> :wrong_arity end,
          replay_check: fn _jti -> :wrong_arity end
        ] do
      assert_raise ArgumentError, fn ->
        ResourceServerPlug.init([{:server, ctx.server}, {key, callback}])
      end
    end

    assert_raise ArgumentError, fn ->
      ResourceServerPlug.init(server: fn _argument -> ctx.server end)
    end

    assert_raise ArgumentError, fn ->
      ResourceServerPlug.init(server: ctx.server, dpop_max_age_seconds: 0)
    end

    assert_raise ArgumentError, fn ->
      ResourceServerPlug.init(server: ctx.server, allowed_subjects: ["valid", 123])
    end

    assert_raise ArgumentError, fn ->
      ResourceServerPlug.init(server: ctx.server, max_token_age_seconds: -1)
    end
  end

  defp access_token(key, overrides \\ %{}) do
    claims =
      Map.merge(
        %{
          "iss" => @issuer,
          "aud" => @audience,
          "sub" => "user-123",
          "client_id" => "client-123",
          "exp" => @now + 3_600,
          "iat" => @now - 10,
          "jti" => "token-123",
          "scope" => "documents.read"
        },
        overrides
      )

    {_, token} =
      key
      |> JOSE.JWT.sign(%{"alg" => "RS256", "kid" => "key-1", "typ" => "at+jwt"}, claims)
      |> JOSE.JWS.compact()

    token
  end

  defp dpop_proof(key, access_token, htu, opts \\ []) do
    public = key |> JOSE.JWK.to_public_map() |> elem(1)

    header = %{
      "alg" => "ES256",
      "jwk" => public,
      "typ" => "dpop+jwt"
    }

    claims = %{
      "ath" => Attesto.DPoP.compute_ath(access_token),
      "htm" => "GET",
      "htu" => htu,
      "iat" => Keyword.get(opts, :iat, @now),
      "jti" => "proof-123"
    }

    {_, proof} = key |> JOSE.JWT.sign(header, claims) |> JOSE.JWS.compact()
    proof
  end

  defp external_https_conn(conn), do: %{conn | scheme: :https, host: "api.example", port: 443}

  defp cert_der(name) do
    %{cert: der} = :public_key.pkix_test_root_cert(String.to_charlist(name), [])
    der
  end
end
