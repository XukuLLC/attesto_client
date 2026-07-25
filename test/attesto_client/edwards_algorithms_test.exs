defmodule AttestoClient.EdwardsAlgorithmsTest do
  use ExUnit.Case, async: false

  alias AttestoClient.AuthorizationCode
  alias AttestoClient.AuthorizationTransaction.Store.ETS
  alias AttestoClient.ClientAssertion
  alias AttestoClient.IdentityAssertion
  alias AttestoClient.JARM
  alias AttestoClient.RefreshCoordinator
  alias AttestoClient.RefreshResult
  alias AttestoClient.RequestObject
  alias AttestoClient.ResourceServer
  alias AttestoClient.Token
  alias AttestoClient.TokenSet

  @issuer "https://op.example.com"
  @client_id "client-edwards"
  @audience "https://api.example.com"
  @redirect_uri "https://client.example.com/callback"
  @browser_binding "opaque-edwards-browser-binding"
  @now System.system_time(:second)

  setup_all do
    previous_fallback = JOSE.crypto_fallback()
    JOSE.crypto_fallback(true)

    on_exit(fn -> JOSE.crypto_fallback(previous_fallback) end)
    :ok
  end

  describe "key-aware ID Token hashes" do
    for {alg, curve} <- [
          {"EdDSA", :Ed25519},
          {"Ed25519", :Ed25519},
          {"EdDSA", :Ed448},
          {"Ed448", :Ed448}
        ] do
      test "validates at_hash, c_hash, and s_hash for #{alg} over #{curve}" do
        alg = unquote(alg)
        curve = unquote(curve)
        key = JOSE.JWK.generate_key({:okp, curve})
        access_token = "access-#{alg}-#{curve}"
        code = "code-#{alg}-#{curve}"
        state = "state-#{alg}-#{curve}"

        claims =
          base_id_token_claims()
          |> Map.merge(%{
            "at_hash" => reference_hash(access_token, curve),
            "c_hash" => reference_hash(code, curve),
            "s_hash" => reference_hash(state, curve)
          })

        jwt = sign(key, alg, claims, "issuer-key")

        assert {:ok, verified} =
                 AttestoClient.IDToken.verify(jwt,
                   issuer: @issuer,
                   client_id: @client_id,
                   jwks: jwks(key, nil, "issuer-key"),
                   accepted_algs: [alg],
                   access_token: access_token,
                   code: code,
                   state: state,
                   now: @now
                 )

        assert verified["at_hash"] == reference_hash(access_token, curve)
      end
    end

    test "rejects exact Edwards identifiers on the other curve" do
      if node_available?() do
        for {header_alg, curve} <- [{"Ed25519", :Ed448}, {"Ed448", :Ed25519}] do
          key = JOSE.JWK.generate_key({:okp, curve})

          {:ok, %{"token" => token}} =
            node_reference(%{
              operation: "sign",
              private_jwk: private_map(key),
              alg: header_alg,
              curve: Atom.to_string(curve),
              kid: "cross-curve",
              claims: base_id_token_claims()
            })

          assert {:error, :invalid_signature} =
                   AttestoClient.IDToken.verify(token,
                     issuer: @issuer,
                     client_id: @client_id,
                     jwks: jwks(key, nil, "cross-curve"),
                     accepted_algs: [header_alg],
                     now: @now
                   )
        end
      else
        IO.puts("Skipping Node Edwards cross-curve parity: node not found")
      end
    end
  end

  test "authorization-code callback validates an exact Ed25519 ID Token" do
    key = JOSE.JWK.generate_key({:okp, :Ed25519})
    store = start_supervised!(ETS)
    metadata = metadata("Ed25519")

    assert {:ok, started} =
             AuthorizationCode.start({ETS, store},
               issuer: @issuer,
               client_id: @client_id,
               browser_binding: @browser_binding,
               redirect_uri: @redirect_uri,
               metadata: metadata,
               id_token_alg: "Ed25519"
             )

    request = started.url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
    access_token = "authorization-code-access"
    code = "authorization-code"

    claims =
      base_id_token_claims()
      |> Map.merge(%{
        "nonce" => request["nonce"],
        "at_hash" => reference_hash(access_token, :Ed25519),
        "c_hash" => reference_hash(code, :Ed25519)
      })

    id_token = sign(key, "Ed25519", claims, "authorization-code-key")

    plug =
      token_endpoint_plug(id_token, access_token, jwks(key, "Ed25519", "authorization-code-key"))

    assert {:ok, %{id_token_claims: %{"sub" => "subject-1"}}} =
             AuthorizationCode.callback(
               {ETS, store},
               %{"state" => started.state, "code" => code},
               browser_binding: @browser_binding,
               req_options: [plug: plug]
             )
  end

  test "refresh validates legacy EdDSA over Ed448 with the Ed448 hash profile" do
    key = JOSE.JWK.generate_key({:okp, :Ed448})
    coordinator = start_supervised!(RefreshCoordinator)
    access_token = "refreshed-ed448-access"

    claims =
      base_id_token_claims()
      |> Map.put("at_hash", reference_hash(access_token, :Ed448))

    id_token = sign(key, "EdDSA", claims, "refresh-ed448")

    plug = fn conn ->
      json(conn, 200, %{
        "access_token" => access_token,
        "token_type" => "Bearer",
        "id_token" => id_token
      })
    end

    tokens = %TokenSet{
      access_token: "old-access",
      token_type: "Bearer",
      refresh_token: "old-refresh"
    }

    assert {:ok, %RefreshResult{id_token_claims: %{"sub" => "subject-1"}}} =
             Token.refresh(coordinator, :ed448, tokens,
               token_endpoint: "#{@issuer}/token",
               issuer: @issuer,
               client_id: @client_id,
               subject: "subject-1",
               id_token_alg: "EdDSA",
               jwks: jwks(key, "EdDSA", "refresh-ed448"),
               req_options: [plug: plug],
               timeout: 1_000
             )
  end

  test "resource-server verification accepts exact Ed448 only for an Ed448 key" do
    key = JOSE.JWK.generate_key({:okp, :Ed448})
    keyset = jwks(key, "Ed448", "resource-ed448")

    plug = fn conn ->
      case conn.request_path do
        "/.well-known/openid-configuration" ->
          json(conn, 200, %{"issuer" => @issuer, "jwks_uri" => "#{@issuer}/jwks"})

        "/jwks" ->
          json(conn, 200, keyset)
      end
    end

    server =
      start_supervised!(
        {ResourceServer,
         issuer: @issuer, audience: @audience, accepted_algs: ["Ed448"], req_options: [plug: plug]}
      )

    claims = %{
      "iss" => @issuer,
      "aud" => @audience,
      "sub" => "subject-1",
      "client_id" => @client_id,
      "iat" => @now,
      "exp" => @now + 600,
      "jti" => "resource-ed448-token",
      "scope" => "documents.read"
    }

    token = sign(key, "Ed448", claims, "resource-ed448", "at+jwt")

    assert {:ok, %{"sub" => "subject-1"}} = ResourceServer.verify(server, token, now: @now)
  end

  describe "JARM FAPI key policy" do
    test "the default rejects EdDSA over Ed448 but an explicit non-FAPI list permits it" do
      ed25519 = JOSE.JWK.generate_key({:okp, :Ed25519})
      ed25519_token = sign(ed25519, "EdDSA", jarm_claims(), "jarm-legacy-ed25519")

      assert {:ok, _claims} =
               JARM.verify(
                 ed25519_token,
                 jwks(ed25519, "EdDSA", "jarm-legacy-ed25519"),
                 jarm_opts()
               )

      key = JOSE.JWK.generate_key({:okp, :Ed448})
      token = sign(key, "EdDSA", jarm_claims(), "jarm-ed448")
      keyset = jwks(key, "EdDSA", "jarm-ed448")

      assert {:error, :invalid_signature} = JARM.verify(token, keyset, jarm_opts())

      assert {:ok, %{"code" => "code-1"}} =
               JARM.verify(token, keyset, jarm_opts(accepted_algs: ["EdDSA"]))

      assert {:error, :invalid_signature} =
               JARM.verify(
                 token,
                 keyset,
                 jarm_opts(accepted_algs: ["EdDSA"], enforce_fapi_alg_policy: true)
               )

      assert {:error, :unsupported_alg} =
               JARM.verify(token, keyset, jarm_opts(accepted_algs: nil))
    end

    test "accepts exact Ed25519 by default and exact Ed448 only under explicit policy" do
      ed25519 = JOSE.JWK.generate_key({:okp, :Ed25519})
      ed25519_token = sign(ed25519, "Ed25519", jarm_claims(), "jarm-ed25519")

      assert {:ok, _claims} =
               JARM.verify(
                 ed25519_token,
                 jwks(ed25519, "Ed25519", "jarm-ed25519"),
                 jarm_opts()
               )

      ed448 = JOSE.JWK.generate_key({:okp, :Ed448})
      ed448_token = sign(ed448, "Ed448", jarm_claims(), "jarm-exact-ed448")
      ed448_jwks = jwks(ed448, "Ed448", "jarm-exact-ed448")

      assert {:error, :invalid_signature} = JARM.verify(ed448_token, ed448_jwks, jarm_opts())

      assert {:ok, _claims} =
               JARM.verify(ed448_token, ed448_jwks, jarm_opts(accepted_algs: ["Ed448"]))
    end

    test "rejects ambiguous, unsuitable, algorithm-confused, and weak JWKs" do
      key = JOSE.JWK.generate_key({:ec, "P-256"})
      token = sign(key, "ES256", jarm_claims(), "jarm-key")
      public = public_map(key, "ES256", "jarm-key")

      assert {:error, :ambiguous_key} =
               JARM.verify(token, %{"keys" => [public, public]}, jarm_opts())

      for override <- [
            %{"use" => "enc"},
            %{"use" => nil},
            %{"key_ops" => ["sign"]},
            %{"key_ops" => ["verify", 42]},
            %{"alg" => "PS256"}
          ] do
        assert {:error, :invalid_signature} =
                 JARM.verify(token, %{"keys" => [Map.merge(public, override)]}, jarm_opts())
      end

      strong = JOSE.JWK.generate_key({:rsa, 2048})
      strong_token = sign(strong, "PS256", jarm_claims(), "strong-rsa")

      assert {:ok, _claims} =
               JARM.verify(
                 strong_token,
                 jwks(strong, "PS256", "strong-rsa"),
                 jarm_opts()
               )

      weak = JOSE.JWK.generate_key({:rsa, 1024})
      weak_token = sign(weak, "PS256", jarm_claims(), "weak-rsa")

      assert {:error, :weak_key} =
               JARM.verify(weak_token, jwks(weak, "PS256", "weak-rsa"), jarm_opts())
    end
  end

  describe "outbound builders" do
    test "build exact Edwards artifacts only with the matching curve" do
      ed25519 = JOSE.JWK.generate_key({:okp, :Ed25519})
      ed448 = JOSE.JWK.generate_key({:okp, :Ed448})

      assert {:ok, client_assertion} =
               ClientAssertion.build(ed25519,
                 client_id: @client_id,
                 audience: @issuer,
                 alg: "Ed25519"
               )

      assert protected_alg(client_assertion) == "Ed25519"

      assert {:ok, request_object} =
               RequestObject.build(ed448,
                 client_id: @client_id,
                 audience: @issuer,
                 alg: "Ed448"
               )

      assert protected_alg(request_object) == "Ed448"

      assert {:ok, identity_assertion} =
               IdentityAssertion.build(ed448,
                 issuer: "https://identity.example.com",
                 audience: @issuer,
                 client_id: @client_id,
                 subject: "subject-1",
                 alg: "Ed448"
               )

      assert protected_alg(identity_assertion) == "Ed448"

      for {key, alg} <- [{ed25519, "Ed448"}, {ed448, "Ed25519"}] do
        assert {:error, {:signing_failed, _message}} =
                 ClientAssertion.build(key,
                   client_id: @client_id,
                   audience: @issuer,
                   alg: alg
                 )

        assert {:error, {:signing_failed, _message}} =
                 RequestObject.build(key,
                   client_id: @client_id,
                   audience: @issuer,
                   alg: alg
                 )

        assert {:error, {:signing_failed, _message}} =
                 IdentityAssertion.build(key,
                   issuer: "https://identity.example.com",
                   audience: @issuer,
                   client_id: @client_id,
                   subject: "subject-1",
                   alg: alg
                 )
      end
    end

    test "Node crypto verifies an exact Ed448 client assertion" do
      if node_available?() do
        key = JOSE.JWK.generate_key({:okp, :Ed448})

        assert {:ok, assertion} =
                 ClientAssertion.build(key,
                   client_id: @client_id,
                   audience: @issuer,
                   alg: "Ed448",
                   kid: "node-ed448"
                 )

        assert {:ok, %{"header" => %{"alg" => "Ed448"}, "claims" => claims}} =
                 node_reference(%{
                   operation: "verify",
                   token: assertion,
                   public_jwk: public_map(key, nil, nil)
                 })

        assert claims["iss"] == @client_id
      else
        IO.puts("Skipping Node Ed448 builder parity: node not found")
      end
    end
  end

  test "independent Node crypto signs all Edwards ID Token variants with matching hashes" do
    if node_available?() do
      for {alg, curve} <- [
            {"EdDSA", :Ed25519},
            {"Ed25519", :Ed25519},
            {"EdDSA", :Ed448},
            {"Ed448", :Ed448}
          ] do
        key = JOSE.JWK.generate_key({:okp, curve})
        access_token = "node-access-#{alg}-#{curve}"
        code = "node-code-#{alg}-#{curve}"
        state = "node-state-#{alg}-#{curve}"

        assert {:ok, %{"token" => token, "claims" => node_claims}} =
                 node_reference(%{
                   operation: "sign",
                   private_jwk: private_map(key),
                   alg: alg,
                   curve: Atom.to_string(curve),
                   kid: "node-issuer-key",
                   claims: base_id_token_claims(),
                   detached_hashes: %{
                     at_hash: access_token,
                     c_hash: code,
                     s_hash: state
                   }
                 })

        assert {:ok, claims} =
                 AttestoClient.IDToken.verify(token,
                   issuer: @issuer,
                   client_id: @client_id,
                   jwks: jwks(key, nil, "node-issuer-key"),
                   accepted_algs: [alg],
                   access_token: access_token,
                   code: code,
                   state: state,
                   now: @now
                 )

        assert claims["at_hash"] == node_claims["at_hash"]
      end
    else
      IO.puts("Skipping Node Edwards ID Token parity: node not found")
    end
  end

  defp base_id_token_claims do
    %{
      "iss" => @issuer,
      "sub" => "subject-1",
      "aud" => @client_id,
      "iat" => @now,
      "exp" => @now + 600
    }
  end

  defp jarm_claims do
    %{
      "iss" => @issuer,
      "aud" => @client_id,
      "iat" => @now,
      "exp" => @now + 600,
      "code" => "code-1",
      "state" => "state-1"
    }
  end

  defp jarm_opts(extra \\ []) do
    Keyword.merge([issuer: @issuer, client_id: @client_id, now: @now], extra)
  end

  defp metadata(alg) do
    %{
      "issuer" => @issuer,
      "authorization_endpoint" => "#{@issuer}/authorize",
      "token_endpoint" => "#{@issuer}/token",
      "jwks_uri" => "#{@issuer}/jwks",
      "response_types_supported" => ["code"],
      "subject_types_supported" => ["public"],
      "id_token_signing_alg_values_supported" => Enum.uniq(["RS256", alg]),
      "code_challenge_methods_supported" => ["S256"]
    }
  end

  defp token_endpoint_plug(id_token, access_token, keyset) do
    fn conn ->
      case conn.request_path do
        "/token" ->
          json(conn, 200, %{
            "access_token" => access_token,
            "token_type" => "Bearer",
            "id_token" => id_token
          })

        "/jwks" ->
          json(conn, 200, keyset)
      end
    end
  end

  defp sign(key, alg, claims, kid, typ \\ "JWT") do
    {_, jwt} =
      key
      |> JOSE.JWT.sign(%{"alg" => alg, "kid" => kid, "typ" => typ}, claims)
      |> JOSE.JWS.compact()

    jwt
  end

  defp jwks(key, alg, kid), do: %{"keys" => [public_map(key, alg, kid)]}

  defp public_map(key, alg, kid) do
    map = key |> JOSE.JWK.to_public_map() |> elem(1)

    map
    |> maybe_put("alg", alg)
    |> maybe_put("kid", kid)
    |> Map.put("use", "sig")
  end

  defp private_map(key), do: key |> JOSE.JWK.to_map() |> elem(1)

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp reference_hash(value, :Ed25519) do
    value
    |> then(&:crypto.hash(:sha512, &1))
    |> binary_part(0, 32)
    |> Base.url_encode64(padding: false)
  end

  defp reference_hash(value, :Ed448) do
    value
    |> then(&JOSE.sha3_module().shake256(&1, 114))
    |> binary_part(0, 57)
    |> Base.url_encode64(padding: false)
  end

  defp protected_alg(jwt) do
    jwt |> JOSE.JWS.peek_protected() |> JSON.decode!() |> Map.fetch!("alg")
  end

  defp json(conn, status, body) do
    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.send_resp(status, JSON.encode!(body))
  end

  defp node_reference(payload) do
    case System.find_executable("node") do
      nil ->
        {:error, :node_unavailable}

      node ->
        path =
          Path.join(
            System.tmp_dir!(),
            "attesto_client_edwards_#{System.unique_integer([:positive])}.json"
          )

        File.write!(path, JSON.encode!(payload))

        try do
          case System.cmd(node, [node_reference_script(), path], stderr_to_stdout: true) do
            {output, 0} -> {:ok, output |> String.trim() |> JSON.decode!()}
            {output, _status} -> {:error, String.trim(output)}
          end
        after
          File.rm(path)
        end
    end
  end

  defp node_available? do
    case System.find_executable("node") do
      nil ->
        false

      node ->
        probe =
          "const c=require('crypto');" <>
            "c.generateKeyPairSync('ed448');" <>
            "c.createHash('shake256',{outputLength:114}).update('probe').digest();"

        match?({_output, 0}, System.cmd(node, ["-e", probe], stderr_to_stdout: true))
    end
  end

  defp node_reference_script do
    Path.expand("../../test_support/node/edwards_reference.js", __DIR__)
  end
end
