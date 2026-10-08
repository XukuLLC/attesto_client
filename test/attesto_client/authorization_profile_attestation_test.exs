defmodule AttestoClient.AuthorizationProfileAttestationTest do
  use ExUnit.Case, async: true

  alias AttestoClient.AuthorizationCode
  alias AttestoClient.AuthorizationProfile
  alias AttestoClient.AuthorizationTransaction.Store.ETS
  alias AttestoClient.RefreshCoordinator
  alias AttestoClient.Token
  alias AttestoClient.TokenSet
  alias AttestoClient.Wallet.Presentation.CertificateTrust
  alias AttestoClient.WalletAttestation

  @issuer "https://issuer.example"
  @provider "https://provider.example"

  setup_all do
    curve = {:namedCurve, {1, 2, 840, 10_045, 3, 1, 7}}

    data =
      :public_key.pkix_test_data(%{root: [key: curve], intermediates: [], peer: [key: curve]})

    rotated =
      :public_key.pkix_test_data(%{root: [key: curve], intermediates: [], peer: [key: curve]})

    %{
      provider: data[:key] |> elem(1) |> JOSE.JWK.from_der(),
      certificate: data[:cert],
      anchors: data[:cacerts],
      rotated_provider: rotated[:key] |> elem(1) |> JOSE.JWK.from_der(),
      rotated_certificate: rotated[:cert],
      rotated_anchors: rotated[:cacerts]
    }
  end

  setup context do
    key = JOSE.JWK.generate_key({:ec, "P-256"})
    dpop = JOSE.JWK.generate_key({:ec, "P-256"})
    Map.merge(context, %{instance: key, dpop: dpop, now: System.system_time(:second)})
  end

  defp attestation(context, claims \\ %{}, header \\ %{}) do
    {:ok, jwt} =
      WalletAttestation.attestation(context.provider,
        issuer: @provider,
        client_id: "client",
        instance_key: context.instance,
        x5c: [Base.encode64(context.certificate)],
        now: context.now,
        lifetime: 60
      )

    {:ok, payload} = Attesto.JWS.peek_json(jwt, :payload)
    {:ok, protected} = Attesto.JWS.peek_json(jwt, :protected)

    Attesto.JWS.sign_compact_jwk(
      context.provider,
      Map.merge(protected, header),
      Map.merge(payload, claims)
      |> Enum.reject(fn {_key, value} -> is_nil(value) end)
      |> Map.new()
    )
  end

  defp options(context, attestation, plug) do
    [
      protocol: :oauth,
      haip: true,
      issuer: @issuer,
      client_id: "client",
      redirect_uri: "https://client.example/callback",
      browser_binding: "browser",
      scopes: ["credential"],
      dpop: context.dpop,
      client_auth: {:client_attestation, attestation, context.instance, [audience: @issuer]},
      req_options: [plug: plug],
      metadata: %{
        "issuer" => @issuer,
        "authorization_endpoint" => @issuer <> "/authorize",
        "token_endpoint" => @issuer <> "/token",
        "pushed_authorization_request_endpoint" => @issuer <> "/par",
        "code_challenge_methods_supported" => ["S256"]
      }
    ]
  end

  defp store, do: {ETS, start_supervised!(ETS, id: make_ref())}

  test "HAIP rejects missing and malformed provider certificates before discovery", context do
    owner = self()

    spy = fn conn ->
      send(owner, :http)
      Req.Test.json(conn, %{})
    end

    encoded = Base.encode64(context.certificate)

    for chain <- [
          nil,
          [],
          "certificate",
          [nil],
          [42],
          [""],
          ["!"],
          [Base.encode64("not a certificate")],
          [Base.encode64(context.certificate <> <<0>>)],
          [Base.encode64(:binary.copy(<<0>>, 65_537))],
          List.duplicate(encoded, 9)
        ] do
      jwt = attestation(context, %{}, %{"x5c" => chain})
      opts = options(context, jwt, spy) |> Keyword.delete(:metadata)
      assert {:error, :invalid_profile_client_auth} = AuthorizationCode.start(store(), opts)
    end

    {:ok, no_chain} =
      WalletAttestation.attestation(context.provider,
        issuer: @provider,
        client_id: "client",
        instance_key: context.instance
      )

    assert {:error, :invalid_profile_client_auth} =
             AuthorizationCode.start(store(), options(context, no_chain, spy))

    refute_receive :http
  end

  test "HAIP accepts certificate-backed attestations without the optional issuer claim",
       context do
    {:ok, no_issuer} =
      WalletAttestation.attestation(context.provider,
        client_id: "client",
        instance_key: context.instance,
        x5c: [Base.encode64(context.certificate)]
      )

    opts =
      options(context, no_issuer, fn conn ->
        conn
        |> Plug.Conn.put_status(201)
        |> Req.Test.json(%{"request_uri" => "urn:example:par", "expires_in" => 90})
      end)

    assert {:ok, _started} = AuthorizationCode.start(store(), opts)
  end

  test "same-provider client and instance renewal survives callback and expired old attestation refresh",
       context do
    {:ok, clock} = Agent.start_link(fn -> context.now end)
    owner = self()

    plug = fn conn ->
      [jwt] = Plug.Conn.get_req_header(conn, "oauth-client-attestation")
      {:ok, %{"x5c" => [encoded]}} = Attesto.JWS.peek_json(jwt, :protected)
      {:ok, der} = Base.decode64(encoded)
      assert der in [context.certificate, context.rotated_certificate]

      {:ok, verified} =
        CertificateTrust.verify([der],
          trusted_certificates: context.anchors ++ context.rotated_anchors
        )

      public = JOSE.JWK.from_map(verified.public_key)
      assert {true, %JOSE.JWT{fields: claims}, _} = JOSE.JWT.verify_strict(public, ["ES256"], jwt)
      assert claims["iss"] in [nil, @provider]
      assert claims["sub"] == "client"
      assert claims["exp"] > Agent.get(clock, & &1)
      send(owner, {:http, conn.request_path, claims["jti"]})

      if conn.request_path == "/par" do
        conn
        |> Plug.Conn.put_status(201)
        |> Req.Test.json(%{"request_uri" => "urn:example:par", "expires_in" => 90})
      else
        Req.Test.json(conn, %{
          "access_token" => "access",
          "refresh_token" => "refresh",
          "token_type" => "DPoP"
        })
      end
    end

    initial = attestation(context, %{"jti" => "initial"})
    store = store()
    assert {:ok, started} = AuthorizationCode.start(store, options(context, initial, plug))
    assert_receive {:http, "/par", "initial"}

    callback_jwt =
      attestation(context, %{"jti" => "callback", "exp" => context.now + 120, "iss" => nil})

    assert {:ok, %{tokens: tokens}} =
             AuthorizationCode.callback(
               store,
               %{"state" => started.state, "code" => "code", "iss" => @issuer},
               options(context, callback_jwt, plug)
             )

    assert_receive {:http, "/token", "callback"}
    assert tokens.client_auth_binding.subject == "client"
    refute Map.has_key?(tokens.client_auth_binding, :attestation_digest)

    Agent.update(clock, fn _ -> context.now + 180 end)
    {:ok, initial_claims} = Attesto.JWS.peek_json(initial, :payload)
    assert initial_claims["exp"] < Agent.get(clock, & &1)

    rotated_context = %{
      context
      | provider: context.rotated_provider,
        certificate: context.rotated_certificate
    }

    renewed =
      attestation(
        rotated_context,
        %{"jti" => "renewed", "iat" => context.now + 180, "exp" => context.now + 240},
        %{"kid" => "renewed-certificate-key"}
      )

    coordinator = start_supervised!(RefreshCoordinator, id: make_ref())

    refresh_opts =
      options(context, renewed, plug)
      |> Keyword.merge(
        token_endpoint: @issuer <> "/token",
        subject: "subject",
        jwks: %{"keys" => []}
      )

    assert {:ok, result} = Token.refresh(coordinator, :record, tokens, refresh_opts)
    assert_receive {:http, "/token", "renewed"}
    assert result.tokens.client_auth_binding == tokens.client_auth_binding
  end

  test "renewal cannot change client instance or authentication key before HTTP", context do
    owner = self()

    spy = fn conn ->
      send(owner, {:http, conn.request_path})

      conn
      |> Plug.Conn.put_status(201)
      |> Req.Test.json(%{"request_uri" => "urn:example:par", "expires_in" => 90})
    end

    original = attestation(context)
    opts = options(context, original, spy)
    assert {:ok, binding} = AuthorizationProfile.bind(:haip, "client", @issuer, opts)
    {:ok, jkt} = TokenSet.dpop_thumbprint(opts)

    tokens = %TokenSet{
      access_token: "access",
      token_type: "DPoP",
      refresh_token: "refresh",
      profile: :haip,
      client_auth_binding: binding,
      client_id: "client",
      issuer: @issuer,
      dpop_jkt: jkt
    }

    coordinator = start_supervised!(RefreshCoordinator, id: make_ref())
    other = JOSE.JWK.generate_key({:ec, "P-256"})
    public = JOSE.JWK.to_public_map(other) |> elem(1)

    for {claims, key, expected} <- [
          {%{"sub" => "other-client"}, context.instance, :invalid_profile_client_auth},
          {%{"cnf" => %{"jwk" => public}}, context.instance, :invalid_profile_client_auth},
          {%{}, other, :invalid_profile_client_auth}
        ] do
      jwt = attestation(context, claims)

      changed =
        Keyword.put(opts, :client_auth, {:client_attestation, jwt, key, [audience: @issuer]})

      assert {:error, ^expected} =
               AuthorizationProfile.check(:haip, binding, "client", @issuer, changed)

      store = store()
      assert {:ok, started} = AuthorizationCode.start(store, opts)
      assert_receive {:http, "/par"}

      assert {:error, ^expected} =
               AuthorizationCode.callback(
                 store,
                 %{"state" => started.state, "code" => "code", "iss" => @issuer},
                 changed
               )

      assert {:error, ^expected} =
               Token.refresh(
                 coordinator,
                 make_ref(),
                 tokens,
                 Keyword.merge(changed, token_endpoint: @issuer <> "/token", subject: "subject")
               )
    end

    refute_receive {:http, "/token"}
  end

  test "renewal retains the instance PoP algorithm and authentication method", context do
    instance = JOSE.JWK.generate_key({:rsa, 2_048})
    context = %{context | instance: instance}
    jwt = attestation(context)
    opts = options(context, jwt, fn conn -> Req.Test.json(conn, %{}) end)

    opts =
      Keyword.put(
        opts,
        :client_auth,
        {:client_attestation, jwt, instance, [audience: @issuer, alg: "PS256"]}
      )

    assert {:ok, binding} = AuthorizationProfile.bind(:haip, "client", @issuer, opts)

    changed_alg =
      Keyword.put(
        opts,
        :client_auth,
        {:client_attestation, jwt, instance, [audience: @issuer, alg: "RS256"]}
      )

    changed_method = Keyword.put(opts, :client_auth, {:private_key_jwt, instance, [alg: "PS256"]})

    assert {:error, :client_auth_mismatch} =
             AuthorizationProfile.check(:haip, binding, "client", @issuer, changed_alg)

    assert {:error, :client_auth_mismatch} =
             AuthorizationProfile.check(:haip, binding, "client", @issuer, changed_method)
  end

  test "provider key certificates and optional issuer are not local instance identity", context do
    initial = attestation(context)
    opts = options(context, initial, fn conn -> Req.Test.json(conn, %{}) end)
    assert {:ok, binding} = AuthorizationProfile.bind(:haip, "client", @issuer, opts)

    curve = {:namedCurve, {1, 2, 840, 10_045, 3, 1, 7}}

    data =
      :public_key.pkix_test_data(%{root: [key: curve], intermediates: [], peer: [key: curve]})

    rotated = %{
      context
      | provider: data[:key] |> elem(1) |> JOSE.JWK.from_der(),
        certificate: data[:cert]
    }

    {:ok, jwt} =
      WalletAttestation.attestation(rotated.provider,
        client_id: "client",
        instance_key: context.instance,
        x5c: [Base.encode64(rotated.certificate)]
      )

    changed =
      Keyword.put(
        opts,
        :client_auth,
        {:client_attestation, jwt, context.instance, [audience: @issuer]}
      )

    assert :ok = AuthorizationProfile.check(:haip, binding, "client", @issuer, changed)

    jwt = attestation(rotated, %{"iss" => "https://renewed-provider.example"})

    changed =
      Keyword.put(
        opts,
        :client_auth,
        {:client_attestation, jwt, context.instance, [audience: @issuer]}
      )

    assert :ok = AuthorizationProfile.check(:haip, binding, "client", @issuer, changed)
  end
end
