defmodule AttestoClient.AuthorizationProfileBindingTest do
  use ExUnit.Case, async: true

  alias AttestoClient.AuthorizationCode
  alias AttestoClient.AuthorizationTransaction.Store
  alias AttestoClient.AuthorizationTransaction.Store.ETS
  alias AttestoClient.OAuthHTTP
  alias AttestoClient.WalletAttestation
  alias Plug.Conn.Query

  @issuer "https://issuer.example"
  @protected ~w(client_id redirect_uri response_type scope state nonce code_challenge code_challenge_method dpop_jkt request_uri request request_uri_method client_secret client_assertion client_assertion_type grant_type code code_verifier)

  defp store, do: {ETS, start_supervised!(ETS, id: make_ref())}

  defp options(extra \\ []) do
    Keyword.merge(
      [
        protocol: :oauth,
        scopes: ["credential"],
        issuer: @issuer,
        client_id: "client",
        redirect_uri: "https://client.example/callback",
        browser_binding: "browser",
        metadata: %{
          "issuer" => @issuer,
          "authorization_endpoint" => @issuer <> "/authorize",
          "token_endpoint" => @issuer <> "/token",
          "code_challenge_methods_supported" => ["S256"],
          "pushed_authorization_request_endpoint" => @issuer <> "/par"
        }
      ],
      extra
    )
  end

  defp authenticated_options(profile, plug) do
    key = JOSE.JWK.generate_key({:ec, "P-256"})
    dpop = JOSE.JWK.generate_key({:ec, "P-256"})

    options([
      {profile, true},
      client_auth: {:private_key_jwt, key},
      dpop: dpop,
      req_options: [plug: plug]
    ])
  end

  defp par(conn) do
    conn
    |> Plug.Conn.put_status(201)
    |> Req.Test.json(%{"request_uri" => "urn:example:par", "expires_in" => 90})
  end

  test "profiles reject unauthenticated PAR before discovery or any endpoint call" do
    owner = self()

    spy = fn conn ->
      send(owner, :http)
      par(conn)
    end

    for profile <- [:haip, :fapi?], auth <- [:none, nil] do
      opts = options([{profile, true}, client_auth: auth, req_options: [plug: spy]])
      assert {:error, :profile_client_auth_required} = AuthorizationCode.start(store(), opts)

      assert {:error, :profile_client_auth_required} =
               AuthorizationCode.start(store(), Keyword.delete(opts, :metadata))
    end

    refute_receive :http
  end

  test "profiles require actual DPoP signing material before discovery" do
    owner = self()

    spy = fn conn ->
      send(owner, :http)
      par(conn)
    end

    for profile <- [:haip, :fapi?] do
      opts = authenticated_options(profile, spy) |> Keyword.delete(:dpop)
      assert {:error, :profile_dpop_required} = AuthorizationCode.start(store(), opts)

      assert {:error, :profile_dpop_required} =
               AuthorizationCode.start(store(), Keyword.delete(opts, :metadata))
    end

    refute_receive :http
  end

  test "FAPI disallows secret authentication and ambiguous profile selection" do
    assert {:error, :unsupported_profile_client_auth} =
             AuthorizationCode.start(
               store(),
               options(fapi?: true, client_auth: {:client_secret_basic, "secret"})
             )

    assert {:error, :conflicting_profiles} =
             AuthorizationCode.start(store(), options(haip: true, fapi?: true))
  end

  test "selected profile and public authentication identity are retained in the transaction" do
    store = store()
    opts = authenticated_options(:fapi?, &par/1)
    assert {:ok, started} = AuthorizationCode.start(store, opts)
    assert {:ok, transaction} = Store.take(store, started.state)
    assert Map.get(transaction, :profile) == :fapi
    assert %{method: :private_key_jwt, jkt: jkt} = Map.get(transaction, :client_auth_binding)
    assert is_binary(jkt)
    refute Map.has_key?(Map.get(transaction, :client_auth_binding), :key)
  end

  test "missing or changed authentication at callback rejects before token HTTP" do
    owner = self()

    spy = fn conn ->
      send(owner, conn.request_path)
      par(conn)
    end

    for profile <- [:haip, :fapi?],
        mutation <- [:missing, :key, :method, :audience, :client_id] do
      store = store()
      opts = authenticated_options(profile, spy)
      assert {:ok, started} = AuthorizationCode.start(store, opts)
      assert_receive "/par"
      callback = opts |> Keyword.put(:haip, false) |> Keyword.put(:fapi?, false)

      callback =
        case mutation do
          :missing ->
            Keyword.delete(callback, :client_auth)

          :key ->
            Keyword.put(
              callback,
              :client_auth,
              {:private_key_jwt, JOSE.JWK.generate_key({:ec, "P-256"})}
            )

          :method ->
            Keyword.put(callback, :client_auth, {:client_secret_post, "secret"})

          :audience ->
            Keyword.put(
              callback,
              :client_auth,
              {:private_key_jwt, elem(opts[:client_auth], 1), [audience: "https://other.example"]}
            )

          :client_id ->
            Keyword.put(callback, :client_id, "other")
        end

      assert {:error, _reason} =
               AuthorizationCode.callback(
                 store,
                 %{"state" => started.state, "code" => "code", "iss" => @issuer},
                 callback
               )

      refute_receive "/token"
    end
  end

  test "pinned profile never accepts Bearer or absent token type even with caller flags false" do
    for profile <- [:haip, :fapi?], type <- [nil, "Bearer", "dPoP"] do
      plug = fn conn ->
        if conn.request_path == "/par" do
          par(conn)
        else
          assert [_proof] = Plug.Conn.get_req_header(conn, "dpop")
          {:ok, bytes, conn} = Plug.Conn.read_body(conn)
          assert is_binary(Query.decode(bytes)["client_assertion"])
          response = %{"access_token" => "access"}
          response = if type, do: Map.put(response, "token_type", type), else: response
          Req.Test.json(conn, response)
        end
      end

      store = store()
      opts = authenticated_options(profile, plug)
      assert {:ok, started} = AuthorizationCode.start(store, opts)

      result =
        AuthorizationCode.callback(
          store,
          %{"state" => started.state, "code" => "code", "iss" => @issuer},
          opts |> Keyword.put(:haip, false) |> Keyword.put(:fapi?, false)
        )

      if type == "dPoP",
        do: assert(match?({:ok, _}, result)),
        else: assert(match?({:error, _}, result))
    end
  end

  test "discovered endpoints cannot inject protected exact names or decoded bracket aliases" do
    owner = self()

    spy = fn conn ->
      send(owner, :http)
      par(conn)
    end

    for endpoint <- [
          "authorization_endpoint",
          "pushed_authorization_request_endpoint",
          "token_endpoint"
        ],
        field <- @protected,
        suffix <- ["", "[]", "[value]"],
        par? <- [false, true] do
      params = URI.encode_query(%{(field <> suffix) => "override"})
      assert Map.has_key?(Query.decode(params), field)
      metadata = options()[:metadata]
      metadata = Map.update!(metadata, endpoint, &(&1 <> "?" <> params))

      assert {:error, :invalid_endpoint_query} =
               AuthorizationCode.start(
                 store(),
                 options(metadata: metadata, par: par?, req_options: [plug: spy])
               )
    end

    refute_receive :http
  end

  test "duplicate decoded endpoint roots reject while benign fixed query values survive" do
    metadata = options()[:metadata]

    for query <- ["tenant=a&tenant=b", "tenant=a&ten%61nt=b", "tenant=x&tenant[]=y"] do
      assert {:error, :invalid_endpoint_query} =
               AuthorizationCode.start(
                 store(),
                 options(
                   metadata:
                     Map.put(
                       metadata,
                       "authorization_endpoint",
                       @issuer <> "/authorize?" <> query
                     )
                 )
               )
    end

    assert {:ok, started} =
             AuthorizationCode.start(
               store(),
               options(
                 metadata:
                   Map.put(
                     metadata,
                     "authorization_endpoint",
                     @issuer <> "/authorize?tenant=fixed"
                   )
               )
             )

    assert Query.decode(URI.parse(started.url).query)["tenant"] == "fixed"
  end

  test "JAR form and token callers cannot bypass endpoint query protection" do
    owner = self()

    spy = fn conn ->
      send(owner, :http)
      Req.Test.json(conn, %{})
    end

    for field <- @protected, suffix <- ["", "[]", "[0]"] do
      endpoint = @issuer <> "/par?" <> URI.encode_query(%{(field <> suffix) => "override"})

      assert {:error, :invalid_endpoint_query} =
               OAuthHTTP.post_form(
                 endpoint,
                 %{"request" => "signed-request"},
                 client_id: "client",
                 req_options: [plug: spy]
               )
    end

    refute_receive :http
  end

  test "invalid authentication options or public-only keys fail before discovery" do
    owner = self()

    spy = fn conn ->
      send(owner, :http)
      par(conn)
    end

    key = JOSE.JWK.generate_key({:ec, "P-256"})
    {_, public} = JOSE.JWK.to_public_map(key)

    for auth <- [
          {:private_key_jwt, public},
          {:private_key_jwt, key, [audience: "https://other.example"]},
          {:private_key_jwt, key, [audience: @issuer, audience: @issuer]},
          {:private_key_jwt, key, [alg: "none"]},
          {:private_key_jwt, key, [client_id: "other"]}
        ] do
      assert {:error, :invalid_profile_client_auth} =
               AuthorizationCode.start(
                 store(),
                 options(haip: true, client_auth: auth, dpop: key, req_options: [plug: spy])
                 |> Keyword.delete(:metadata)
               )
    end

    refute_receive :http
  end

  test "explicit advertised auth-method contradictions fail before PAR" do
    owner = self()

    spy = fn conn ->
      send(owner, :http)
      par(conn)
    end

    opts = authenticated_options(:fapi?, spy)
    metadata = Map.put(opts[:metadata], "token_endpoint_auth_methods_supported", ["none"])

    assert {:error, :unsupported_profile_client_auth} =
             AuthorizationCode.start(store(), Keyword.put(opts, :metadata, metadata))

    refute_receive :http
  end

  test "FAPI incompatible signing choices reject before discovery" do
    owner = self()

    spy = fn conn ->
      send(owner, :http)
      par(conn)
    end

    key = JOSE.JWK.generate_key({:ec, "P-256"})
    incompatible_dpop = JOSE.JWK.generate_key({:ec, "P-384"})

    opts =
      options(
        fapi?: true,
        client_auth: {:private_key_jwt, key},
        dpop: incompatible_dpop,
        req_options: [plug: spy]
      )
      |> Keyword.delete(:metadata)

    assert {:error, :invalid_profile_dpop_key} = AuthorizationCode.start(store(), opts)

    assert {:error, :invalid_profile_client_auth} =
             AuthorizationCode.start(
               store(),
               Keyword.merge(opts, dpop: key, client_auth: {:private_key_jwt, incompatible_dpop})
             )

    refute_receive :http
  end

  test "HAIP attestation pins its declared client and instance key through challenge renewal" do
    curve = {:namedCurve, {1, 2, 840, 10_045, 3, 1, 7}}

    data =
      :public_key.pkix_test_data(%{root: [key: curve], intermediates: [], peer: [key: curve]})

    provider = data[:key] |> elem(1) |> JOSE.JWK.from_der()
    chain = [Base.encode64(data[:cert])]
    key = JOSE.JWK.generate_key({:ec, "P-256"})
    other = JOSE.JWK.generate_key({:ec, "P-256"})

    {:ok, attestation} =
      WalletAttestation.attestation(provider, client_id: "client", instance_key: key, x5c: chain)

    owner = self()

    plug = fn conn ->
      assert [_attestation] = Plug.Conn.get_req_header(conn, "oauth-client-attestation")
      assert [_pop] = Plug.Conn.get_req_header(conn, "oauth-client-attestation-pop")

      if conn.request_path == "/par",
        do: par(conn),
        else:
          (
            send(owner, :token)
            Req.Test.json(conn, %{"access_token" => "access", "token_type" => "DPoP"})
          )
    end

    opts =
      options(
        haip: true,
        dpop: key,
        req_options: [plug: plug],
        client_auth:
          {:client_attestation, attestation, key, [audience: @issuer, challenge: "initial"]}
      )

    store = store()
    assert {:ok, started} = AuthorizationCode.start(store, opts)

    callback =
      Keyword.put(
        opts,
        :client_auth,
        {:client_attestation, attestation, key, [audience: @issuer, challenge: "renewed"]}
      )

    assert {:ok, _completed} =
             AuthorizationCode.callback(
               store,
               %{"state" => started.state, "code" => "code", "iss" => @issuer},
               callback
             )

    assert_receive :token

    for {declared_client, instance} <- [{"other", key}, {"client", other}] do
      {:ok, wrong} =
        WalletAttestation.attestation(provider,
          client_id: declared_client,
          instance_key: instance,
          x5c: chain
        )

      assert {:error, :invalid_profile_client_auth} =
               AuthorizationCode.start(
                 store(),
                 Keyword.put(
                   opts,
                   :client_auth,
                   {:client_attestation, wrong, key, [audience: @issuer]}
                 )
               )
    end

    refute_receive :token

    assert {:ok, started} = AuthorizationCode.start(store, opts)

    {:ok, renewed} =
      WalletAttestation.attestation(provider,
        client_id: "client",
        instance_key: key,
        x5c: chain,
        lifetime: 7_200
      )

    assert {:ok, _completed} =
             AuthorizationCode.callback(
               store,
               %{"state" => started.state, "code" => "code", "iss" => @issuer},
               Keyword.put(
                 opts,
                 :client_auth,
                 {:client_attestation, renewed, key, [audience: @issuer]}
               )
             )

    assert_receive :token
  end

  test "generic transactions retain existing unauthenticated and secret authentication behavior" do
    store = store()
    assert {:ok, started} = AuthorizationCode.start(store, options())

    assert {:ok, _completed} =
             AuthorizationCode.callback(
               store,
               %{"state" => started.state, "code" => "code"},
               browser_binding: "browser",
               client_auth: {:client_secret_basic, "secret"},
               req_options: [
                 plug: fn conn ->
                   assert [_auth] = Plug.Conn.get_req_header(conn, "authorization")
                   Req.Test.json(conn, %{"access_token" => "access", "token_type" => "Bearer"})
                 end
               ]
             )
  end

  test "HAIP requires a scope and FAPI rejects insecure explicit OIDC algorithms before discovery" do
    owner = self()

    spy = fn conn ->
      send(owner, :http)
      par(conn)
    end

    assert {:error, :profile_scope_required} =
             AuthorizationCode.start(
               store(),
               authenticated_options(:haip, spy)
               |> Keyword.put(:scopes, [])
               |> Keyword.delete(:metadata)
             )

    assert {:error, :unsupported_alg} =
             AuthorizationCode.start(
               store(),
               authenticated_options(:fapi?, spy)
               |> Keyword.merge(protocol: :oidc, scopes: ["openid"], id_token_alg: "RS256")
               |> Keyword.delete(:metadata)
             )

    refute_receive :http
  end

  test "FAPI chooses an advertised compliant default and carries local profile into tokens" do
    key = JOSE.JWK.generate_key({:ec, "P-256"})
    {_, public} = JOSE.JWK.to_public_map(key)
    store = store()
    # The transaction store remains authoritative; retain only the nonce for
    # the synthetic provider's signed ID Token.
    {:ok, nonce_store} = Agent.start_link(fn -> nil end)

    plug = fn conn ->
      case conn.request_path do
        "/jwks" ->
          Req.Test.json(conn, %{"keys" => [public]})

        "/par" ->
          {:ok, bytes, conn} = Plug.Conn.read_body(conn)
          Agent.update(nonce_store, fn _ -> Query.decode(bytes)["nonce"] end)
          par(conn)

        "/token" ->
          now = System.system_time(:second)

          {:ok, id_token} =
            AttestoClient.Builder.sign(key, %{"alg" => "ES256", "typ" => "JWT"}, %{
              "iss" => @issuer,
              "sub" => "subject",
              "aud" => "client",
              "iat" => now,
              "exp" => now + 60,
              "nonce" => Agent.get(nonce_store, & &1)
            })

          Req.Test.json(conn, %{
            "access_token" => "access",
            "token_type" => "DPoP",
            "id_token" => id_token
          })
      end
    end

    opts =
      authenticated_options(:fapi?, plug) |> Keyword.merge(protocol: :oidc, scopes: ["openid"])

    metadata =
      opts[:metadata]
      |> Map.merge(%{
        "jwks_uri" => @issuer <> "/jwks",
        "id_token_signing_alg_values_supported" => ["ES256"],
        "response_types_supported" => ["code"],
        "subject_types_supported" => ["public"]
      })

    opts = Keyword.put(opts, :metadata, metadata)
    assert {:ok, started} = AuthorizationCode.start(store, opts)

    assert {:ok, %{tokens: tokens}} =
             AuthorizationCode.callback(
               store,
               %{"state" => started.state, "code" => "code", "iss" => @issuer},
               opts
             )

    assert tokens.profile == :fapi
    assert tokens.client_id == "client"
    assert tokens.issuer == @issuer
    assert tokens.client_auth_binding.method == :private_key_jwt

    assert {:error, :invalid_metadata} =
             AuthorizationCode.start(
               store(),
               opts |> Keyword.delete(:fapi?) |> Keyword.put(:id_token_alg, "ES256")
             )

    assert {:error, :invalid_metadata} =
             AuthorizationCode.start(
               store(),
               Keyword.put(
                 opts,
                 :metadata,
                 Map.put(metadata, "id_token_signing_alg_values_supported", [])
               )
             )

    assert {:error, :unsupported_alg} =
             AuthorizationCode.start(
               store(),
               Keyword.put(
                 opts,
                 :metadata,
                 Map.put(metadata, "id_token_signing_alg_values_supported", ["RS256"])
               )
             )
  end

  test "generic unsolicited DPoP responses require signing material" do
    store = store()
    assert {:ok, started} = AuthorizationCode.start(store, options())

    assert {:error, :missing_dpop_key} =
             AuthorizationCode.callback(
               store,
               %{"state" => started.state, "code" => "code"},
               browser_binding: "browser",
               req_options: [
                 plug: fn conn ->
                   Req.Test.json(conn, %{"access_token" => "access", "token_type" => "DPoP"})
                 end
               ]
             )
  end

  test "pre-upgrade generic stored transactions remain usable without new fields" do
    store = store()
    assert {:ok, started} = AuthorizationCode.start(store, options())
    assert {:ok, transaction} = Store.take(store, started.state)
    legacy = Map.drop(transaction, [:profile, :client_auth_binding])
    assert :ok = Store.put_new(store, started.state, legacy, 10_000)

    assert {:ok, %{tokens: tokens}} =
             AuthorizationCode.callback(
               store,
               %{"state" => started.state, "code" => "code"},
               browser_binding: "browser",
               req_options: [
                 plug: fn conn ->
                   Req.Test.json(conn, %{"access_token" => "access", "token_type" => "Bearer"})
                 end
               ]
             )

    assert tokens.profile == :generic
    assert tokens.client_auth_binding == nil
  end

  test "pre-upgrade protected transactions require restart instead of inferred profile" do
    owner = self()
    store = store()
    assert {:ok, started} = AuthorizationCode.start(store, options())
    assert {:ok, transaction} = Store.take(store, started.state)

    legacy =
      transaction
      |> Map.drop([:profile, :client_auth_binding])
      |> Map.put(:require_response_issuer, true)

    assert :ok = Store.put_new(store, started.state, legacy, 10_000)

    assert {:error, :invalid_profile} =
             AuthorizationCode.callback(
               store,
               %{"state" => started.state, "code" => "code", "iss" => @issuer},
               browser_binding: "browser",
               req_options: [
                 plug: fn conn ->
                   send(owner, :unexpected_http)
                   Req.Test.json(conn, %{})
                 end
               ]
             )

    refute_receive :unexpected_http
  end
end
