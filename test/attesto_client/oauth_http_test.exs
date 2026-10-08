defmodule AttestoClient.OAuthHTTPTest do
  use ExUnit.Case, async: true

  alias AttestoClient.Discovery
  alias AttestoClient.OAuthHTTP

  @endpoint "https://op.example.com/token"

  defp call(client_auth, parent) do
    plug = fn conn ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)

      send(
        parent,
        {:request, Plug.Conn.get_req_header(conn, "authorization"), URI.decode_query(body)}
      )

      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.send_resp(200, JSON.encode!(%{"ok" => true}))
    end

    OAuthHTTP.post_form(@endpoint, %{"grant_type" => "authorization_code"},
      client_id: "client id:one",
      client_auth: client_auth,
      req_options: [plug: plug]
    )
  end

  test "supports public and client_secret_post authentication" do
    assert {:ok, %{"ok" => true}} = call(:none, self())
    assert_receive {:request, [], %{"client_id" => "client id:one"}}

    assert {:ok, %{"ok" => true}} = call({:client_secret_post, "s:e c"}, self())

    assert_receive {:request, [], form}
    assert form["client_id"] == "client id:one"
    assert form["client_secret"] == "s:e c"
  end

  test "form-encodes client_secret_basic credentials before base64" do
    assert {:ok, _response} = call({:client_secret_basic, "s:e c"}, self())
    assert_receive {:request, ["Basic " <> encoded], form}
    assert Base.decode64!(encoded) == "client+id%3Aone:s%3Ae+c"
    refute Map.has_key?(form, "client_id")
    refute Map.has_key?(form, "client_secret")
  end

  test "supports private_key_jwt defaults and registered assertion overrides" do
    key = JOSE.JWK.generate_key({:rsa, 2048})

    assert {:ok, _response} =
             call(
               {:private_key_jwt, key,
                [
                  audience: "https://op.example.com/custom-audience",
                  alg: "RS256",
                  kid: "registered-key",
                  now: 1_700_000_000,
                  jti: "assertion-jti"
                ]},
               self()
             )

    assert_receive {:request, [], form}
    assert form["client_id"] == "client id:one"
    assert form["client_assertion_type"] == AttestoClient.ClientAssertion.assertion_type()

    [header, claims, _signature] = String.split(form["client_assertion"], ".")
    assert %{"alg" => "RS256", "kid" => "registered-key"} = decode_segment(header)

    assert %{
             "iss" => "client id:one",
             "sub" => "client id:one",
             "aud" => "https://op.example.com/custom-audience",
             "jti" => "assertion-jti"
           } = decode_segment(claims)

    assert {:error, :invalid_client_assertion_options} =
             call({:private_key_jwt, key, [algg: "RS256"]}, self())

    assert {:error, :invalid_client_assertion_options} =
             call({:private_key_jwt, key, [alg: "RS256", alg: "PS256"]}, self())
  end

  defp decode_segment(segment) do
    {:ok, json} = Base.url_decode64(segment, padding: false)
    JSON.decode!(json)
  end

  test "private_key_jwt prefers the trusted issuer and retains a deprecated endpoint fallback" do
    key = JOSE.JWK.generate_key({:ec, "P-256"})
    owner = self()

    plug = fn conn ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      assertion = URI.decode_query(body)["client_assertion"]
      send(owner, {:issuer_assertion, assertion})

      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.send_resp(200, "{}")
    end

    opts = [
      client_id: "issuer-client",
      client_auth: {:private_key_jwt, key},
      req_options: [plug: plug]
    ]

    event = [:attesto_client, :client_assertion, :legacy_endpoint_audience]
    handler = "assertion-audience-#{System.unique_integer([:positive])}"

    :ok =
      :telemetry.attach(
        handler,
        event,
        &__MODULE__.handle_legacy_audience/4,
        owner
      )

    on_exit(fn -> :telemetry.detach(handler) end)

    assert {:ok, %{}} = OAuthHTTP.post_form(@endpoint, %{}, opts)
    assert_receive {:issuer_assertion, legacy}
    assert JSON.decode!(JOSE.JWS.peek_payload(legacy))["aud"] == @endpoint
    assert_receive {:legacy_audience, ^event, %{count: 1}, %{}}

    assert {:ok, %{}} =
             OAuthHTTP.post_form(
               @endpoint,
               %{},
               Keyword.put(opts, :issuer, "https://op.example.com")
             )

    assert_receive {:issuer_assertion, assertion}
    assert JSON.decode!(JOSE.JWS.peek_payload(assertion))["aud"] == "https://op.example.com"
    assert JSON.decode!(JOSE.JWS.peek_protected(assertion))["typ"] == "client-authentication+jwt"
    refute_received {:legacy_audience, _, _, _}

    # An explicitly supplied, unusable issuer must never silently fall back.
    assert {:error, {:client_assertion, :invalid_audience}} =
             OAuthHTTP.post_form(@endpoint, %{}, Keyword.put(opts, :issuer, nil))

    refute_received {:issuer_assertion, _}

    for typ <- [nil, "JWT"] do
      auth = {:private_key_jwt, key, [typ: typ, audience: "https://op.example.com"]}

      assert {:ok, %{}} =
               OAuthHTTP.post_form(@endpoint, %{}, Keyword.put(opts, :client_auth, auth))

      assert_receive {:issuer_assertion, assertion}
      assert JSON.decode!(JOSE.JWS.peek_protected(assertion))["typ"] == typ
      refute_received {:legacy_audience, _, _, _}
    end
  end

  @doc false
  def handle_legacy_audience(name, measurements, metadata, pid) do
    send(pid, {:legacy_audience, name, measurements, metadata})
  end

  describe "post_json/4" do
    test "authenticates with a bearer token and returns the decoded JSON body" do
      parent = self()

      plug = fn conn ->
        {:ok, body, conn} = Plug.Conn.read_body(conn)

        send(
          parent,
          {:request, Plug.Conn.get_req_header(conn, "authorization"), JSON.decode!(body)}
        )

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(200, JSON.encode!(%{"ok" => true}))
      end

      assert {:ok, %{"ok" => true}} =
               OAuthHTTP.post_json(
                 "https://issuer.example.com/credential",
                 %{"a" => 1},
                 "access-token",
                 req_options: [plug: plug]
               )

      assert_receive {:request, ["Bearer access-token"], %{"a" => 1}}
    end

    test "surfaces an OAuth-shaped error body, including a retry c_nonce" do
      plug = fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(
          400,
          JSON.encode!(%{"error" => "invalid_proof", "c_nonce" => "fresh-nonce"})
        )
      end

      assert {:error,
              {:oauth_error, 400, %{"error" => "invalid_proof", "c_nonce" => "fresh-nonce"}}} =
               OAuthHTTP.post_json("https://issuer.example.com/credential", %{}, "access-token",
                 req_options: [plug: plug]
               )
    end

    test "rejects a non-https endpoint before making the request" do
      assert {:error, :invalid_endpoint} =
               OAuthHTTP.post_json("http://issuer.example.com/credential", %{}, "at", [])
    end

    test "rejects an invalid resolver instead of silently using system DNS" do
      assert {:error, :invalid_resolver} =
               OAuthHTTP.get_json("https://issuer.example.com/document",
                 resolver: fn _host -> {:ok, []} end
               )
    end

    test "the request deadline includes DNS screening" do
      parent = self()

      slow_resolver = fn _host, _family ->
        send(parent, :dns_screening_started)
        Process.sleep(3_000)
        {:ok, [{93, 184, 216, 34}]}
      end

      started_at = System.monotonic_time(:millisecond)

      assert {:error, :timeout} =
               OAuthHTTP.get_json("https://slow-dns.example/document",
                 resolver: slow_resolver,
                 timeout: 20
               )

      assert_receive :dns_screening_started
      assert System.monotonic_time(:millisecond) - started_at < 1_500
    end

    test "an invalid timeout fails before DNS resolution" do
      parent = self()
      resolver = fn _, _ -> send(parent, :invalid_timeout_resolved) end

      assert {:error, :invalid_timeout} =
               OAuthHTTP.get_json("https://op.example/document", resolver: resolver, timeout: 0)

      refute_receive :invalid_timeout_resolved
    end
  end

  describe "DPoP sender-constraining" do
    defp dpop_claims(proof), do: proof |> JOSE.JWS.peek_payload() |> JSON.decode!()
    defp dpop_header(proof), do: proof |> JOSE.JWS.peek_protected() |> JSON.decode!()

    defp echo_dpop_plug(parent, status \\ 200) do
      fn conn ->
        [proof] = Plug.Conn.get_req_header(conn, "dpop")
        send(parent, {:dpop, proof})

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(status, JSON.encode!(%{"ok" => true}))
      end
    end

    test "post_json binds the proof to the method, uri, and access token (ath)" do
      parent = self()
      key = JOSE.JWK.generate_key({:ec, "P-256"})

      assert {:ok, %{"ok" => true}} =
               OAuthHTTP.post_json(
                 "https://issuer.example.com/credential",
                 %{},
                 "access-token",
                 dpop: key,
                 req_options: [plug: echo_dpop_plug(parent)]
               )

      assert_receive {:dpop, proof}
      assert dpop_header(proof)["typ"] == "dpop+jwt"
      claims = dpop_claims(proof)
      assert claims["htm"] == "POST"
      assert claims["htu"] == "https://issuer.example.com/credential"
      assert claims["ath"] == Attesto.DPoP.compute_ath("access-token")
    end

    test "post_form attaches a proof with no ath (no access token at the token endpoint)" do
      parent = self()
      key = JOSE.JWK.generate_key({:ec, "P-256"})

      assert {:ok, %{"ok" => true}} =
               OAuthHTTP.post_form(
                 "https://op.example.com/token",
                 %{"grant_type" => "authorization_code"},
                 client_id: "c",
                 dpop: key,
                 req_options: [plug: echo_dpop_plug(parent)]
               )

      assert_receive {:dpop, proof}
      claims = dpop_claims(proof)
      assert claims["htm"] == "POST"
      assert claims["htu"] == "https://op.example.com/token"
      refute Map.has_key?(claims, "ath")
    end

    test "retries a use_dpop_nonce challenge once, echoing the server DPoP-Nonce" do
      parent = self()
      key = JOSE.JWK.generate_key({:ec, "P-256"})
      {:ok, counter} = Agent.start_link(fn -> 0 end)

      plug = fn conn ->
        n = Agent.get_and_update(counter, fn c -> {c, c + 1} end)
        [proof] = Plug.Conn.get_req_header(conn, "dpop")
        send(parent, {:attempt, n, proof})

        if n == 0 do
          conn
          |> Plug.Conn.put_resp_header("dpop-nonce", "server-nonce-xyz")
          |> Plug.Conn.put_resp_content_type("application/json")
          |> Plug.Conn.send_resp(400, JSON.encode!(%{"error" => "use_dpop_nonce"}))
        else
          conn
          |> Plug.Conn.put_resp_content_type("application/json")
          |> Plug.Conn.send_resp(200, JSON.encode!(%{"ok" => true}))
        end
      end

      assert {:ok, %{"ok" => true}} =
               OAuthHTTP.post_form(
                 "https://op.example.com/token",
                 %{"grant_type" => "authorization_code"},
                 client_id: "c",
                 dpop: key,
                 req_options: [plug: plug]
               )

      assert_receive {:attempt, 0, first}
      assert_receive {:attempt, 1, second}
      refute_receive {:attempt, 2, _}

      refute Map.has_key?(dpop_claims(first), "nonce")
      assert dpop_claims(second)["nonce"] == "server-nonce-xyz"
      # Each attempt carries a distinct proof (a fresh jti), never a replay.
      refute dpop_claims(first)["jti"] == dpop_claims(second)["jti"]

      Agent.stop(counter)
    end

    test "a use_dpop_nonce retry re-authenticates with a fresh client_assertion" do
      parent = self()
      key = JOSE.JWK.generate_key({:ec, "P-256"})
      client_key = JOSE.JWK.generate_key({:ec, "P-256"})
      {:ok, counter} = Agent.start_link(fn -> 0 end)

      plug = fn conn ->
        {:ok, body, conn} = Plug.Conn.read_body(conn)
        form = URI.decode_query(body)

        jti =
          form["client_assertion"] |> JOSE.JWS.peek_payload() |> JSON.decode!() |> Map.get("jti")

        n = Agent.get_and_update(counter, fn c -> {c, c + 1} end)
        send(parent, {:jti, n, jti})

        if n == 0 do
          conn
          |> Plug.Conn.put_resp_header("dpop-nonce", "n-1")
          |> Plug.Conn.put_resp_content_type("application/json")
          |> Plug.Conn.send_resp(400, JSON.encode!(%{"error" => "use_dpop_nonce"}))
        else
          conn
          |> Plug.Conn.put_resp_content_type("application/json")
          |> Plug.Conn.send_resp(200, JSON.encode!(%{"ok" => true}))
        end
      end

      assert {:ok, %{"ok" => true}} =
               OAuthHTTP.post_form(
                 "https://op.example.com/token",
                 %{"grant_type" => "authorization_code"},
                 client_id: "c",
                 client_auth: {:private_key_jwt, client_key},
                 issuer: "https://op.example.com",
                 dpop: key,
                 req_options: [plug: plug]
               )

      assert_receive {:jti, 0, jti0}
      assert_receive {:jti, 1, jti1}
      assert is_binary(jti0) and is_binary(jti1)
      # The retried assertion must not replay the first attempt's jti.
      refute jti0 == jti1

      Agent.stop(counter)
    end

    test "surfaces the error and stops after one retry when the challenge repeats" do
      parent = self()
      key = JOSE.JWK.generate_key({:ec, "P-256"})

      plug = fn conn ->
        send(parent, :attempt)

        conn
        |> Plug.Conn.put_resp_header("dpop-nonce", "server-nonce-xyz")
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(400, JSON.encode!(%{"error" => "use_dpop_nonce"}))
      end

      assert {:error, {:oauth_error, 400, %{"error" => "use_dpop_nonce"}}} =
               OAuthHTTP.post_json(
                 "https://issuer.example.com/credential",
                 %{},
                 "access-token",
                 dpop: key,
                 req_options: [plug: plug]
               )

      # Exactly two attempts: the original and one nonce retry.
      assert_receive :attempt
      assert_receive :attempt
      refute_receive :attempt
    end
  end

  describe "client_attestation client authentication" do
    setup do
      provider = JOSE.JWK.generate_key({:ec, "P-256"})
      instance = JOSE.JWK.generate_key({:ec, "P-256"})
      client_id = "wallet-instance-1"
      audience = "https://op.example.com"

      {:ok, attestation} =
        AttestoClient.WalletAttestation.attestation(provider,
          client_id: client_id,
          instance_key: instance
        )

      %{
        provider: provider,
        instance: instance,
        client_id: client_id,
        audience: audience,
        attestation: attestation
      }
    end

    defp capture_headers_plug(parent) do
      fn conn ->
        send(
          parent,
          {:headers,
           %{
             "oauth-client-attestation" =>
               Plug.Conn.get_req_header(conn, "oauth-client-attestation"),
             "oauth-client-attestation-pop" =>
               Plug.Conn.get_req_header(conn, "oauth-client-attestation-pop"),
             "dpop" => Plug.Conn.get_req_header(conn, "dpop")
           }}
        )

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(200, JSON.encode!(%{"ok" => true}))
      end
    end

    test "sets both attestation headers and a PoP that verifies against the attestation", ctx do
      assert {:ok, %{"ok" => true}} =
               OAuthHTTP.post_form(
                 "https://op.example.com/token",
                 %{"grant_type" => "authorization_code"},
                 client_id: ctx.client_id,
                 client_auth:
                   {:client_attestation, ctx.attestation, ctx.instance, audience: ctx.audience},
                 req_options: [plug: capture_headers_plug(self())]
               )

      assert_receive {:headers, headers}
      assert [ctx.attestation] == headers["oauth-client-attestation"]
      assert [pop] = headers["oauth-client-attestation-pop"]

      {_, provider_public} = JOSE.JWK.to_public_map(ctx.provider)

      assert {:ok, %{instance_key: %{jwk: jwk}}} =
               Attesto.WalletAttestation.verify(ctx.attestation, pop,
                 trusted_wallet_provider_jwks: provider_public,
                 audience: ctx.audience,
                 client_id: ctx.client_id
               )

      {_, instance_public} = JOSE.JWK.to_public_map(ctx.instance)
      assert jwk == instance_public
    end

    test "retries a Challenge once with a fresh PoP and reports the newest response Challenge",
         ctx do
      owner = self()

      plug = fn conn ->
        [pop] = Plug.Conn.get_req_header(conn, "oauth-client-attestation-pop")
        claims = JSON.decode!(JOSE.JWS.peek_payload(pop))
        send(owner, {:pop_attempt, claims})
        conn = Plug.Conn.put_resp_content_type(conn, "application/json")

        if claims["challenge"] == "challenge-1" do
          conn
          |> Plug.Conn.put_resp_header("oauth-client-attestation-challenge", "challenge-2")
          |> Plug.Conn.send_resp(200, "{}")
        else
          conn
          |> Plug.Conn.put_resp_header("oauth-client-attestation-challenge", "challenge-1")
          |> Plug.Conn.send_resp(400, JSON.encode!(%{"error" => "use_attestation_challenge"}))
        end
      end

      assert {:ok, %{}} =
               OAuthHTTP.post_form("https://op.example.com/token", %{},
                 client_id: ctx.client_id,
                 client_auth:
                   {:client_attestation, ctx.attestation, ctx.instance,
                    audience: ctx.audience, jti: "pinned-jti", challenge: "obsolete-challenge"},
                 attestation_challenge_received: fn challenge ->
                   send(owner, {:received_challenge, challenge})
                 end,
                 req_options: [plug: plug]
               )

      assert_receive {:pop_attempt, first}
      assert_receive {:pop_attempt, second}
      assert first["jti"] == "pinned-jti"
      assert first["challenge"] == "obsolete-challenge"
      assert second["challenge"] == "challenge-1"
      refute second["jti"] == first["jti"]
      assert_receive {:received_challenge, "challenge-1"}
      assert_receive {:received_challenge, "challenge-2"}
      refute_receive {:pop_attempt, _}
    end

    test "attestation and DPoP challenges each permit one retry and retain the latest values",
         ctx do
      owner = self()
      dpop_key = JOSE.JWK.generate_key({:ec, "P-256"})

      plug = fn conn ->
        [pop] = Plug.Conn.get_req_header(conn, "oauth-client-attestation-pop")
        [proof] = Plug.Conn.get_req_header(conn, "dpop")
        pop_claims = JSON.decode!(JOSE.JWS.peek_payload(pop))
        dpop_claims = JSON.decode!(JOSE.JWS.peek_payload(proof))
        send(owner, {:combined_attempt, pop_claims, dpop_claims})
        conn = Plug.Conn.put_resp_content_type(conn, "application/json")

        cond do
          pop_claims["challenge"] == nil ->
            conn
            |> Plug.Conn.put_resp_header("oauth-client-attestation-challenge", "challenge-1")
            |> Plug.Conn.send_resp(400, JSON.encode!(%{"error" => "use_attestation_challenge"}))

          dpop_claims["nonce"] == nil ->
            conn
            |> Plug.Conn.put_resp_header("oauth-client-attestation-challenge", "challenge-2")
            |> Plug.Conn.put_resp_header("dpop-nonce", "nonce-1")
            |> Plug.Conn.send_resp(400, JSON.encode!(%{"error" => "use_dpop_nonce"}))

          true ->
            Plug.Conn.send_resp(conn, 200, "{}")
        end
      end

      assert {:ok, %{}} =
               OAuthHTTP.post_form("https://op.example.com/token", %{},
                 client_id: ctx.client_id,
                 client_auth:
                   {:client_attestation, ctx.attestation, ctx.instance, audience: ctx.audience},
                 dpop: dpop_key,
                 req_options: [plug: plug]
               )

      assert_receive {:combined_attempt, pop1, dpop1}
      assert_receive {:combined_attempt, pop2, dpop2}
      assert_receive {:combined_attempt, pop3, dpop3}
      assert pop2["challenge"] == "challenge-1"
      assert pop3["challenge"] == "challenge-2"
      assert dpop3["nonce"] == "nonce-1"
      assert length(Enum.uniq(Enum.map([pop1, pop2, pop3], & &1["jti"]))) == 3
      assert length(Enum.uniq(Enum.map([dpop1, dpop2, dpop3], & &1["jti"]))) == 3
      refute_receive {:combined_attempt, _, _}
    end

    test "repeated or incomplete Challenge errors cannot retry indefinitely", ctx do
      owner = self()

      for header <- ["fresh-challenge", nil] do
        plug = fn conn ->
          send(owner, :attestation_attempt)
          conn = Plug.Conn.put_resp_content_type(conn, "application/json")

          conn =
            if header,
              do: Plug.Conn.put_resp_header(conn, "oauth-client-attestation-challenge", header),
              else: conn

          Plug.Conn.send_resp(conn, 400, JSON.encode!(%{"error" => "use_attestation_challenge"}))
        end

        assert {:error, {:oauth_error, 400, %{"error" => "use_attestation_challenge"}}} =
                 OAuthHTTP.post_form("https://op.example.com/token", %{},
                   client_id: ctx.client_id,
                   client_auth:
                     {:client_attestation, ctx.attestation, ctx.instance, audience: ctx.audience},
                   req_options: [plug: plug]
                 )

        assert_receive :attestation_attempt
        if header, do: assert_receive(:attestation_attempt)
        refute_receive :attestation_attempt
      end
    end

    test "fails closed when no PoP audience is supplied (no endpoint fallback)", ctx do
      assert {:error, {:client_attestation, :invalid_audience}} =
               OAuthHTTP.post_form(
                 "https://op.example.com/token",
                 %{"grant_type" => "authorization_code"},
                 client_id: ctx.client_id,
                 client_auth: {:client_attestation, ctx.attestation, ctx.instance, []},
                 req_options: [plug: capture_headers_plug(self())]
               )
    end

    test "composes with DPoP - both attestation headers and a DPoP proof are present", ctx do
      dpop_key = JOSE.JWK.generate_key({:ec, "P-256"})

      assert {:ok, %{"ok" => true}} =
               OAuthHTTP.post_form(
                 "https://op.example.com/token",
                 %{"grant_type" => "authorization_code"},
                 client_id: ctx.client_id,
                 client_auth:
                   {:client_attestation, ctx.attestation, ctx.instance, audience: ctx.audience},
                 dpop: dpop_key,
                 req_options: [plug: capture_headers_plug(self())]
               )

      assert_receive {:headers, headers}
      assert [ctx.attestation] == headers["oauth-client-attestation"]
      assert [_pop] = headers["oauth-client-attestation-pop"]
      assert [proof] = headers["dpop"]
      assert (proof |> JOSE.JWS.peek_protected() |> JSON.decode!())["typ"] == "dpop+jwt"
    end
  end

  describe "get_json/2" do
    test "returns the decoded JSON body" do
      plug = fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(
          200,
          JSON.encode!(%{"credential_issuer" => "https://issuer.example.com"})
        )
      end

      assert {:ok, %{"credential_issuer" => "https://issuer.example.com"}} =
               OAuthHTTP.get_json("https://issuer.example.com/offers/1",
                 req_options: [plug: plug]
               )
    end

    test "surfaces a non-200 status" do
      plug = fn conn -> Plug.Conn.send_resp(conn, 404, "") end

      assert {:error, {:http_status, 404}} =
               OAuthHTTP.get_json("https://issuer.example.com/offers/missing",
                 req_options: [plug: plug]
               )
    end
  end

  describe "get_text/2" do
    test "returns the raw response body" do
      plug = fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/oauth-authz-req+jwt")
        |> Plug.Conn.send_resp(200, "header.payload.signature")
      end

      assert {:ok, "header.payload.signature"} =
               OAuthHTTP.get_text("https://verifier.example.com/requests/1",
                 req_options: [plug: plug]
               )
    end

    test "surfaces a non-200 status" do
      plug = fn conn -> Plug.Conn.send_resp(conn, 404, "") end

      assert {:error, {:http_status, 404}} =
               OAuthHTTP.get_text("https://verifier.example.com/requests/missing",
                 req_options: [plug: plug]
               )
    end

    test "bounds an oversized body from a hostile by-reference endpoint" do
      # A request_uri / credential_offer_uri is caller-influenceable; an
      # unbounded body must not be buffered whole.
      huge = String.duplicate("A", 3_000_000)
      plug = fn conn -> Plug.Conn.send_resp(conn, 200, huge) end

      assert {:error, :response_too_large} =
               OAuthHTTP.get_text("https://verifier.example.com/requests/huge",
                 req_options: [plug: plug]
               )

      assert {:error, :response_too_large} =
               OAuthHTTP.get_json("https://issuer.example.com/offers/huge",
                 req_options: [plug: plug]
               )
    end
  end

  describe "post_form_open/3" do
    test "POSTs unauthenticated and returns the decoded JSON body" do
      parent = self()

      plug = fn conn ->
        {:ok, body, conn} = Plug.Conn.read_body(conn)
        send(parent, {:request, URI.decode_query(body)})

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(
          200,
          JSON.encode!(%{"redirect_uri" => "https://wallet.example.com/done"})
        )
      end

      assert {:ok, %{"redirect_uri" => "https://wallet.example.com/done"}} =
               OAuthHTTP.post_form_open(
                 "https://verifier.example.com/response",
                 %{"vp_token" => "{}", "state" => "state-1"},
                 req_options: [plug: plug]
               )

      assert_receive {:request, %{"vp_token" => "{}", "state" => "state-1"}}
    end

    test "rejects a non-JSON success body" do
      plug = fn conn -> Plug.Conn.send_resp(conn, 200, "") end

      assert {:error, :invalid_response_content_type} =
               OAuthHTTP.post_form_open("https://verifier.example.com/response", %{},
                 req_options: [plug: plug]
               )
    end

    test "surfaces an oauth-shaped error body and a bare non-2xx status" do
      error_plug = fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(400, JSON.encode!(%{"error" => "invalid_request"}))
      end

      assert {:error, {:oauth_error, 400, %{"error" => "invalid_request"}}} =
               OAuthHTTP.post_form_open("https://verifier.example.com/response", %{},
                 req_options: [plug: error_plug]
               )

      plain_plug = fn conn -> Plug.Conn.send_resp(conn, 500, "") end

      assert {:error, {:http_status, 500}} =
               OAuthHTTP.post_form_open("https://verifier.example.com/response", %{},
                 req_options: [plug: plain_plug]
               )
    end
  end

  describe "SSRF-safe pinned requests" do
    @pinned_endpoint "https://service.example.test:8443/oauth/path?existing=1"
    @pinned_url "https://93.184.216.34:8443/oauth/path?existing=1"
    @pinned_dpop_htu "https://service.example.test:8443/oauth/path"

    test "every HTTP method family preserves protocol-owned request data" do
      basic = "Basic " <> Base.encode64("client-id:client-secret")

      calls = [
        {"form POST", basic,
         fn opts ->
           OAuthHTTP.post_form(
             @pinned_endpoint,
             %{"grant_type" => "authorization_code"},
             [client_id: "client-id", client_auth: {:client_secret_basic, "client-secret"}] ++
               opts
           )
         end, Req.Response.new(status: 200, body: %{"ok" => true}), {:ok, %{"ok" => true}}},
        {"unit form POST", basic,
         fn opts ->
           OAuthHTTP.post_form_unit(
             @pinned_endpoint,
             %{"token" => "token"},
             [client_id: "client-id", client_auth: {:client_secret_basic, "client-secret"}] ++
               opts
           )
         end, Req.Response.new(status: 204), :ok},
        {"JSON POST", "Bearer access-token",
         &OAuthHTTP.post_json(@pinned_endpoint, %{"proof" => "proof"}, "access-token", &1),
         Req.Response.new(status: 200, body: %{"ok" => true}), {:ok, %{"ok" => true}}},
        {"unit JSON POST", "Bearer access-token",
         &OAuthHTTP.post_json_unit(
           @pinned_endpoint,
           %{"event" => "accepted"},
           "access-token",
           &1
         ), Req.Response.new(status: 204), :ok},
        {"JSON GET", nil, &OAuthHTTP.get_json(@pinned_endpoint, &1),
         Req.Response.new(status: 200, body: JSON.encode!(%{"ok" => true})),
         {:ok, %{"ok" => true}}},
        {"text GET", nil, &OAuthHTTP.get_text(@pinned_endpoint, &1),
         Req.Response.new(status: 200, body: "header.payload.signature"),
         {:ok, "header.payload.signature"}},
        {"open form POST", nil,
         &OAuthHTTP.post_form_open(@pinned_endpoint, %{"vp_token" => "{}"}, &1),
         Req.Response.new(status: 200, body: %{"ok" => true}), {:ok, %{"ok" => true}}}
      ]

      Enum.each(calls, fn {name, expected_authorization, call, response, expected_result} ->
        opts = pinned_options(self(), name, response)

        assert call.(opts) == expected_result
        assert_receive {:pinned_request, ^name, request}
        assert_pinned_request(request, expected_authorization, name)
      end)
    end

    test "DNS screening returns one immutable public-IP target" do
      resolutions = :atomics.new(1, [])

      assert {:ok, target} =
               Discovery.screen_endpoint(@pinned_endpoint,
                 resolver: rebinding_resolver(resolutions)
               )

      assert target.url == @pinned_url
      assert target.host == "service.example.test"
      assert target.authority == "service.example.test:8443"
      assert :atomics.get(resolutions, 1) == 2
    end

    test "a DPoP nonce retry preserves external htu and protocol-owned auth headers" do
      attempts = :atomics.new(1, [])
      parent = self()

      plug = fn conn ->
        {:ok, request_body, conn} = Plug.Conn.read_body(conn)
        attempt = :atomics.add_get(attempts, 1, 1)
        send(parent, {:pinned_dpop_attempt, attempt, request_snapshot(conn, request_body)})

        if attempt == 1 do
          conn
          |> Plug.Conn.put_resp_header("dpop-nonce", "server-nonce")
          |> Plug.Conn.put_resp_content_type("application/json")
          |> Plug.Conn.send_resp(401, JSON.encode!(%{"error" => "use_dpop_nonce"}))
        else
          conn
          |> Plug.Conn.put_resp_content_type("application/json")
          |> Plug.Conn.send_resp(200, JSON.encode!(%{"ok" => true}))
        end
      end

      key = JOSE.JWK.generate_key({:ec, "P-256"})

      assert {:ok, %{"ok" => true}} =
               OAuthHTTP.post_json(@pinned_endpoint, %{}, "access-token",
                 dpop: key,
                 req_options: hostile_transport_options(plug)
               )

      assert_receive {:pinned_dpop_attempt, 1, first_request}
      assert_receive {:pinned_dpop_attempt, 2, second_request}
      refute_receive {:pinned_dpop_attempt, 3, _request}

      Enum.each([first_request, second_request], fn request ->
        assert_pinned_request(request, "DPoP access-token")
        assert [_proof] = request_header(request, "dpop")
      end)

      [first_proof] = request_header(first_request, "dpop")
      [second_proof] = request_header(second_request, "dpop")
      first_claims = dpop_claims(first_proof)
      second_claims = dpop_claims(second_proof)

      # RFC 9449 normalizes `htu` by removing the query, while retaining the
      # external authority/path rather than the pinned socket IP.
      assert first_claims["htu"] == @pinned_dpop_htu
      assert second_claims["htu"] == @pinned_dpop_htu
      refute Map.has_key?(first_claims, "nonce")
      assert second_claims["nonce"] == "server-nonce"
      refute first_claims["jti"] == second_claims["jti"]

      assert :atomics.get(attempts, 1) == 2
    end

    test "rejects proxy and custom Finch routing when a DNS name is pinned to an IP" do
      resolver = fn
        _host, :inet -> {:ok, [{93, 184, 216, 34}]}
        _host, :inet6 -> {:error, :nxdomain}
      end

      unsafe_options = [
        [connect_options: [proxy: {:http, "proxy.example", 8080, []}]],
        [finch: __MODULE__.CustomFinch],
        [adapter: fn request -> {request, Req.Response.new(status: 200)} end]
      ]

      Enum.each(unsafe_options, fn req_options ->
        assert {:error, :unsafe_transport_options} =
                 OAuthHTTP.get_json(@pinned_endpoint,
                   resolver: resolver,
                   req_options: req_options
                 )
      end)
    end

    test "bounds OAuth POST response bodies before decoding" do
      oversized = String.duplicate("x", 2_000_001)

      plug = fn conn -> Plug.Conn.send_resp(conn, 200, oversized) end

      assert {:error, :response_too_large} =
               OAuthHTTP.post_json(@pinned_endpoint, %{}, "access-token",
                 req_options: [plug: plug]
               )
    end

    test "an in-process Req plug remains compatible with a caller Finch option" do
      plug = fn conn -> Req.Test.json(conn, %{"ok" => true}) end

      assert {:ok, %{"ok" => true}} =
               OAuthHTTP.get_json("https://127.0.0.1/document",
                 req_options: [plug: plug, finch: __MODULE__.CustomFinch]
               )
    end
  end

  defp pinned_options(parent, name, response) do
    plug = fn conn ->
      {:ok, request_body, conn} = Plug.Conn.read_body(conn)
      send(parent, {:pinned_request, name, request_snapshot(conn, request_body)})

      conn =
        if name == "text GET" do
          Plug.Conn.put_resp_content_type(conn, "application/oauth-authz-req+jwt")
        else
          Plug.Conn.put_resp_content_type(conn, "application/json")
        end

      body =
        case response.body do
          nil -> ""
          body when is_map(body) -> JSON.encode!(body)
          body when is_binary(body) -> body
        end

      Plug.Conn.send_resp(conn, response.status, body)
    end

    [req_options: hostile_transport_options(plug)]
  end

  defp rebinding_resolver(resolutions) do
    fn host, family ->
      resolution = :atomics.add_get(resolutions, 1, 1)
      assert List.to_string(host) == "service.example.test"

      case {resolution, family} do
        {1, :inet} -> {:ok, [{93, 184, 216, 34}]}
        {2, :inet6} -> {:error, :nxdomain}
        {_rebound, _family} -> {:ok, [{127, 0, 0, 1}]}
      end
    end
  end

  defp hostile_transport_options(plug) do
    [
      plug: plug,
      adapter: fn _request -> raise "caller adapter ran" end,
      url: "https://caller.invalid/override",
      auth: {:bearer, "caller-token"},
      headers: [
        {"authorization", "Bearer caller-header"},
        {"content-encoding", "gzip"},
        {"content-length", "999"},
        {"content-type", "text/plain"},
        {"dpop", "caller-proof"},
        {"host", "caller.invalid"},
        {"oauth-client-attestation", "caller-attestation"},
        {"oauth-client-attestation-pop", "caller-pop"},
        {"transfer-encoding", "chunked"},
        {"accept-encoding", "gzip"},
        {:content_type, "application/xml"},
        {:oauth_client_attestation, "caller-atom-attestation"},
        {"x-trace", "preserved"}
      ],
      aws_sigv4: [
        access_key_id: "caller-access-key",
        secret_access_key: "caller-secret-key",
        region: "us-east-1",
        service: "execute-api"
      ],
      params: [reroute: "true"],
      body: "caller-body",
      form: [caller: "form"],
      form_multipart: [caller: "multipart"],
      json: %{"caller" => "json"},
      compress_body: true,
      finch_request: fn _, _, _, _ -> raise "caller finch_request ran" end,
      connect_options: [
        hostname: "caller.invalid",
        timeout: 321,
        transport_opts: [
          verify: :verify_none,
          server_name_indication: ~c"caller.invalid",
          customize_hostname_check: [match_fun: fn _, _ -> true end],
          verify_fun: {fn _, _, state -> {:valid, state} end, nil},
          partial_chain: fn _ -> {:trusted_ca, :caller} end
        ]
      ],
      redirect: true,
      follow_redirects: true,
      retry: true,
      receive_timeout: 1
    ]
  end

  defp assert_pinned_request(request, expected_authorization, name \\ nil) do
    assert request.request_path == "/oauth/path"
    assert request.query_string == "existing=1"
    assert request_header(request, "host") == ["service.example.test:8443"]

    expected_trace =
      if name in ["JSON GET", "text GET", "open form POST"], do: [], else: ["preserved"]

    assert request_header(request, "x-trace") == expected_trace
    assert request_header(request, "oauth-client-attestation") == []
    assert request_header(request, "oauth-client-attestation-pop") == []
    assert request_header(request, "content-encoding") == []
    refute request_header(request, "content-type") == ["text/plain"]
    assert request_header(request, "transfer-encoding") == []
    assert request_header(request, "accept-encoding") == []
    refute String.contains?(request.body, "caller")

    expected = if expected_authorization, do: [expected_authorization], else: []
    assert request_header(request, "authorization") == expected
  end

  defp request_snapshot(conn, body) do
    %{
      method: conn.method,
      request_path: conn.request_path,
      query_string: conn.query_string,
      headers: conn.req_headers,
      body: body
    }
  end

  defp request_header(%{headers: headers}, name) do
    for {header_name, value} <- headers, header_name == name, do: value
  end
end
