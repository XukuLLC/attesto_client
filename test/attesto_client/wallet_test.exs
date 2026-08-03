defmodule AttestoClient.WalletTest do
  use ExUnit.Case, async: true

  alias AttestoClient.Wallet
  alias AttestoClient.Wallet.CredentialOffer

  @issuer "https://issuer.example.com"
  @client_id "wallet-client"
  @configuration_id "UniversityDegree"
  @pre_authorized_code "pre-auth-code-123"
  @access_token "access-token-abc"
  @c_nonce "server-nonce-1"
  # A non-empty trust anchor for fail-fast tests that assert a non-trust error;
  # `request_credential/3` now rejects missing/empty `:trusted` up front.
  @trusted_placeholder JOSE.JWK.generate_key({:ec, "P-256"})
                       |> JOSE.JWK.to_public_map()
                       |> elem(1)

  defp holder_key, do: JOSE.JWK.generate_key({:ec, "P-256"})

  defp issuer_keypair do
    jwk = JOSE.JWK.generate_key({:ec, "P-256"})
    pem = jwk |> JOSE.JWK.to_pem() |> elem(1)
    {_type, public} = JOSE.JWK.to_public_map(jwk)
    {pem, public}
  end

  defp offer(grants \\ nil) do
    grants =
      grants ||
        %{
          "urn:ietf:params:oauth:grant-type:pre-authorized_code" => %{
            "pre-authorized_code" => @pre_authorized_code
          }
        }

    {:ok, offer} =
      CredentialOffer.parse(%{
        "credential_issuer" => @issuer,
        "credential_configuration_ids" => [@configuration_id],
        "grants" => grants
      })

    offer
  end

  defp json(conn, status, body) do
    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.send_resp(status, JSON.encode!(body))
  end

  defp read_json_body!(conn) do
    {:ok, body, conn} = Plug.Conn.read_body(conn)
    {JSON.decode!(body), conn}
  end

  # A full plug covering the token, nonce, and credential endpoints, issuing an
  # SD-JWT VC bound to whatever holder key the wallet's proof carries.
  defp sd_jwt_vc_plug(issuer_pem, test_pid) do
    fn conn ->
      case {conn.method, conn.request_path} do
        {"POST", "/token"} ->
          {:ok, body, conn} = Plug.Conn.read_body(conn)
          form = URI.decode_query(body)
          send(test_pid, {:token_request, form})
          json(conn, 200, %{"access_token" => @access_token, "token_type" => "Bearer"})

        {"POST", "/nonce"} ->
          send(test_pid, :nonce_request)
          json(conn, 200, %{"c_nonce" => @c_nonce})

        {"POST", "/credential"} ->
          {request, conn} = read_json_body!(conn)

          send(
            test_pid,
            {:credential_request, Plug.Conn.get_req_header(conn, "authorization"), request}
          )

          proof_jwt = hd(request["proofs"]["jwt"])

          {:ok, %{jwk: holder_jwk}} =
            Attesto.CredentialProof.verify_jwt(proof_jwt,
              issuer: @issuer,
              nonce: @c_nonce,
              client_id: @client_id
            )

          credential =
            Attesto.SdJwtVc.issue(
              [iss: @issuer, vct: @configuration_id, pem: issuer_pem],
              claims: %{"given_name" => "Jane"},
              cnf: %{"jwk" => holder_jwk}
            )

          json(conn, 200, Attesto.CredentialResponse.build(credential))
      end
    end
  end

  describe "request_credential/3 - pre-authorized_code flow, SD-JWT VC" do
    test "exchanges the code, proves the holder key, and returns the verified credential" do
      {issuer_pem, issuer_jwk} = issuer_keypair()
      key = holder_key()

      assert {:ok, result} =
               Wallet.request_credential(offer(), key,
                 token_endpoint: "#{@issuer}/token",
                 nonce_endpoint: "#{@issuer}/nonce",
                 credential_endpoint: "#{@issuer}/credential",
                 client_id: @client_id,
                 format: "vc+sd-jwt",
                 trusted: issuer_jwk,
                 req_options: [plug: sd_jwt_vc_plug(issuer_pem, self())]
               )

      assert %{c_nonce: @c_nonce, credentials: [held]} = result
      assert held.format == "vc+sd-jwt"
      assert held.claims["given_name"] == "Jane"
      assert held.claims["vct"] == @configuration_id

      {_type, expected_holder_jwk} = JOSE.JWK.to_public_map(key)
      assert held.holder_binding == %{"jwk" => expected_holder_jwk}

      assert_receive {:token_request, form}
      assert form["grant_type"] == "urn:ietf:params:oauth:grant-type:pre-authorized_code"
      assert form["pre-authorized_code"] == @pre_authorized_code
      assert form["client_id"] == @client_id

      assert_receive :nonce_request

      assert_receive {:credential_request, ["Bearer #{@access_token}"], request}
      assert request["credential_configuration_id"] == @configuration_id
      assert [proof_jwt] = request["proofs"]["jwt"]
      assert is_binary(proof_jwt)
    end

    test "reuses a supplied access_token instead of exchanging the code" do
      {issuer_pem, issuer_jwk} = issuer_keypair()
      key = holder_key()
      test_pid = self()

      plug = fn conn ->
        case {conn.method, conn.request_path} do
          {"POST", "/credential"} ->
            {request, conn} = read_json_body!(conn)
            send(test_pid, {:credential_request, Plug.Conn.get_req_header(conn, "authorization")})
            proof_jwt = hd(request["proofs"]["jwt"])

            {:ok, %{jwk: holder_jwk}} =
              Attesto.CredentialProof.verify_jwt(proof_jwt, issuer: @issuer)

            credential =
              Attesto.SdJwtVc.issue([iss: @issuer, vct: @configuration_id, pem: issuer_pem],
                claims: %{},
                cnf: %{"jwk" => holder_jwk}
              )

            json(conn, 200, Attesto.CredentialResponse.build(credential))
        end
      end

      assert {:ok, %{credentials: [held]}} =
               Wallet.request_credential(offer(), key,
                 access_token: "already-have-one",
                 credential_endpoint: "#{@issuer}/credential",
                 format: "vc+sd-jwt",
                 trusted: issuer_jwk,
                 req_options: [plug: plug]
               )

      assert held.format == "vc+sd-jwt"
      assert_receive {:credential_request, ["Bearer already-have-one"]}
    end

    test "requires a tx_code when the offer's grant carries one, and forwards it" do
      {issuer_pem, issuer_jwk} = issuer_keypair()
      key = holder_key()
      test_pid = self()

      offer_with_tx_code =
        offer(%{
          "urn:ietf:params:oauth:grant-type:pre-authorized_code" => %{
            "pre-authorized_code" => @pre_authorized_code,
            "tx_code" => %{"input_mode" => "numeric", "length" => 4}
          }
        })

      opts = [
        token_endpoint: "#{@issuer}/token",
        nonce_endpoint: "#{@issuer}/nonce",
        credential_endpoint: "#{@issuer}/credential",
        client_id: @client_id,
        format: "vc+sd-jwt",
        trusted: issuer_jwk,
        req_options: [plug: sd_jwt_vc_plug(issuer_pem, test_pid)]
      ]

      assert {:error, :missing_tx_code} = Wallet.request_credential(offer_with_tx_code, key, opts)

      assert {:ok, %{credentials: [_held]}} =
               Wallet.request_credential(
                 offer_with_tx_code,
                 key,
                 Keyword.put(opts, :tx_code, "1234")
               )

      assert_receive {:token_request, form}
      assert form["tx_code"] == "1234"
    end

    test "returns a pending marker for a deferred (transaction_id) response" do
      key = holder_key()
      {_issuer_pem, issuer_jwk} = issuer_keypair()

      plug = fn conn ->
        case {conn.method, conn.request_path} do
          {"POST", "/token"} ->
            json(conn, 200, %{"access_token" => @access_token, "token_type" => "Bearer"})

          {"POST", "/credential"} ->
            json(conn, 200, %{"transaction_id" => "txn-1", "notification_id" => "notif-1"})
        end
      end

      assert {:ok, %{credentials: [pending], c_nonce: nil}} =
               Wallet.request_credential(offer(), key,
                 token_endpoint: "#{@issuer}/token",
                 credential_endpoint: "#{@issuer}/credential",
                 client_id: @client_id,
                 format: "vc+sd-jwt",
                 trusted: issuer_jwk,
                 req_options: [plug: plug]
               )

      assert pending == %{status: :pending, transaction_id: "txn-1", notification_id: "notif-1"}
    end
  end

  describe "request_credential/3 - DPoP sender-constraining" do
    # The token endpoint binds the access token to the DPoP key's jkt; the
    # credential endpoint checks a fresh proof carrying the token's ath. One
    # `:dpop` key threads through both legs.
    defp dpop_capturing_plug(issuer_pem, test_pid) do
      fn conn ->
        dpop = Plug.Conn.get_req_header(conn, "dpop")

        case {conn.method, conn.request_path} do
          {"POST", "/token"} ->
            send(test_pid, {:token_dpop, dpop})
            json(conn, 200, %{"access_token" => @access_token, "token_type" => "DPoP"})

          {"POST", "/nonce"} ->
            json(conn, 200, %{"c_nonce" => @c_nonce})

          {"POST", "/credential"} ->
            {request, conn} = read_json_body!(conn)
            send(test_pid, {:credential_dpop, dpop})

            {:ok, %{jwk: holder_jwk}} =
              Attesto.CredentialProof.verify_jwt(hd(request["proofs"]["jwt"]),
                issuer: @issuer,
                nonce: @c_nonce,
                client_id: @client_id
              )

            credential =
              Attesto.SdJwtVc.issue([iss: @issuer, vct: @configuration_id, pem: issuer_pem],
                claims: %{"given_name" => "Jane"},
                cnf: %{"jwk" => holder_jwk}
              )

            json(conn, 200, Attesto.CredentialResponse.build(credential))
        end
      end
    end

    test "attaches a proof to both the token and credential requests, ath-bound" do
      {issuer_pem, issuer_jwk} = issuer_keypair()
      dpop_key = JOSE.JWK.generate_key({:ec, "P-256"})

      assert {:ok, %{credentials: [_held]}} =
               Wallet.request_credential(offer(), holder_key(),
                 token_endpoint: "#{@issuer}/token",
                 nonce_endpoint: "#{@issuer}/nonce",
                 credential_endpoint: "#{@issuer}/credential",
                 client_id: @client_id,
                 format: "vc+sd-jwt",
                 trusted: issuer_jwk,
                 dpop: dpop_key,
                 req_options: [plug: dpop_capturing_plug(issuer_pem, self())]
               )

      expected_jkt = Attesto.DPoP.compute_jkt(dpop_key)

      # Token leg: a proof for the token endpoint, no ath (no token yet).
      assert_receive {:token_dpop, [token_proof]}

      assert {:ok, %{jkt: ^expected_jkt, ath: nil, htm: "POST"}} =
               Attesto.DPoP.verify_proof(token_proof,
                 http_method: "POST",
                 http_uri: "#{@issuer}/token"
               )

      # Credential leg: same key, bound to the access token's ath.
      assert_receive {:credential_dpop, [credential_proof]}

      assert {:ok, %{jkt: ^expected_jkt, ath: ath, htm: "POST"}} =
               Attesto.DPoP.verify_proof(credential_proof,
                 http_method: "POST",
                 http_uri: "#{@issuer}/credential",
                 access_token: @access_token
               )

      assert ath == Attesto.DPoP.compute_ath(@access_token)
    end
  end

  describe "request_credential/3 - OID4VCI notification (§10)" do
    test "POSTs a notification acknowledging the credential and returns its id" do
      {issuer_pem, issuer_jwk} = issuer_keypair()
      test_pid = self()

      plug = fn conn ->
        case {conn.method, conn.request_path} do
          {"POST", "/token"} ->
            json(conn, 200, %{"access_token" => @access_token, "token_type" => "Bearer"})

          {"POST", "/credential"} ->
            {request, conn} = read_json_body!(conn)

            {:ok, %{jwk: holder_jwk}} =
              Attesto.CredentialProof.verify_jwt(hd(request["proofs"]["jwt"]), issuer: @issuer)

            credential =
              Attesto.SdJwtVc.issue([iss: @issuer, vct: @configuration_id, pem: issuer_pem],
                claims: %{},
                cnf: %{"jwk" => holder_jwk}
              )

            body = credential |> Attesto.CredentialResponse.build() |> Map.put("notification_id", "n-42")
            json(conn, 200, body)

          {"POST", "/notification"} ->
            {notification, conn} = read_json_body!(conn)
            send(test_pid, {:notification, Plug.Conn.get_req_header(conn, "authorization"), notification})
            Plug.Conn.send_resp(conn, 204, "")
        end
      end

      assert {:ok, %{credentials: [_held], notification_id: "n-42"}} =
               Wallet.request_credential(offer(), holder_key(),
                 token_endpoint: "#{@issuer}/token",
                 credential_endpoint: "#{@issuer}/credential",
                 notification_endpoint: "#{@issuer}/notification",
                 client_id: @client_id,
                 format: "vc+sd-jwt",
                 trusted: issuer_jwk,
                 req_options: [plug: plug]
               )

      assert_receive {:notification, ["Bearer #{@access_token}"], notification}
      assert notification == %{"notification_id" => "n-42", "event" => "credential_accepted"}
    end

    test "does not notify when no notification_endpoint is configured" do
      {issuer_pem, issuer_jwk} = issuer_keypair()
      test_pid = self()

      plug = fn conn ->
        case {conn.method, conn.request_path} do
          {"POST", "/token"} ->
            json(conn, 200, %{"access_token" => @access_token, "token_type" => "Bearer"})

          {"POST", "/credential"} ->
            {request, conn} = read_json_body!(conn)

            {:ok, %{jwk: holder_jwk}} =
              Attesto.CredentialProof.verify_jwt(hd(request["proofs"]["jwt"]), issuer: @issuer)

            credential =
              Attesto.SdJwtVc.issue([iss: @issuer, vct: @configuration_id, pem: issuer_pem],
                claims: %{},
                cnf: %{"jwk" => holder_jwk}
              )

            body = credential |> Attesto.CredentialResponse.build() |> Map.put("notification_id", "n-1")
            json(conn, 200, body)

          {"POST", "/notification"} ->
            send(test_pid, :unexpected_notification)
            Plug.Conn.send_resp(conn, 204, "")
        end
      end

      assert {:ok, %{notification_id: "n-1"}} =
               Wallet.request_credential(offer(), holder_key(),
                 token_endpoint: "#{@issuer}/token",
                 credential_endpoint: "#{@issuer}/credential",
                 client_id: @client_id,
                 format: "vc+sd-jwt",
                 trusted: issuer_jwk,
                 req_options: [plug: plug]
               )

      refute_receive :unexpected_notification
    end
  end

  describe "request_credential/3 - batch issuance (§8.2)" do
    test "sends one proof per holder key and verifies each returned credential" do
      {issuer_pem, issuer_jwk} = issuer_keypair()
      test_pid = self()

      plug = fn conn ->
        case {conn.method, conn.request_path} do
          {"POST", "/token"} ->
            json(conn, 200, %{"access_token" => @access_token, "token_type" => "Bearer"})

          {"POST", "/credential"} ->
            {request, conn} = read_json_body!(conn)
            proofs = request["proofs"]["jwt"]
            send(test_pid, {:proof_count, length(proofs)})

            credentials =
              for proof <- proofs do
                {:ok, %{jwk: holder_jwk}} =
                  Attesto.CredentialProof.verify_jwt(proof, issuer: @issuer)

                cred =
                  Attesto.SdJwtVc.issue([iss: @issuer, vct: @configuration_id, pem: issuer_pem],
                    claims: %{},
                    cnf: %{"jwk" => holder_jwk}
                  )

                %{"credential" => cred}
              end

            json(conn, 200, %{"credentials" => credentials})
        end
      end

      key_a = holder_key()
      key_b = holder_key()

      assert {:ok, %{credentials: held}} =
               Wallet.request_credential(offer(), [key_a, key_b],
                 token_endpoint: "#{@issuer}/token",
                 credential_endpoint: "#{@issuer}/credential",
                 client_id: @client_id,
                 format: "vc+sd-jwt",
                 trusted: issuer_jwk,
                 req_options: [plug: plug]
               )

      assert_receive {:proof_count, 2}
      assert length(held) == 2

      # Each credential is bound to a distinct holder key.
      bindings = Enum.map(held, & &1.holder_binding)
      assert Enum.uniq(bindings) == bindings

      {_type, pub_a} = JOSE.JWK.to_public_map(key_a)
      {_type, pub_b} = JOSE.JWK.to_public_map(key_b)
      assert %{"jwk" => pub_a} in bindings
      assert %{"jwk" => pub_b} in bindings
    end
  end

  describe "request_credential/3 - holder-binding and trust integrity" do
    test "rejects a credential bound to a key the wallet does not control" do
      {issuer_pem, issuer_jwk} = issuer_keypair()
      # A hostile issuer binds the credential to an unrelated key, not the
      # wallet's holder key that proved possession.
      attacker_key = JOSE.JWK.generate_key({:ec, "P-256"})
      {_t, attacker_pub} = JOSE.JWK.to_public_map(attacker_key)

      plug = fn conn ->
        case {conn.method, conn.request_path} do
          {"POST", "/token"} ->
            json(conn, 200, %{"access_token" => @access_token, "token_type" => "Bearer"})

          {"POST", "/credential"} ->
            credential =
              Attesto.SdJwtVc.issue([iss: @issuer, vct: @configuration_id, pem: issuer_pem],
                claims: %{},
                cnf: %{"jwk" => attacker_pub}
              )

            json(conn, 200, Attesto.CredentialResponse.build(credential))
        end
      end

      assert {:error, :holder_binding_mismatch} =
               Wallet.request_credential(offer(), holder_key(),
                 token_endpoint: "#{@issuer}/token",
                 credential_endpoint: "#{@issuer}/credential",
                 client_id: @client_id,
                 format: "vc+sd-jwt",
                 trusted: issuer_jwk,
                 req_options: [plug: plug]
               )
    end

    test "rejects a batch response whose credential count differs from the proofs" do
      {issuer_pem, issuer_jwk} = issuer_keypair()

      plug = fn conn ->
        case {conn.method, conn.request_path} do
          {"POST", "/token"} ->
            json(conn, 200, %{"access_token" => @access_token, "token_type" => "Bearer"})

          {"POST", "/credential"} ->
            {request, conn} = read_json_body!(conn)
            # Two proofs sent, but the issuer returns only one credential.
            [proof | _] = request["proofs"]["jwt"]
            {:ok, %{jwk: holder_jwk}} = Attesto.CredentialProof.verify_jwt(proof, issuer: @issuer)

            cred =
              Attesto.SdJwtVc.issue([iss: @issuer, vct: @configuration_id, pem: issuer_pem],
                claims: %{},
                cnf: %{"jwk" => holder_jwk}
              )

            json(conn, 200, %{"credentials" => [%{"credential" => cred}]})
        end
      end

      assert {:error, :credential_count_mismatch} =
               Wallet.request_credential(offer(), [holder_key(), holder_key()],
                 token_endpoint: "#{@issuer}/token",
                 credential_endpoint: "#{@issuer}/credential",
                 client_id: @client_id,
                 format: "vc+sd-jwt",
                 trusted: issuer_jwk,
                 req_options: [plug: plug]
               )
    end

    test "fails closed with no trust anchor, before any network call" do
      test_pid = self()
      plug = fn conn -> send(test_pid, :unexpected_request); json(conn, 200, %{}) end

      assert {:error, :missing_trusted} =
               Wallet.request_credential(offer(), holder_key(),
                 token_endpoint: "#{@issuer}/token",
                 credential_endpoint: "#{@issuer}/credential",
                 format: "vc+sd-jwt",
                 req_options: [plug: plug]
               )

      refute_receive :unexpected_request
    end

    test "mints a nonce-bound key attestation via a builder callback after fetch" do
      {issuer_pem, issuer_jwk} = issuer_keypair()
      provider = JOSE.JWK.generate_key({:ec, "P-256"})
      test_pid = self()

      builder = fn holder_publics, c_nonce ->
        send(test_pid, {:attestation_built, length(holder_publics), c_nonce})
        AttestoClient.KeyAttestation.build(provider, attested_keys: holder_publics, nonce: c_nonce)
      end

      assert {:ok, %{credentials: [_held]}} =
               Wallet.request_credential(offer(), holder_key(),
                 token_endpoint: "#{@issuer}/token",
                 nonce_endpoint: "#{@issuer}/nonce",
                 credential_endpoint: "#{@issuer}/credential",
                 client_id: @client_id,
                 format: "vc+sd-jwt",
                 trusted: issuer_jwk,
                 key_attestation: builder,
                 req_options: [plug: sd_jwt_vc_plug(issuer_pem, self())]
               )

      # The builder ran with the wallet's holder key and the fetched c_nonce.
      assert_receive {:attestation_built, 1, @c_nonce}
    end
  end

  describe "request_credential/3 rejects invalid input (fail fast)" do
    test "an offer with no pre-authorized_code grant and no access_token" do
      offer = offer(%{"authorization_code" => %{"issuer_state" => "state-1"}})

      assert {:error, :missing_pre_authorized_code_grant} =
               Wallet.request_credential(offer, holder_key(),
                 credential_endpoint: "#{@issuer}/credential",
                 format: "vc+sd-jwt",
                 trusted: @trusted_placeholder
               )
    end

    test "an unsupported or missing format" do
      opts = [access_token: "t", credential_endpoint: "#{@issuer}/credential", trusted: @trusted_placeholder]
      assert {:error, :missing_format} = Wallet.request_credential(offer(), holder_key(), opts)

      assert {:error, :missing_format} =
               Wallet.request_credential(offer(), holder_key(), Keyword.put(opts, :format, "vc"))
    end

    test "an ambiguous credential_configuration_id when the offer carries several" do
      {:ok, multi} =
        CredentialOffer.parse(%{
          "credential_issuer" => @issuer,
          "credential_configuration_ids" => ["A", "B"],
          "grants" => %{
            "urn:ietf:params:oauth:grant-type:pre-authorized_code" => %{
              "pre-authorized_code" => @pre_authorized_code
            }
          }
        })

      assert {:error, :ambiguous_credential_configuration_id} =
               Wallet.request_credential(multi, holder_key(),
                 access_token: "t",
                 credential_endpoint: "#{@issuer}/credential",
                 format: "vc+sd-jwt",
                 trusted: @trusted_placeholder
               )
    end

    test "not a CredentialOffer struct" do
      assert {:error, :invalid_offer} =
               Wallet.request_credential(%{}, holder_key(), format: "vc+sd-jwt")
    end
  end

  describe "request_credential/3 - jwt_vc_json format" do
    test "verifies a jwt_vc_json credential returned by the issuer" do
      {issuer_pem, issuer_jwk} = issuer_keypair()
      # Attesto.JwtVc.issue/2 defaults its JWS `kid` header to the issuer key's
      # own thumbprint (Attesto.Key.kid/1); verification's candidate matching
      # then requires the trusted key to carry the same "kid" (see
      # Attesto.JWS.verification_candidates/2 - kid filtering, unlike
      # Attesto.SdJwtVc, is unconditional whenever the JWS header carries one).
      trusted =
        Map.merge(issuer_jwk, %{
          "kid" => Attesto.Key.kid(issuer_pem),
          "alg" => "ES256",
          "use" => "sig"
        })

      key = holder_key()

      plug = fn conn ->
        case {conn.method, conn.request_path} do
          {"POST", "/credential"} ->
            {request, conn} = read_json_body!(conn)
            proof_jwt = hd(request["proofs"]["jwt"])

            {:ok, %{jwk: holder_jwk}} =
              Attesto.CredentialProof.verify_jwt(proof_jwt, issuer: @issuer)

            credential =
              Attesto.JwtVc.issue([pem: issuer_pem, iss: @issuer, sub: "subject-1"],
                cnf: %{"jwk" => holder_jwk}
              )

            json(conn, 200, Attesto.CredentialResponse.build(credential))
        end
      end

      assert {:ok, %{credentials: [held]}} =
               Wallet.request_credential(offer(), key,
                 access_token: "already-have-one",
                 credential_endpoint: "#{@issuer}/credential",
                 format: "jwt_vc_json",
                 trusted: trusted,
                 req_options: [plug: plug]
               )

      assert held.format == "jwt_vc_json"
      assert held.claims == %{}
    end
  end
end
