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

          proof_jwt = request["proof"]["jwt"]

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
      assert request["proof"]["proof_type"] == "jwt"
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
            proof_jwt = request["proof"]["jwt"]

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

  describe "request_credential/3 rejects invalid input (fail fast)" do
    test "an offer with no pre-authorized_code grant and no access_token" do
      offer = offer(%{"authorization_code" => %{"issuer_state" => "state-1"}})

      assert {:error, :missing_pre_authorized_code_grant} =
               Wallet.request_credential(offer, holder_key(),
                 credential_endpoint: "#{@issuer}/credential",
                 format: "vc+sd-jwt",
                 trusted: %{}
               )
    end

    test "an unsupported or missing format" do
      opts = [access_token: "t", credential_endpoint: "#{@issuer}/credential", trusted: %{}]
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
                 trusted: %{}
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
            proof_jwt = request["proof"]["jwt"]

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
