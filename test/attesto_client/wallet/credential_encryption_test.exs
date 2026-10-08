defmodule AttestoClient.Wallet.CredentialEncryptionTest do
  use ExUnit.Case, async: true
  @moduletag :requires_core_jwe

  alias AttestoClient.Wallet
  alias AttestoClient.Wallet.CredentialEncryption
  alias AttestoClient.Wallet.CredentialOffer

  @issuer "https://issuer.example.com"

  setup do
    key = JOSE.JWK.generate_key({:ec, "P-256"})
    {_type, public} = JOSE.JWK.to_public_map(key)

    public =
      Map.merge(public, %{"alg" => "ECDH-ES", "use" => "enc", "kid" => "issuer-encryption"})

    metadata = %{
      "credential_issuer" => @issuer,
      "credential_endpoint" => @issuer <> "/credential",
      "credential_request_encryption" => %{
        "jwks" => %{"keys" => [public]},
        "enc_values_supported" => ["A128GCM", "A256GCM"],
        "encryption_required" => false
      },
      "credential_response_encryption" => %{
        "alg_values_supported" => ["ECDH-ES"],
        "enc_values_supported" => ["A128GCM", "A256GCM"],
        "encryption_required" => true
      }
    }

    {:ok, key: key, public: public, metadata: metadata}
  end

  defp respond(conn, status, type, body) do
    conn
    |> Plug.Conn.put_resp_content_type(type)
    |> Plug.Conn.send_resp(status, body)
  end

  defp issue(request, issuer_key) do
    [proof] = request["proofs"]["jwt"]
    {:ok, %{jwk: holder}} = Attesto.CredentialProof.verify_jwt(proof, issuer: @issuer)
    {_type, pem} = JOSE.JWK.to_pem(issuer_key)

    credential =
      Attesto.SdJwtVc.issue([iss: @issuer, vct: "ExampleCredential", pem: pem],
        claims: %{"given_name" => "Jane"},
        cnf: %{"jwk" => holder}
      )

    Attesto.CredentialResponse.build(credential)
  end

  defp encrypted_response(conn, request, response, status \\ 200) do
    parameters = request["credential_response_encryption"]

    {:ok, jwt} =
      AttestoClient.CryptoJWE.encrypt(parameters["jwk"], JSON.encode!(response), %{
        "alg" => parameters["jwk"]["alg"],
        "enc" => parameters["enc"],
        "cty" => "json"
      })

    respond(conn, status, "application/jwt", jwt)
  end

  defp decrypt_request(conn, key) do
    assert Plug.Conn.get_req_header(conn, "content-type") == ["application/jwt"]
    {:ok, jwt, conn} = Plug.Conn.read_body(conn)
    assert {:ok, json, header} = AttestoClient.CryptoJWE.decrypt(key, jwt)
    assert header["kid"] == "issuer-encryption"
    assert header["alg"] == "ECDH-ES"
    {JSON.decode!(json), conn}
  end

  defp offer do
    {:ok, offer} =
      CredentialOffer.parse(%{
        "credential_issuer" => @issuer,
        "credential_configuration_ids" => ["ExampleCredential"]
      })

    offer
  end

  test "encrypts the full request, advertises only a public response key, decrypts and verifies",
       ctx do
    signing = JOSE.JWK.generate_key({:ec, "P-256"})
    {_type, signing_public} = JOSE.JWK.to_public_map(signing)
    owner = self()

    plug = fn conn ->
      {request, conn} = decrypt_request(conn, ctx.key)
      send(owner, {:request, request})
      encrypted_response(conn, request, issue(request, signing))
    end

    assert {:ok, %{credentials: [held]}} =
             Wallet.request_credential(offer(), JOSE.JWK.generate_key({:ec, "P-256"}),
               access_token: "access-token",
               credential_issuer_metadata: ctx.metadata,
               format: "dc+sd-jwt",
               trusted: signing_public,
               req_options: [plug: plug]
             )

    assert held.claims["given_name"] == "Jane"
    assert_receive {:request, request}
    response_key = request["credential_response_encryption"]["jwk"]
    assert response_key["alg"] == "ECDH-ES"
    assert response_key["crv"] == "P-256"
    refute Map.has_key?(response_key, "d")
    assert request["credential_response_encryption"]["enc"] == "A256GCM"
  end

  test "encrypted deferred responses keep the transaction and preserve response encryption",
       ctx do
    signing = JOSE.JWK.generate_key({:ec, "P-256"})
    {_type, trusted} = JOSE.JWK.to_public_map(signing)
    owner = self()
    cache = start_supervised!({Agent, fn -> nil end})

    plug = fn conn ->
      {request, conn} = decrypt_request(conn, ctx.key)

      case conn.request_path do
        "/credential" ->
          Agent.update(cache, fn _ -> issue(request, signing) end)

          encrypted_response(
            conn,
            request,
            %{"transaction_id" => "txn", "interval" => 1},
            202
          )

        "/deferred" ->
          send(owner, {:deferred, request, Plug.Conn.get_req_header(conn, "authorization")})
          encrypted_response(conn, request, Agent.get(cache, & &1))
      end
    end

    metadata = Map.put(ctx.metadata, "deferred_credential_endpoint", @issuer <> "/deferred")

    assert {:ok, %{credentials: [held]}} =
             Wallet.request_credential(offer(), JOSE.JWK.generate_key({:ec, "P-256"}),
               access_token: "access-token",
               credential_issuer_metadata: metadata,
               format: "dc+sd-jwt",
               trusted: trusted,
               deferred_sleep: fn _ -> :ok end,
               req_options: [plug: plug]
             )

    assert held.claims["given_name"] == "Jane"

    assert_receive {:deferred,
                    %{"transaction_id" => "txn", "credential_response_encryption" => %{}},
                    ["Bearer access-token"]}
  end

  test "auto encrypts an optional request-only advertisement instead of sending plaintext", ctx do
    signing = JOSE.JWK.generate_key({:ec, "P-256"})
    {_type, trusted} = JOSE.JWK.to_public_map(signing)
    metadata = Map.delete(ctx.metadata, "credential_response_encryption")
    owner = self()

    plug = fn conn ->
      {request, conn} = decrypt_request(conn, ctx.key)
      refute Map.has_key?(request, "credential_response_encryption")
      send(owner, :encrypted_request)
      respond(conn, 200, "application/json", JSON.encode!(issue(request, signing)))
    end

    assert {:ok, %{credentials: [held]}} =
             Wallet.request_credential(offer(), JOSE.JWK.generate_key({:ec, "P-256"}),
               access_token: "access-token",
               credential_issuer_metadata: metadata,
               format: "dc+sd-jwt",
               trusted: trusted,
               req_options: [plug: plug]
             )

    assert held.claims["given_name"] == "Jane"
    assert_receive :encrypted_request
  end

  test "auto encrypts both request and response when both advertisements are optional", ctx do
    signing = JOSE.JWK.generate_key({:ec, "P-256"})
    {_type, trusted} = JOSE.JWK.to_public_map(signing)

    metadata =
      put_in(ctx.metadata, ["credential_response_encryption", "encryption_required"], false)

    plug = fn conn ->
      {request, conn} = decrypt_request(conn, ctx.key)
      assert request["credential_response_encryption"]["enc"] == "A256GCM"
      encrypted_response(conn, request, issue(request, signing))
    end

    assert {:ok, %{credentials: [held]}} =
             Wallet.request_credential(offer(), JOSE.JWK.generate_key({:ec, "P-256"}),
               access_token: "access-token",
               credential_issuer_metadata: metadata,
               format: "dc+sd-jwt",
               trusted: trusted,
               req_options: [plug: plug]
             )

    assert held.claims["given_name"] == "Jane"
  end

  test "unsupported optional request encryption fails before HTTP unless explicitly disabled",
       ctx do
    metadata =
      ctx.metadata
      |> Map.delete("credential_response_encryption")
      |> put_in(["credential_request_encryption", "enc_values_supported"], ["A128CBC-HS256"])

    assert {:error, :unsupported_credential_encryption_method} =
             Wallet.request_credential(offer(), JOSE.JWK.generate_key({:ec, "P-256"}),
               access_token: "access-token",
               credential_issuer_metadata: metadata,
               req_options: [
                 plug: fn _conn -> flunk("unsupported encryption must not use HTTP") end
               ]
             )

    assert {:ok, %{request: nil, response: nil}} =
             CredentialEncryption.prepare(
               credential_issuer_metadata: metadata,
               credential_encryption: :disabled
             )
  end

  test "rejects plaintext success when response encryption was negotiated", ctx do
    {:ok, context} = CredentialEncryption.prepare(credential_issuer_metadata: ctx.metadata)
    plug = fn conn -> respond(conn, 200, "application/json", "{\"credentials\":[]}") end

    assert {:error, :unencrypted_credential_response} =
             CredentialEncryption.post(@issuer <> "/credential", %{}, "token", context,
               req_options: [plug: plug]
             )
  end

  test "rejects nonadvertised algorithms, signing keys and plaintext downgrade", ctx do
    no_alg =
      put_in(ctx.metadata, ["credential_response_encryption", "alg_values_supported"], ["RSA1_5"])

    assert {:error, :unsupported_credential_encryption_algorithm} =
             CredentialEncryption.prepare(credential_issuer_metadata: no_alg)

    bad_key =
      put_in(ctx.metadata, ["credential_request_encryption", "jwks", "keys"], [
        Map.put(ctx.public, "use", "sig")
      ])

    assert {:error, :unsupported_request_encryption_key} =
             CredentialEncryption.prepare(credential_issuer_metadata: bad_key)

    assert {:error, :credential_encryption_required} =
             CredentialEncryption.prepare(
               credential_issuer_metadata: ctx.metadata,
               credential_encryption: :disabled
             )

    assert {:error, :missing_request_encryption_metadata} =
             CredentialEncryption.prepare(
               credential_issuer_metadata:
                 Map.delete(ctx.metadata, "credential_request_encryption")
             )
  end

  test "issuer and endpoint mismatches fail before HTTP", ctx do
    opts = [
      credential_issuer_metadata: ctx.metadata,
      req_options: [plug: fn _ -> flunk("unexpected HTTP") end]
    ]

    assert {:error, :credential_issuer_metadata_mismatch} =
             Wallet.request_credential(
               offer(),
               nil,
               Keyword.put(
                 opts,
                 :credential_issuer_metadata,
                 Map.put(ctx.metadata, "credential_issuer", "https://other.example")
               )
             )

    assert {:error, {:credential_endpoint_mismatch, :credential_endpoint}} =
             Wallet.request_credential(
               offer(),
               nil,
               Keyword.put(opts, :credential_endpoint, "https://other.example/credential")
             )
  end

  test "request encryption JWKS requires unique nonempty key identifiers", ctx do
    for keys <- [
          [Map.delete(ctx.public, "kid")],
          [ctx.public, ctx.public],
          [Map.put(ctx.public, "kid", "")]
        ] do
      metadata = put_in(ctx.metadata, ["credential_request_encryption", "jwks", "keys"], keys)

      assert {:error, :invalid_credential_encryption_metadata} =
               CredentialEncryption.prepare(credential_issuer_metadata: metadata)
    end
  end

  test "rejects duplicate response members including nested objects after authenticated decryption",
       ctx do
    {:ok, context} = CredentialEncryption.prepare(credential_issuer_metadata: ctx.metadata)

    for plaintext <- [
          "{\"credentials\":[],\"credentials\":[]}",
          "{\"credentials\":[{\"credential\":\"a\",\"credential\":\"b\"}]}"
        ] do
      plug = fn conn ->
        {request, conn} = decrypt_request(conn, ctx.key)
        parameters = request["credential_response_encryption"]

        {:ok, jwt} =
          AttestoClient.CryptoJWE.encrypt(parameters["jwk"], plaintext, %{
            "alg" => "ECDH-ES",
            "enc" => parameters["enc"]
          })

        respond(conn, 200, "application/jwt", jwt)
      end

      assert {:error, :invalid_credential_response} =
               CredentialEncryption.post(@issuer <> "/credential", %{}, "token", context,
                 req_options: [plug: plug]
               )
    end
  end

  test "rejects an authenticated response using a different negotiated encryption method", ctx do
    {:ok, context} = CredentialEncryption.prepare(credential_issuer_metadata: ctx.metadata)

    plug = fn conn ->
      {request, conn} = decrypt_request(conn, ctx.key)
      public = request["credential_response_encryption"]["jwk"]

      {:ok, jwt} =
        AttestoClient.CryptoJWE.encrypt(public, "{\"credentials\":[]}", %{
          "alg" => "ECDH-ES",
          "enc" => "A128GCM"
        })

      respond(conn, 200, "application/jwt", jwt)
    end

    assert {:error, :invalid_header} =
             CredentialEncryption.post(@issuer <> "/credential", %{}, "token", context,
               req_options: [plug: plug]
             )
  end

  test "encrypted terminal errors preserve the protocol error and are not accepted as credentials",
       ctx do
    {:ok, context} = CredentialEncryption.prepare(credential_issuer_metadata: ctx.metadata)

    plug = fn conn ->
      {request, conn} = decrypt_request(conn, ctx.key)
      encrypted_response(conn, request, %{"error" => "credential_request_denied"}, 400)
    end

    assert {:error, {:oauth_error, 400, %{"error" => "credential_request_denied"}}} =
             CredentialEncryption.post(@issuer <> "/credential", %{}, "token", context,
               req_options: [plug: plug]
             )
  end

  test "deferred status and interval are validated even when polling is disabled", ctx do
    {:ok, context} = CredentialEncryption.prepare(credential_issuer_metadata: ctx.metadata)

    for {status, response, error} <- [
          {200, %{"transaction_id" => "txn", "interval" => 1},
           :invalid_deferred_credential_response},
          {202, %{"credentials" => []}, :invalid_deferred_credential_response},
          {202, %{"transaction_id" => "txn"}, :invalid_deferred_interval},
          {202, %{"transaction_id" => "txn", "interval" => 1.0}, :invalid_deferred_interval},
          {202, %{"transaction_id" => "txn", "interval" => -1}, :invalid_deferred_interval}
        ] do
      plug = fn conn ->
        {request, conn} = decrypt_request(conn, ctx.key)
        encrypted_response(conn, request, response, status)
      end

      assert {:error, ^error} =
               CredentialEncryption.post(@issuer <> "/credential", %{}, "token", context,
                 deferred_poll: false,
                 req_options: [plug: plug]
               )
    end
  end

  test "partial batch success retains holder binding integrity and rejects duplicates or extra credentials",
       ctx do
    signing = JOSE.JWK.generate_key({:ec, "P-256"})
    {_type, trusted} = JOSE.JWK.to_public_map(signing)

    for {keys, expected} <- [
          {[JOSE.JWK.generate_key({:ec, "P-256"})], :credential_count_mismatch},
          {[JOSE.JWK.generate_key({:ec, "P-256"}), JOSE.JWK.generate_key({:ec, "P-256"})],
           :holder_binding_mismatch}
        ] do
      plug = fn conn ->
        {request, conn} = decrypt_request(conn, ctx.key)

        response =
          issue(
            Map.update!(
              request,
              "proofs",
              &Map.update!(&1, "jwt", fn [first | _] -> [first] end)
            ),
            signing
          )

        response =
          Map.update!(response, "credentials", fn [credential] -> [credential, credential] end)

        encrypted_response(conn, request, response)
      end

      assert {:error, ^expected} =
               Wallet.request_credential(offer(), keys,
                 access_token: "token",
                 credential_issuer_metadata: ctx.metadata,
                 format: "dc+sd-jwt",
                 trusted: trusted,
                 req_options: [plug: plug]
               )
    end
  end
end
