defmodule AttestoClient.Wallet.ProfileBoundaryTest do
  use ExUnit.Case, async: true

  alias AttestoClient.{RefreshCoordinator, Token, TokenSet, Wallet}
  alias AttestoClient.Wallet.CredentialOffer
  alias AttestoClient.Wallet.Presentation.Encryption
  alias Plug.Conn.Query

  @issuer "https://issuer.example"

  defp options(key, extra) do
    Keyword.merge(
      [
        issuer: @issuer,
        client_id: "wallet",
        token_endpoint: @issuer <> "/token",
        haip: true,
        dpop: key,
        client_auth: {:private_key_jwt, key}
      ],
      extra
    )
  end

  test "profile preauthorization requires authentication and DPoP before HTTP" do
    key = JOSE.JWK.generate_key({:ec, "P-256"})
    no_http = [plug: fn _ -> flunk("profile rejection must precede HTTP") end]

    for profile <- [:haip, :fapi?] do
      opts = options(key, haip: false, req_options: no_http) |> Keyword.put(profile, true)

      assert {:error, :profile_client_auth_required} =
               Token.exchange_pre_authorized_code("code", Keyword.delete(opts, :client_auth))

      assert {:error, :profile_dpop_required} =
               Token.exchange_pre_authorized_code("code", Keyword.delete(opts, :dpop))
    end
  end

  test "authenticated profile token state survives refresh and cannot be weakened" do
    key = JOSE.JWK.generate_key({:ec, "P-256"})

    plug = fn conn ->
      assert [_] = Plug.Conn.get_req_header(conn, "dpop")
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      assert Query.decode(body)["client_assertion"]

      Req.Test.json(conn, %{
        "access_token" => "access",
        "token_type" => "DPoP",
        "refresh_token" => "refresh",
        "profile" => "generic",
        "client_auth_binding" => nil
      })
    end

    assert {:ok, tokens} =
             Token.exchange_pre_authorized_code("code", options(key, req_options: [plug: plug]))

    assert tokens.profile == :haip
    assert %{method: :private_key_jwt} = tokens.client_auth_binding
    assert tokens.client_id == "wallet"
    assert tokens.issuer == @issuer

    coordinator = start_supervised!(RefreshCoordinator)

    opts =
      options(key,
        haip: false,
        subject: "subject",
        jwks: %{"keys" => []},
        req_options: [plug: plug]
      )

    assert {:ok, result} = Token.refresh(coordinator, make_ref(), tokens, opts)
    assert result.tokens.profile == :haip
    assert result.tokens.client_auth_binding == tokens.client_auth_binding

    no_http = Keyword.put(opts, :req_options, plug: fn _ -> flunk("unexpected HTTP") end)

    assert {:error, :profile_client_auth_required} =
             Token.refresh(coordinator, make_ref(), tokens, Keyword.delete(no_http, :client_auth))

    assert {:error, :client_auth_mismatch} =
             Token.refresh(
               coordinator,
               make_ref(),
               tokens,
               Keyword.put(
                 no_http,
                 :client_auth,
                 {:private_key_jwt, JOSE.JWK.generate_key({:ec, "P-256"})}
               )
             )

    assert {:error, :client_auth_mismatch} =
             Token.refresh(
               coordinator,
               make_ref(),
               tokens,
               Keyword.put(no_http, :issuer, "https://other.example")
             )
  end

  test "HAIP credential issuance rejects bare tokens before any credential or nonce call" do
    key = JOSE.JWK.generate_key({:ec, "P-256"})

    {:ok, offer} =
      CredentialOffer.parse(%{
        "credential_issuer" => @issuer,
        "credential_configuration_ids" => ["example"]
      })

    opts =
      options(key,
        access_token: "untyped-access",
        req_options: [plug: fn _ -> flunk("unexpected HTTP") end]
      )

    assert {:error, :profile_token_set_required} = Wallet.request_credential(offer, key, opts)

    assert {:error, :profile_dpop_required} =
             Wallet.request_credential(offer, key, Keyword.delete(opts, :dpop))

    tokens = %TokenSet{
      access_token: "access",
      token_type: "DPoP",
      profile: :haip,
      client_auth_binding: %{method: :private_key_jwt}
    }

    assert {:error, :profile_dpop_required} =
             Wallet.request_credential(
               offer,
               key,
               opts
               |> Keyword.put(:haip, false)
               |> Keyword.put(:access_token, tokens)
               |> Keyword.delete(:dpop)
             )
  end

  test "FAPI refresh retains profile and rejects non-FAPI ID-token policy before HTTP" do
    key = JOSE.JWK.generate_key({:ec, "P-256"})

    plug = fn conn ->
      Req.Test.json(conn, %{
        "access_token" => "access",
        "token_type" => "DPoP",
        "refresh_token" => "refresh"
      })
    end

    opts = options(key, haip: false, fapi?: true, req_options: [plug: plug])
    assert {:ok, tokens} = Token.exchange_pre_authorized_code("code", opts)
    assert tokens.profile == :fapi
    coordinator = start_supervised!(RefreshCoordinator)
    opts = Keyword.merge(opts, fapi?: false, subject: "subject", jwks: %{"keys" => []})
    assert {:ok, result} = Token.refresh(coordinator, make_ref(), tokens, opts)
    assert result.tokens.profile == :fapi

    assert {:error, :unsupported_alg} =
             Token.refresh(
               coordinator,
               make_ref(),
               tokens,
               Keyword.merge(opts,
                 id_token_alg: "RS256",
                 req_options: [plug: fn _ -> flunk("unexpected HTTP") end]
               )
             )
  end

  test "HAIP verifier metadata requires both GCM algorithms; generic negotiation is preserved" do
    key = JOSE.JWK.generate_key({:ec, "P-256"}) |> JOSE.JWK.to_public_map() |> elem(1)

    metadata = %{
      "jwks" => %{"keys" => [Map.merge(key, %{"alg" => "ECDH-ES", "kid" => "recipient"})]}
    }

    request = %{response_mode: "direct_post.jwt", client_metadata: metadata, profile: :haip}

    for values <- [nil, [], ["A128GCM"], ["A256GCM"], ["A128GCM", "A256GCM", nil]] do
      assert {:error, :invalid_encryption_metadata} =
               Encryption.context(%{
                 request
                 | client_metadata:
                     Map.put(metadata, "encrypted_response_enc_values_supported", values)
               })
    end

    assert {:error, :invalid_encryption_metadata} = Encryption.context(request)
    assert {:ok, %{enc: "A128GCM"}} = Encryption.context(%{request | profile: :generic})

    assert {:ok, %{enc: "A256GCM"}} =
             Encryption.context(%{
               request
               | client_metadata:
                   Map.put(metadata, "encrypted_response_enc_values_supported", [
                     "A128GCM",
                     "A256GCM"
                   ])
             })

    assert {:error, :invalid_encryption_metadata} =
             Encryption.context(%{request | response_mode: "direct_post"})
  end
end
