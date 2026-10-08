defmodule AttestoClient.Wallet.PresentationEncryptedTest do
  use ExUnit.Case, async: true
  @moduletag :requires_core_jwe
  alias Attesto.{Mdoc, SdJwt, SdJwtVc, VpToken}
  alias AttestoClient.CryptoJWE
  alias AttestoClient.Wallet.{Presentation, PresentationRequest}

  @now 1_700_000_000
  @namespace "org.iso.18013.5.1"
  @doctype "org.iso.18013.5.1.mDL"

  defp keypair do
    key = JOSE.JWK.generate_key({:ec, "P-256"})
    {key, key |> JOSE.JWK.to_public_map() |> elem(1)}
  end

  defp request(format, public, claims \\ nil) do
    query = %{"id" => "identity", "format" => format}
    query = if claims, do: Map.put(query, "claims", claims), else: query

    %PresentationRequest{
      client_id: "x509_hash:verified-client",
      nonce: "fresh-nonce",
      response_uri: "https://verifier.example/response",
      response_mode: "direct_post.jwt",
      state: "private-state",
      dcql_query: %{"credentials" => [query]},
      client_metadata: %{
        "vp_formats_supported" => %{format => %{}},
        "jwks" => %{
          "keys" => [
            Map.merge(public, %{"kid" => "recipient", "alg" => "ECDH-ES", "use" => "enc"})
          ]
        },
        "encrypted_response_enc_values_supported" => ["A128GCM", "A256GCM"]
      }
    }
  end

  defp sd_credential(holder) do
    {issuer, public} = keypair()
    pem = issuer |> JOSE.JWK.to_pem() |> elem(1)

    credential =
      SdJwtVc.issue([iss: "https://issuer.example", vct: "identity", pem: pem],
        claims: %{
          "given_name" => "Alice",
          "family_name" => "Example",
          "address" => %{"city" => "Example", "street" => "Private"}
        },
        cnf: %{"jwk" => holder},
        iat: @now
      )

    {:ok, verified} = SdJwtVc.verify(credential, public, now: @now)

    {%{
       format: "dc+sd-jwt",
       credential: credential,
       claims: verified.claims,
       holder_binding: %{"jwk" => holder}
     }, public}
  end

  defp nested_credential(holder) do
    {issuer, public} = keypair()
    city = SdJwt.object_disclosure("city-salt", "city", "Example")
    street = SdJwt.object_disclosure("street-salt", "street", "Private")

    address =
      SdJwt.object_disclosure("address-salt", "address", %{
        "_sd" => [SdJwt.digest(city), SdJwt.digest(street)]
      })

    claims = %{
      "iss" => "https://issuer.example",
      "vct" => "identity",
      "iat" => @now,
      "cnf" => %{"jwk" => holder},
      "_sd" => [SdJwt.digest(address)]
    }

    {_jws, jwt} =
      issuer
      |> JOSE.JWT.sign(%{"alg" => "ES256", "typ" => "dc+sd-jwt"}, claims)
      |> JOSE.JWS.compact()

    credential = Enum.join([jwt, address, city, street, ""], "~")
    {:ok, verified} = SdJwtVc.verify(credential, public, now: @now)

    {%{
       format: "dc+sd-jwt",
       credential: credential,
       claims: verified.claims,
       holder_binding: %{"jwk" => holder}
     }, public}
  end

  test "encrypted response contains final array VP token and state only inside ciphertext" do
    {holder, holder_public} = keypair()
    {recipient, public} = keypair()
    {held, issuer} = sd_credential(holder_public)
    req = request("dc+sd-jwt", public, [%{"path" => ["given_name"]}])

    assert {:ok, %{"identity" => [presentation]} = vp} =
             Presentation.build_vp_token(%{"identity" => held}, req,
               holder_keys: %{"identity" => holder},
               now: @now
             )

    assert {:ok, %{"response" => compact} = form} = Presentation.build_response(req, vp)
    assert Map.keys(form) == ["response"]
    refute String.contains?(compact, presentation)
    assert {:ok, bytes, header} = CryptoJWE.decrypt(recipient, compact)
    assert header["alg"] == "ECDH-ES"
    assert header["enc"] == "A256GCM"
    assert header["kid"] == "recipient"
    assert JSON.decode!(bytes) == %{"vp_token" => vp, "state" => "private-state"}

    assert {:ok, %{"identity" => [result]}} =
             VpToken.verify(vp,
               nonce: req.nonce,
               audience: req.client_id,
               issuer_jwks: issuer,
               now: @now
             )

    assert result.claims["given_name"] == "Alice"
    refute Map.has_key?(result.claims, "family_name")
    refute Map.has_key?(result.claims, "address")
  end

  test "nested disclosure includes necessary parents without unrelated siblings" do
    {holder, holder_public} = keypair()
    {_recipient, public} = keypair()
    {held, issuer} = nested_credential(holder_public)
    req = request("dc+sd-jwt", public, [%{"path" => ["address", "city"]}])

    assert {:ok, vp} =
             Presentation.build_vp_token(%{"identity" => held}, req,
               holder_keys: %{"identity" => holder},
               now: @now
             )

    assert {:ok, %{"identity" => [result]}} =
             VpToken.verify(vp,
               nonce: req.nonce,
               audience: req.client_id,
               issuer_jwks: issuer,
               now: @now
             )

    assert result.claims["address"] == %{"city" => "Example"}
    refute Map.has_key?(result.claims, "given_name")
  end

  test "absent SD-JWT claim query preserves mandatory claims and a valid holder proof only" do
    {holder, holder_public} = keypair()
    {_recipient, public} = keypair()
    {held, issuer} = sd_credential(holder_public)
    req = request("dc+sd-jwt", public)

    assert {:ok, %{"identity" => [presentation]} = vp} =
             Presentation.build_vp_token(%{"identity" => held}, req,
               holder_keys: %{"identity" => holder},
               now: @now
             )

    assert [issuer_jwt, holder_proof] = String.split(presentation, "~")
    assert issuer_jwt == hd(String.split(held.credential, "~"))
    assert holder_proof != ""
    opts = [nonce: req.nonce, audience: req.client_id, issuer_jwks: issuer, now: @now]
    assert {:ok, %{"identity" => [result]}} = VpToken.verify(vp, opts)
    assert result.claims["iss"] == "https://issuer.example"
    assert result.claims["vct"] == "identity"
    assert result.claims["iat"] == @now
    assert result.claims["cnf"] == %{"jwk" => holder_public}
    refute Map.has_key?(result.claims, "given_name")
    refute Map.has_key?(result.claims, "family_name")
    refute Map.has_key?(result.claims, "address")
    assert {:error, _} = VpToken.verify(vp, Keyword.put(opts, :nonce, "different-nonce"))
  end

  test "unusable keys are skipped but private, duplicate-kid, unsupported algorithm sets fail closed" do
    {_recipient, public} = keypair()
    req = request("dc+sd-jwt", public)
    usable = hd(req.client_metadata["jwks"]["keys"])
    invalid = Map.merge(usable, %{"kid" => "unusable", "alg" => "RSA-OAEP"})
    with_extra = put_in(req.client_metadata["jwks"]["keys"], [invalid, usable])

    assert {:ok, %{"response" => _}} =
             Presentation.build_response(with_extra, %{"identity" => ["presentation"]})

    for keys <- [[Map.put(usable, "d", public["x"])], [usable, usable], [invalid]] do
      bad = put_in(req.client_metadata["jwks"]["keys"], keys)

      assert {:error, :invalid_encryption_metadata} =
               Presentation.build_response(bad, %{"identity" => ["presentation"]})
    end

    bad_enc =
      put_in(req.client_metadata["encrypted_response_enc_values_supported"], ["A128CBC-HS256"])

    assert {:error, :invalid_encryption_metadata} =
             Presentation.build_response(bad_enc, %{"identity" => ["presentation"]})
  end

  test "default enc is A128GCM and caller-built plaintext entries are rejected" do
    {recipient, public} = keypair()
    req = request("dc+sd-jwt", public)

    req = %{
      req
      | client_metadata:
          Map.delete(req.client_metadata, "encrypted_response_enc_values_supported")
    }

    assert {:error, :invalid_vp_token} =
             Presentation.build_response(req, %{"identity" => "plaintext"})

    assert {:error, :invalid_vp_token} =
             Presentation.build_response(req, %{"identity" => ["one", "two"]})

    multiple =
      put_in(req.dcql_query["credentials"], [
        Map.put(hd(req.dcql_query["credentials"]), "multiple", true)
      ])

    assert {:ok, _} = Presentation.build_response(multiple, %{"identity" => ["one", "two"]})

    assert {:ok, %{"response" => compact}} =
             Presentation.build_response(req, %{"identity" => ["presentation"]})

    assert {:ok, _, %{"enc" => "A128GCM"}} = CryptoJWE.decrypt(recipient, compact)
    {other, _} = keypair()
    assert {:error, :invalid_jwe} = CryptoJWE.decrypt(other, compact)
  end

  test "present submits only encrypted response and returns the browser continuation" do
    {holder, holder_public} = keypair()
    {recipient, public} = keypair()
    {held, _issuer} = sd_credential(holder_public)
    req = request("dc+sd-jwt", public)

    plug = fn conn ->
      assert conn.method == "POST"
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      assert %{"response" => compact} = form = URI.decode_query(body)
      assert Map.keys(form) == ["response"]
      assert {:ok, plaintext, _header} = CryptoJWE.decrypt(recipient, compact)

      assert %{"vp_token" => %{"identity" => [_]}, "state" => "private-state"} =
               JSON.decode!(plaintext)

      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.send_resp(
        200,
        JSON.encode!(%{"redirect_uri" => "https://verifier.example/continue?code=random"})
      )
    end

    assert {:ok, %{"redirect_uri" => "https://verifier.example/continue?code=random"}} =
             Presentation.present(req, [held],
               holder_keys: %{"identity" => holder},
               now: @now,
               req_options: [plug: plug]
             )
  end

  test "mdoc disclosure is minimized and device signature binds exact recipient key" do
    {holder, holder_public} = keypair()
    {issuer, issuer_public} = keypair()
    {_recipient, public} = keypair()
    pem = issuer |> JOSE.JWK.to_pem() |> elem(1)

    {:ok, credential} =
      Mdoc.issue(
        device_key: holder_public,
        issuer_pem: pem,
        doc_type: @doctype,
        namespaces: %{@namespace => %{"given_name" => "Alice", "family_name" => "Private"}},
        validity: %{signed: @now - 2, valid_from: @now - 1, valid_until: @now + 3600}
      )

    {:ok, verified} = Mdoc.verify(credential, issuer_public, now: @now)

    held = %{
      format: "mso_mdoc",
      credential: credential,
      claims: verified.namespaces,
      doc_type: @doctype,
      holder_binding: holder_public
    }

    req = request("mso_mdoc", public, [%{"path" => [@namespace, "given_name"]}])

    assert {:ok, vp} =
             Presentation.build_vp_token(%{"identity" => held}, req,
               holder_keys: %{"identity" => holder}
             )

    opts = [
      nonce: req.nonce,
      audience: req.client_id,
      issuer_jwks: issuer_public,
      now: @now,
      response_uri: req.response_uri,
      response_encryption_jwk: public,
      formats: %{"identity" => "mso_mdoc"}
    ]

    assert {:ok, %{"identity" => [result]}} = VpToken.verify(vp, opts)
    assert result.namespaces == %{@namespace => %{"given_name" => "Alice"}}
    {_other, other_public} = keypair()

    assert {:error, _} =
             VpToken.verify(vp, Keyword.put(opts, :response_encryption_jwk, other_public))

    assert {:error, _} = VpToken.verify(vp, Keyword.delete(opts, :response_encryption_jwk))
  end

  test "absent mdoc claim query preserves issuer authentication and a valid device proof only" do
    {holder, holder_public} = keypair()
    {issuer, issuer_public} = keypair()
    {_recipient, public} = keypair()
    pem = issuer |> JOSE.JWK.to_pem() |> elem(1)

    {:ok, credential} =
      Mdoc.issue(
        device_key: holder_public,
        issuer_pem: pem,
        doc_type: @doctype,
        namespaces: %{@namespace => %{"given_name" => "Alice", "family_name" => "Private"}},
        validity: %{signed: @now - 2, valid_from: @now - 1, valid_until: @now + 3600}
      )

    {:ok, verified} = Mdoc.verify(credential, issuer_public, now: @now)

    held = %{
      format: "mso_mdoc",
      credential: credential,
      claims: verified.namespaces,
      doc_type: @doctype,
      holder_binding: holder_public
    }

    req = request("mso_mdoc", public)

    assert {:ok, %{"identity" => [presentation]} = vp} =
             Presentation.build_vp_token(%{"identity" => held}, req,
               holder_keys: %{"identity" => holder}
             )

    {:ok, original, ""} = credential |> Base.url_decode64!(padding: false) |> CBOR.decode()
    {:ok, response, ""} = presentation |> Base.url_decode64!(padding: false) |> CBOR.decode()
    assert [document] = response["documents"]
    assert document["issuerSigned"]["issuerAuth"] == original["issuerAuth"]
    assert document["issuerSigned"]["nameSpaces"] == %{}

    opts = [
      nonce: req.nonce,
      audience: req.client_id,
      issuer_jwks: issuer_public,
      now: @now,
      response_uri: req.response_uri,
      response_encryption_jwk: public,
      formats: %{"identity" => "mso_mdoc"}
    ]

    assert {:ok, %{"identity" => [result]}} = VpToken.verify(vp, opts)
    assert result.namespaces == %{}
    assert result.device_namespaces == %{}
    assert result.doc_type == @doctype
    assert {:error, _} = VpToken.verify(vp, Keyword.put(opts, :nonce, "different-nonce"))
  end
end
