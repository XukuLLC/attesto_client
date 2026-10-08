defmodule AttestoClient.Wallet.CredentialTrustTest do
  use ExUnit.Case, async: true

  alias AttestoClient.Wallet
  alias AttestoClient.Wallet.CredentialOffer
  alias AttestoClient.Wallet.CredentialTrust
  alias AttestoClient.Wallet.Presentation.CertificateTrust

  @issuer "https://issuer.example.com"
  @curve {:namedCurve, {1, 2, 840, 10_045, 3, 1, 7}}

  setup_all do
    aki = :crypto.strong_rand_bytes(20)

    data =
      :public_key.pkix_test_data(%{
        root: [key: @curve, extensions: [{:Extension, {2, 5, 29, 14}, false, aki}]],
        intermediates: [],
        peer: [
          key: @curve,
          extensions: [
            {:Extension, {2, 5, 29, 35}, false,
             {:AuthorityKeyIdentifier, aki, :asn1_NOVALUE, :asn1_NOVALUE}}
          ]
        ]
      })

    key = data[:key] |> elem(1) |> JOSE.JWK.from_der()

    %{
      key: key,
      leaf: data[:cert],
      anchors: data[:cacerts],
      aki: Base.url_encode64(aki, padding: false)
    }
  end

  setup do
    holder = JOSE.JWK.generate_key({:ec, "P-256"})
    %{holder: holder, public: holder |> JOSE.JWK.to_public_map() |> elem(1)}
  end

  for format <- ~w(dc+sd-jwt mso_mdoc) do
    @format format

    test "#{@format} resolves the signature key from a trusted issuer chain", context do
      credential = issue(@format, context, [context.leaf])
      assert {:ok, %{credentials: [held]}} = request(@format, credential, context)
      assert held.format == @format
      assert held.issuer_certificate_chain == [context.leaf]
      assert held.authority_key_identifiers == [context.aki]
      assert held.credential == credential
    end

    test "#{@format} rejects absent, untrusted, self-signed and root-in-chain certificates",
         context do
      self_signed = :public_key.pkix_test_root_cert(~c"synthetic-issuer", key: @curve)
      unrelated = :public_key.pkix_test_root_cert(~c"unrelated-issuer", key: @curve)

      cases = [
        {[], context.anchors},
        {[context.leaf], [unrelated.cert]},
        {[self_signed.cert], [self_signed.cert]},
        {[context.leaf | context.anchors], context.anchors}
      ]

      for {chain, anchors} <- cases do
        credential = issue(@format, context, chain)
        trusted = context.key |> JOSE.JWK.to_public_map() |> elem(1)

        assert {:error, _} =
                 request(@format, credential, context,
                   trusted_certificates: anchors,
                   trusted: trusted
                 )
      end
    end

    test "#{@format} validates the actual signature and holder binding after chain resolution",
         context do
      wrong = %{context | key: JOSE.JWK.generate_key({:ec, "P-256"})}
      wrong_signature = issue(@format, wrong, [context.leaf])
      assert {:error, :invalid_signature} = request(@format, wrong_signature, context)

      wrong_holder = %{
        context
        | public: JOSE.JWK.generate_key({:ec, "P-256"}) |> JOSE.JWK.to_public_map() |> elem(1)
      }

      wrong_binding = issue(@format, wrong_holder, [context.leaf])
      assert {:error, :holder_binding_mismatch} = request(@format, wrong_binding, context)
    end

    test "#{@format} applies additional policy without allowing it to bypass PKIX", context do
      credential = issue(@format, context, [context.leaf])

      assert {:error, :untrusted_certificate} =
               request(@format, credential, context,
                 certificate_trust: fn _ -> {:error, :denied} end
               )

      unrelated = :public_key.pkix_test_root_cert(~c"unrelated-policy-root", key: @curve)

      assert {:error, :untrusted_certificate} =
               request(@format, credential, context,
                 trusted_certificates: [unrelated.cert],
                 certificate_trust: fn _ -> :ok end
               )
    end

    test "#{@format} retains fixed-key non-HAIP behavior without invented provenance", context do
      credential = issue(@format, context, [])
      trusted = context.key |> JOSE.JWK.to_public_map() |> elem(1)

      assert {:ok, %{credentials: [held]}} =
               request(@format, credential, context, haip: false, trusted: trusted)

      refute Map.has_key?(held, :issuer_certificate_chain)
      refute Map.has_key?(held, :authority_key_identifiers)
    end
  end

  test "invalid HAIP options fail before any HTTP request", context do
    for overrides <- [
          [trusted_certificates: nil],
          [trusted_certificates: []],
          [trusted_certificates: [:not_der]],
          [trusted_certificates: [String.duplicate("x", 65_537)]],
          [haip: :enabled],
          [certificate_trust: :allow],
          [format: "jwt_vc_json"]
        ] do
      opts = Keyword.put(overrides, :req_options, plug: fn _ -> flunk("unexpected HTTP") end)
      assert {:error, _} = request("dc+sd-jwt", "unused", context, opts)
    end
  end

  test "critical mdoc signer usage is accepted only for an mdoc issuer leaf", context do
    issuer = signer_context(context, [signer_usage()])

    assert {:error, :untrusted_certificate} =
             CertificateTrust.verify([issuer.leaf], options(issuer))

    assert {:ok, _verified} =
             CertificateTrust.verify(
               [issuer.leaf],
               Keyword.put(options(issuer), :purpose, :mdoc_issuer)
             )

    credential = issue("mso_mdoc", issuer, [issuer.leaf])
    assert {:ok, %{credentials: [held]}} = request("mso_mdoc", credential, issuer)
    assert held.issuer_certificate_chain == [issuer.leaf]

    sd_jwt = issue("dc+sd-jwt", issuer, [issuer.leaf])

    assert {:error, :untrusted_certificate} =
             request("dc+sd-jwt", sd_jwt, issuer, purpose: :mdoc_issuer)
  end

  test "mdoc purpose does not accept a different usage or an additional unknown critical extension",
       context do
    wrong_usage = {:Extension, {2, 5, 29, 37}, true, [{1, 3, 6, 1, 5, 5, 7, 3, 1}]}
    unknown = {:Extension, {1, 2, 3, 4}, true, <<5, 0>>}

    for extensions <- [[wrong_usage], [signer_usage(), unknown]] do
      issuer = signer_context(context, extensions)
      credential = issue("mso_mdoc", issuer, [issuer.leaf])
      assert {:error, :untrusted_certificate} = request("mso_mdoc", credential, issuer)
    end
  end

  test "mdoc purpose retains certificate time, chain and signature validation", context do
    issuer = signer_context(context, [signer_usage()])
    opts = Keyword.put(options(issuer), :purpose, :mdoc_issuer)
    unrelated = :public_key.pkix_test_root_cert(~c"unrelated-mdoc-root", key: @curve)

    assert {:error, :untrusted_certificate} =
             CertificateTrust.verify(
               [issuer.leaf],
               Keyword.put(opts, :trusted_certificates, [unrelated.cert])
             )

    last = byte_size(issuer.leaf) - 1
    prefix = binary_part(issuer.leaf, 0, last)
    tail = :binary.last(issuer.leaf)
    tampered = prefix <> <<Bitwise.bxor(tail, 1)>>
    assert {:error, _} = CertificateTrust.verify([tampered], opts)

    expired =
      signer_context(context, [signer_usage()], validity: {{2020, 1, 1}, {2020, 1, 2}})

    assert {:error, :untrusted_certificate} =
             CertificateTrust.verify(
               [expired.leaf],
               Keyword.put(options(expired), :purpose, :mdoc_issuer)
             )
  end

  test "mdoc purpose does not recognize document signer usage on an intermediate CA" do
    data =
      :public_key.pkix_test_data(%{
        root: [key: @curve],
        intermediates: [[key: @curve, extensions: [signer_usage()]]],
        peer: [key: @curve]
      })

    root = Enum.find(data[:cacerts], &:public_key.pkix_is_self_signed/1)
    intermediate = Enum.find(data[:cacerts], &(not :public_key.pkix_is_self_signed(&1)))

    assert {:error, :untrusted_certificate} =
             CertificateTrust.verify([data[:cert], intermediate],
               trusted_certificates: [root],
               purpose: :mdoc_issuer
             )
  end

  test "HAIP and default fixed-key PS256 issuance enforce RSA2048; explicit broader policy is available",
       context do
    for bits <- [1024, 2048] do
      data =
        :public_key.pkix_test_data(%{
          root: [key: @curve],
          intermediates: [],
          peer: [key: {:rsa, bits, 65_537}]
        })

      issuer = certificate_context(context, data)

      credential =
        issue("dc+sd-jwt", issuer, [issuer.leaf])
        |> resign_sd_jwt(issuer.key, %{"alg" => "PS256"})

      assert {:ok, _provenance} =
               CertificateTrust.verify(
                 [issuer.leaf],
                 options(issuer)
               )

      jwt = credential |> String.split("~") |> hd()
      assert {true, %JOSE.JWT{}, _} = JOSE.JWT.verify_strict(issuer.key, ["PS256"], jwt)

      for overrides <- [[], [verify_opts: [accepted_algs: ["PS256"]]]] do
        assert_rsa_result(request("dc+sd-jwt", credential, issuer, overrides), bits)
      end

      trusted = issuer.key |> JOSE.JWK.to_public_map() |> elem(1)

      assert {:ok, %{credentials: [_]}} =
               request("dc+sd-jwt", credential, issuer,
                 haip: false,
                 trusted: trusted,
                 verify_opts: [enforce_fapi_alg_policy: false]
               )

      assert_rsa_result(
        request("dc+sd-jwt", credential, issuer, haip: false, trusted: trusted),
        bits
      )
    end
  end

  test "HAIP PS256 cannot use a non-RSA certificate key", context do
    [jwt | rest] = issue("dc+sd-jwt", context, [context.leaf]) |> String.split("~")
    {:ok, header} = Attesto.JWS.peek_json(jwt, :protected)
    [_protected, payload, signature] = String.split(jwt, ".")

    header =
      header |> Map.put("alg", "PS256") |> JSON.encode!() |> Base.url_encode64(padding: false)

    credential = Enum.join([Enum.join([header, payload, signature], ".") | rest], "~")

    assert {:error, :invalid_signature} = request("dc+sd-jwt", credential, context)
  end

  test "the HAIP PS256 strength check preserves supported ES384 and ES512 policy", context do
    for {curve, alg} <- [{{1, 3, 132, 0, 34}, "ES384"}, {{1, 3, 132, 0, 35}, "ES512"}] do
      data =
        :public_key.pkix_test_data(%{
          root: [key: @curve],
          intermediates: [],
          peer: [key: {:namedCurve, curve}]
        })

      issuer = certificate_context(context, data)
      credential = issue("dc+sd-jwt", issuer, [issuer.leaf])

      assert {:ok, %{credentials: [_]}} =
               request("dc+sd-jwt", credential, issuer, verify_opts: [accepted_algs: [alg]])
    end
  end

  @tag :requires_core_jwe
  test "HAIP certificate identity permits omitted issuer while malformed issuer still fails",
       context do
    issued = issue("dc+sd-jwt", context, [context.leaf])
    credential = resign_sd_jwt(issued, context.key, %{}, &Map.delete(&1, "iss"))

    assert {:ok, %{credentials: [held]}} = request("dc+sd-jwt", credential, context)
    refute Map.has_key?(held.claims, "iss")
    assert held.issuer_certificate_chain == [context.leaf]
    assert held.authority_key_identifiers == [context.aki]

    trusted = context.key |> JOSE.JWK.to_public_map() |> elem(1)

    assert {:error, :missing_iss} =
             request("dc+sd-jwt", credential, context, haip: false, trusted: trusted)

    for issuer <- [nil, 42, ""] do
      malformed = resign_sd_jwt(issued, context.key, %{}, &Map.put(&1, "iss", issuer))
      assert {:error, :missing_iss} = request("dc+sd-jwt", malformed, context)
    end
  end

  test "mdoc accepts a single certificate byte string and rejects malformed or oversized envelopes",
       context do
    issued = issue("mso_mdoc", context, [context.leaf])
    raw = Base.url_decode64!(issued, padding: false)
    assert {:ok, envelope, ""} = CBOR.decode(raw)
    [protected, _unprotected, payload, signature] = envelope["issuerAuth"]

    single = %{
      envelope
      | "issuerAuth" => [protected, %{33 => bytes(context.leaf)}, payload, signature]
    }

    encoded = single |> CBOR.encode() |> Base.url_encode64(padding: false)
    assert {:ok, %{credentials: [_held]}} = request("mso_mdoc", encoded, context)

    for chain <- [
          [context.leaf],
          [bytes(String.duplicate("x", 65_537))],
          List.duplicate(bytes(context.leaf), 9)
        ] do
      malformed = %{envelope | "issuerAuth" => [protected, %{33 => chain}, payload, signature]}
      input = malformed |> CBOR.encode() |> Base.url_encode64(padding: false)

      assert {:error, :invalid_certificate} =
               CredentialTrust.resolve("mso_mdoc", input, options(context))
    end

    for input <- [raw <> <<0>>, String.duplicate("A", 1_398_103)] do
      assert {:error, :invalid_certificate} =
               CredentialTrust.resolve("mso_mdoc", input, options(context))
    end
  end

  defp issue("dc+sd-jwt", context, chain) do
    pem = context.key |> JOSE.JWK.to_pem() |> elem(1)

    Attesto.SdJwtVc.issue([iss: @issuer, vct: "ExampleCredential", pem: pem],
      claims: %{"given_name" => "Synthetic", "authority_key_identifiers" => ["unverified-value"]},
      cnf: %{"jwk" => context.public},
      x5c: if(chain == [], do: nil, else: Enum.map(chain, &Base.encode64/1))
    )
  end

  defp issue("mso_mdoc", context, chain) do
    now = System.system_time(:second)
    pem = context.key |> JOSE.JWK.to_pem() |> elem(1)

    assert {:ok, credential} =
             Attesto.Mdoc.issue(
               doc_type: "org.iso.18013.5.1.mDL",
               namespaces: %{"org.iso.18013.5.1" => %{"given_name" => "Synthetic"}},
               device_key: context.public,
               issuer_pem: pem,
               validity: %{signed: now - 10, valid_from: now - 5, valid_until: now + 600},
               x5chain: chain
             )

    credential
  end

  defp options(context),
    do: [haip: true, format: "mso_mdoc", trusted_certificates: context.anchors]

  defp request(format, credential, context, overrides \\ []) do
    {:ok, offer} =
      CredentialOffer.parse(%{
        "credential_issuer" => @issuer,
        "credential_configuration_ids" => ["ExampleCredential"]
      })

    plug = fn conn -> Req.Test.json(conn, %{"credentials" => [%{"credential" => credential}]}) end

    {:ok, jkt} = AttestoClient.TokenSet.dpop_thumbprint(dpop: context.holder)
    haip = Keyword.get(overrides, :haip, true)

    tokens = %AttestoClient.TokenSet{
      access_token: "synthetic-access-token",
      token_type: "DPoP",
      dpop_jkt: jkt,
      profile: if(haip == true, do: :haip, else: :generic),
      client_auth_binding: %{method: :private_key_jwt}
    }

    opts =
      context
      |> options()
      |> Keyword.merge(
        credential_endpoint: @issuer <> "/credential",
        format: format,
        access_token: tokens,
        dpop: context.holder,
        req_options: [plug: plug]
      )
      |> Keyword.merge(overrides)

    Wallet.request_credential(offer, context.holder, opts)
  end

  defp certificate_context(context, data) do
    %{
      context
      | key: data[:key] |> elem(1) |> JOSE.JWK.from_der(),
        leaf: data[:cert],
        anchors: data[:cacerts]
    }
  end

  defp signer_context(context, extensions, overrides \\ []) do
    data =
      :public_key.pkix_test_data(%{
        root: [key: @curve],
        intermediates: [],
        peer: Keyword.merge([key: @curve, extensions: extensions], overrides)
      })

    certificate_context(context, data)
  end

  defp signer_usage, do: {:Extension, {2, 5, 29, 37}, true, [{1, 0, 18_013, 5, 1, 2}]}

  defp resign_sd_jwt(credential, key, header_overrides, transform \\ fn claims -> claims end) do
    [jwt | rest] = String.split(credential, "~")
    {:ok, header} = Attesto.JWS.peek_json(jwt, :protected)
    {:ok, claims} = Attesto.JWS.peek_json(jwt, :payload)

    signed =
      Attesto.JWS.sign_compact_jwk(key, Map.merge(header, header_overrides), transform.(claims))

    Enum.join([signed | rest], "~")
  end

  defp assert_rsa_result(result, 1024), do: assert(result == {:error, :invalid_signature})
  defp assert_rsa_result({:ok, %{credentials: [_]}}, 2048), do: :ok

  defp bytes(value), do: %CBOR.Tag{tag: :bytes, value: value}
end
