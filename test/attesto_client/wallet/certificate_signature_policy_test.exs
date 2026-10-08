defmodule AttestoClient.Wallet.CertificateSignaturePolicyTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias AttestoClient.Wallet
  alias AttestoClient.Wallet.CredentialOffer
  alias AttestoClient.Wallet.Presentation.CertificateTrust
  alias AttestoClient.Wallet.PresentationRequest

  require Record
  @records Record.extract_all(from_lib: "public_key/include/public_key.hrl")
  Record.defrecordp(:otp_certificate, :OTPCertificate, @records[:OTPCertificate])
  Record.defrecordp(:otp_tbs, :OTPTBSCertificate, @records[:OTPTBSCertificate])
  Record.defrecordp(:otp_spki, :OTPSubjectPublicKeyInfo, @records[:OTPSubjectPublicKeyInfo])
  Record.defrecordp(:public_key_algorithm, :PublicKeyAlgorithm, @records[:PublicKeyAlgorithm])
  Record.defrecordp(:extension, :Extension, @records[:Extension])

  @curve {:namedCurve, {1, 2, 840, 10_045, 3, 1, 7}}
  @issuer "https://issuer.example"
  @key_usage_oid {2, 5, 29, 15}
  @pss_oid {1, 2, 840, 113_549, 1, 1, 10}

  setup_all do
    root = :public_key.pkix_test_root_cert(~c"synthetic-signature-root", key: @curve)
    %{root: root}
  end

  for critical <- [true, false] do
    test "a #{critical}-critical leaf KU without digitalSignature cannot authenticate signatures",
         context do
      for usage <- [[:keyEncipherment], [:dataEncipherment], [:keyAgreement], [:nonRepudiation]] do
        issuer = issuer(context.root, usage, unquote(critical))

        assert {:error, :untrusted_certificate} =
                 CertificateTrust.verify([issuer.leaf], options(issuer))

        refute_policy_bypass(issuer)

        for format <- ["dc+sd-jwt", "mso_mdoc"] do
          credential = issue(format, issuer)
          assert {:error, :untrusted_certificate} = request(format, credential, issuer)
        end
      end
    end
  end

  test "digitalSignature permits genuine SD-JWT and mdoc signatures; absent KU remains usable",
       context do
    for usage <- [[:digitalSignature], [:digitalSignature, :keyAgreement], :absent] do
      issuer = issuer(context.root, usage, true)
      assert {:ok, _verified} = CertificateTrust.verify([issuer.leaf], options(issuer))

      for format <- ["dc+sd-jwt", "mso_mdoc"] do
        assert {:ok, %{credentials: [%{format: ^format}]}} =
                 request(format, issue(format, issuer), issuer)
      end
    end
  end

  test "mdoc's critical signer EKU cannot override a conflicting key usage", context do
    signer_usage = {:Extension, {2, 5, 29, 37}, true, [{1, 0, 18_013, 5, 1, 2}]}
    issuer = issuer(context.root, [:keyAgreement], false, extensions: [signer_usage])
    opts = Keyword.put(options(issuer), :purpose, :mdoc_issuer)
    assert {:error, :untrusted_certificate} = CertificateTrust.verify([issuer.leaf], opts)

    assert {:error, :untrusted_certificate} =
             request("mso_mdoc", issue("mso_mdoc", issuer), issuer)
  end

  test "a correctly signed x509 verifier request cannot use an agreement-only leaf", context do
    issuer = issuer(context.root, [:keyAgreement], false)

    client_id =
      "x509_hash:" <> Base.url_encode64(:crypto.hash(:sha256, issuer.leaf), padding: false)

    claims = %{
      "client_id" => client_id,
      "nonce" => "synthetic-nonce",
      "response_type" => "vp_token",
      "response_mode" => "direct_post",
      "response_uri" => "https://verifier.example/response",
      "dcql_query" => %{"credentials" => [%{"id" => "identity", "format" => "dc+sd-jwt"}]}
    }

    {_jws, request} =
      issuer.key
      |> JOSE.JWT.sign(
        %{
          "alg" => "ES256",
          "typ" => "oauth-authz-req+jwt",
          "x5c" => [Base.encode64(issuer.leaf)]
        },
        claims
      )
      |> JOSE.JWS.compact()

    assert {true, _, _} = JOSE.JWT.verify_strict(issuer.key, ["ES256"], request)

    assert {:error, :untrusted_certificate} =
             PresentationRequest.verify(request, nil, options(issuer))
  end

  test "PSS-specific SPKI is not silently converted to an unrestricted RSA key", context do
    issuer = issuer(context.root, [:digitalSignature], true, key: {:rsa, 2048, 65_537})
    assert {:ok, _verified} = CertificateTrust.verify([issuer.leaf], options(issuer))

    # The leaf is genuinely re-signed by the same trusted CA. Its SPKI carries
    # SHA-512/MGF1-SHA-512 and minimum salt64 constraints, not a generic RSA key.
    parameters = pss_parameters()

    for params <- [parameters, :asn1_NOVALUE] do
      restricted = restrict_pss_spki(issuer, context.root, params)

      assert {:ok, _path} =
               :public_key.pkix_path_validation(context.root.cert, [restricted.leaf], [])

      assert {:error, :untrusted_certificate} =
               CertificateTrust.verify([restricted.leaf], options(restricted))

      refute_policy_bypass(restricted)

      assert {:error, :untrusted_certificate} =
               request("dc+sd-jwt", issue("dc+sd-jwt", restricted), restricted)
    end
  end

  defp issuer(root, usage, critical, overrides \\ []) do
    extensions =
      [
        {:Extension, @key_usage_oid, critical,
         if(usage == :absent, do: [:digitalSignature], else: usage)}
      ] ++
        Keyword.get(overrides, :extensions, [])

    data =
      :public_key.pkix_test_data(%{
        root: root,
        intermediates: [],
        peer: [key: Keyword.get(overrides, :key, @curve), extensions: extensions]
      })

    leaf = if usage == :absent, do: remove_key_usage(data[:cert], root), else: data[:cert]
    holder = JOSE.JWK.generate_key({:ec, "P-256"})

    %{
      leaf: leaf,
      key: data[:key] |> elem(1) |> JOSE.JWK.from_der(),
      anchors: [root.cert],
      holder: holder,
      holder_public: holder |> JOSE.JWK.to_public_map() |> elem(1)
    }
  end

  defp remove_key_usage(leaf, root) do
    tbs = leaf |> :public_key.pkix_decode_cert(:otp) |> otp_certificate(:tbsCertificate)

    extensions =
      tbs |> otp_tbs(:extensions) |> Enum.reject(&(extension(&1, :extnID) == @key_usage_oid))

    tbs |> otp_tbs(extensions: extensions) |> :public_key.pkix_sign(root.key)
  end

  defp restrict_pss_spki(issuer, root, parameters) do
    tbs = issuer.leaf |> :public_key.pkix_decode_cert(:otp) |> otp_certificate(:tbsCertificate)
    spki = otp_tbs(tbs, :subjectPublicKeyInfo)
    algorithm = public_key_algorithm(algorithm: @pss_oid, parameters: parameters)
    spki = otp_spki(spki, algorithm: algorithm)
    leaf = tbs |> otp_tbs(subjectPublicKeyInfo: spki) |> :public_key.pkix_sign(root.key)
    %{issuer | leaf: leaf}
  end

  defp pss_parameters do
    hash = {:HashAlgorithm, {2, 16, 840, 1, 101, 3, 4, 2, 3}, :NULL}
    mgf = {:MaskGenAlgorithm, {1, 2, 840, 113_549, 1, 1, 8}, hash}
    {:"RSASSA-PSS-params", hash, mgf, 64, 1}
  end

  defp refute_policy_bypass(issuer) do
    parent = self()

    policy = fn _chain ->
      send(parent, :policy_called)
      :ok
    end

    assert {:error, :untrusted_certificate} =
             CertificateTrust.verify(
               [issuer.leaf],
               Keyword.put(options(issuer), :certificate_trust, policy)
             )

    refute_received :policy_called
  end

  defp options(issuer),
    do: [trusted_certificates: issuer.anchors, haip: true, accepted_algs: ["ES256"]]

  defp issue("dc+sd-jwt", issuer) do
    pem = issuer.key |> JOSE.JWK.to_pem() |> elem(1)

    Attesto.SdJwtVc.issue([iss: @issuer, vct: "SyntheticCredential", pem: pem],
      claims: %{"given_name" => "Synthetic"},
      cnf: %{"jwk" => issuer.holder_public},
      x5c: [Base.encode64(issuer.leaf)]
    )
  end

  defp issue("mso_mdoc", issuer) do
    now = System.system_time(:second)
    pem = issuer.key |> JOSE.JWK.to_pem() |> elem(1)

    {:ok, credential} =
      Attesto.Mdoc.issue(
        doc_type: "org.iso.18013.5.1.mDL",
        namespaces: %{"org.iso.18013.5.1" => %{"given_name" => "Synthetic"}},
        device_key: issuer.holder_public,
        issuer_pem: pem,
        validity: %{signed: now - 10, valid_from: now - 5, valid_until: now + 600},
        x5chain: [issuer.leaf]
      )

    credential
  end

  defp request(format, credential, issuer) do
    {:ok, jkt} = AttestoClient.TokenSet.dpop_thumbprint(dpop: issuer.holder)

    tokens = %AttestoClient.TokenSet{
      access_token: "synthetic-access-token",
      token_type: "DPoP",
      dpop_jkt: jkt,
      profile: :haip,
      client_auth_binding: %{method: :private_key_jwt}
    }

    {:ok, offer} =
      CredentialOffer.parse(%{
        "credential_issuer" => @issuer,
        "credential_configuration_ids" => ["SyntheticCredential"]
      })

    opts =
      issuer
      |> options()
      |> Keyword.merge(
        credential_endpoint: @issuer <> "/credential",
        format: format,
        access_token: tokens,
        dpop: issuer.holder,
        req_options: [
          plug: fn conn ->
            Req.Test.json(conn, %{"credentials" => [%{"credential" => credential}]})
          end
        ]
      )

    Wallet.request_credential(offer, issuer.holder, opts)
  end
end
