defmodule AttestoClient.Wallet.StrictCBORTest do
  use ExUnit.Case, async: true

  alias Attesto.StrictCBOR
  alias AttestoClient.Wallet.{CredentialTrust, Presentation, PresentationRequest}
  alias AttestoClient.Wallet.Presentation.{Formats, Mdoc}

  @namespace "org.iso.18013.5.1"
  @doc_type "org.iso.18013.5.1.mDL"

  setup_all do
    curve = {:namedCurve, {1, 2, 840, 10_045, 3, 1, 7}}

    chain =
      :public_key.pkix_test_data(%{root: [key: curve], intermediates: [], peer: [key: curve]})

    issuer = chain[:key] |> elem(1) |> JOSE.JWK.from_der()
    holder = JOSE.JWK.generate_key({:ec, "P-256"})
    public = holder |> JOSE.JWK.to_public_map() |> elem(1)
    now = System.system_time(:second)

    {:ok, credential} =
      Attesto.Mdoc.issue(
        issuer_pem: issuer |> JOSE.JWK.to_pem() |> elem(1),
        device_key: public,
        doc_type: @doc_type,
        namespaces: %{@namespace => %{"given_name" => "Alice"}},
        validity: %{signed: now - 10, valid_from: now - 5, valid_until: now + 600},
        x5chain: [chain[:cert]]
      )

    {:ok, verified} = Attesto.Mdoc.verify(credential, issuer, now: now)
    {:ok, envelope} = credential |> Base.url_decode64!(padding: false) |> StrictCBOR.decode()

    held = %{
      format: "mso_mdoc",
      credential: credential,
      claims: verified.namespaces,
      holder_binding: public,
      doc_type: @doc_type
    }

    metadata = %{
      "vp_formats_supported" => %{
        "mso_mdoc" => %{"issuerauth_alg_values" => [-7], "deviceauth_alg_values" => [-7]}
      }
    }

    request = %PresentationRequest{
      client_id: "https://verifier.example",
      nonce: "cbor-contract-nonce",
      response_uri: "https://verifier.example/response",
      response_mode: "direct_post",
      dcql_query: %{"credentials" => [%{"id" => "mdl", "format" => "mso_mdoc"}]},
      client_metadata: metadata
    }

    {:ok, response} = Mdoc.build_device_response(held, request, holder)
    {:ok, response_map} = response |> Base.url_decode64!(padding: false) |> StrictCBOR.decode()

    %{
      held: held,
      holder: holder,
      issuer: issuer,
      now: now,
      envelope: envelope,
      metadata: metadata,
      request: request,
      response: response,
      response_map: response_map,
      trust: [haip: true, trusted_certificates: chain[:cacerts]]
    }
  end

  test "credential provenance rejects repeated envelope and nested unprotected header keys",
       ctx do
    assert {:ok, _, _} = CredentialTrust.resolve("mso_mdoc", ctx.held.credential, ctx.trust)

    for raw <- duplicate_envelopes(ctx.envelope), input <- [raw, encode64(raw)] do
      assert {:error, :invalid_certificate} =
               CredentialTrust.resolve("mso_mdoc", input, ctx.trust)
    end
  end

  test "credential format checks reject repeated envelope and nested keys", ctx do
    assert :ok = Formats.check_credential(ctx.metadata, ctx.held, ctx.holder, [])

    for raw <- duplicate_envelopes(ctx.envelope) do
      held = %{ctx.held | credential: encode64(raw)}

      assert {:error, :incompatible_verifier_format} =
               Formats.check_credential(ctx.metadata, held, ctx.holder, [])

      assert {:error, {"mdl", :incompatible_verifier_format}} =
               Presentation.build_vp_token(%{"mdl" => held}, ctx.request,
                 holder_keys: %{"mdl" => ctx.holder}
               )
    end
  end

  test "credential format checks reject repeated protected algorithm and nested extension keys",
       ctx do
    for protected <- duplicate_headers() do
      envelope = Map.update!(ctx.envelope, "issuerAuth", &put_protected(&1, protected))
      held = %{ctx.held | credential: encode(envelope)}

      assert {:error, :incompatible_verifier_format} =
               Formats.check_credential(ctx.metadata, held, ctx.holder, [])
    end
  end

  test "response format checks reject repeated outer and nested document keys", ctx do
    assert {:ok, _} = Presentation.build_response(ctx.request, %{"mdl" => [ctx.response]})
    [document] = ctx.response_map["documents"]

    for raw <- [
          duplicate_map(ctx.response_map, "documents"),
          replace_cbor(ctx.response_map, document, duplicate_map(document, "issuerSigned"))
        ] do
      assert_response_rejected(ctx, encode64(raw))
    end
  end

  for signer <- [:issuer, :device] do
    @signer signer
    test "response format checks reject repeated #{@signer} protected header keys", ctx do
      path =
        case @signer do
          :issuer -> ["issuerSigned", "issuerAuth"]
          :device -> ["deviceSigned", "deviceAuth", "deviceSignature"]
        end

      [document] = ctx.response_map["documents"]

      for protected <- duplicate_headers() do
        modified = update_in(document, path, &put_protected(&1, protected))
        response = Map.put(ctx.response_map, "documents", [modified])
        assert_response_rejected(ctx, encode(response))
      end
    end
  end

  test "device response builder rejects repeated IssuerSigned envelope and nested keys", ctx do
    for raw <- duplicate_envelopes(ctx.envelope) do
      assert {:error, :invalid_credential} =
               Mdoc.build_device_response(
                 %{ctx.held | credential: encode64(raw)},
                 ctx.request,
                 ctx.holder
               )
    end
  end

  test "device response builder rejects repeated embedded item keys for every claim selection",
       ctx do
    [item] = ctx.envelope["nameSpaces"][@namespace]
    {:ok, item_map} = StrictCBOR.decode(item.value.value)
    nested = Map.put(item_map, "elementValue", %{"nested" => [%{"flag" => true}]})

    for encoded <- [
          duplicate_map(item_map, "elementIdentifier"),
          duplicate_map(item_map, "elementValue", :indefinite),
          replace_cbor(nested, %{"flag" => true}, duplicate_map(%{"flag" => true}, "flag"))
        ],
        opts <- [
          [],
          [claim_paths: []],
          [claim_paths: [[@namespace, "given_name"]]],
          [claim_paths: [[@namespace, "unrequested"]]]
        ] do
      bad_item = %{item | value: bytes(encoded)}
      envelope = put_in(ctx.envelope, ["nameSpaces", @namespace], [bad_item])

      assert {:error, :invalid_credential} =
               Mdoc.build_device_response(
                 %{ctx.held | credential: encode(envelope)},
                 ctx.request,
                 ctx.holder,
                 opts
               )
    end
  end

  test "valid embedded items retain their original bytes and local device signatures verify",
       ctx do
    opts = [claim_paths: [[@namespace, "given_name"]]]
    assert {:ok, response} = Mdoc.build_device_response(ctx.held, ctx.request, ctx.holder, opts)
    assert {:ok, decoded} = response |> Base.url_decode64!(padding: false) |> StrictCBOR.decode()
    [document] = decoded["documents"]
    assert document["issuerSigned"] == ctx.envelope

    assert :ok =
             Formats.check_response(ctx.metadata, ctx.request.dcql_query, %{"mdl" => [response]})

    signature = get_in(document, ["deviceSigned", "deviceAuth", "deviceSignature"])
    [protected, _, nil, _] = signature
    assert {:ok, %{1 => -7}} = StrictCBOR.decode(protected.value)

    assert {:ok, [_verified]} =
             Attesto.Mdoc.verify_device_response(
               response,
               [
                 client_id: ctx.request.client_id,
                 nonce: ctx.request.nonce,
                 response_uri: ctx.request.response_uri
               ],
               ctx.issuer,
               now: ctx.now
             )
  end

  test "decode entry points retain trailing-data and encoded-size rejection", ctx do
    raw = CBOR.encode(ctx.envelope)

    for input <- [encode64(raw <> <<0>>), String.duplicate("A", 1_398_103)] do
      held = %{ctx.held | credential: input}

      assert {:error, :invalid_certificate} =
               CredentialTrust.resolve("mso_mdoc", input, ctx.trust)

      assert {:error, :incompatible_verifier_format} =
               Formats.check_credential(ctx.metadata, held, ctx.holder, [])

      assert {:error, :invalid_credential} =
               Mdoc.build_device_response(held, ctx.request, ctx.holder)
    end
  end

  defp assert_response_rejected(ctx, response) do
    vp = %{"mdl" => [response]}

    assert {:error, :incompatible_verifier_format} =
             Formats.check_response(ctx.metadata, ctx.request.dcql_query, vp)

    assert {:error, :incompatible_verifier_format} = Presentation.build_response(ctx.request, vp)
  end

  defp duplicate_envelopes(envelope) do
    [_protected, unprotected, _payload, _signature] = envelope["issuerAuth"]
    namespaces = envelope["nameSpaces"]

    [
      duplicate_map(envelope, "issuerAuth"),
      duplicate_map(envelope, "nameSpaces", :indefinite),
      replace_cbor(envelope, unprotected, duplicate_map(unprotected, 33)),
      replace_cbor(envelope, namespaces, duplicate_map(namespaces, @namespace))
    ]
  end

  defp duplicate_headers do
    nested = %{1 => -7, "extension" => [%{"flag" => true}]}

    [
      <<0xA2, 1, 0x26, 1, 0x26>>,
      <<0xBF, 1, 0x26, 1, 0x26, 0xFF>>,
      <<0xA2, 1, 0x26, 0x18, 1, 0x26>>,
      replace_cbor(nested, %{"flag" => true}, duplicate_map(%{"flag" => true}, "flag"))
    ]
  end

  # Encode pairs directly: constructing an Elixir map would erase the duplicate.
  defp duplicate_map(map, key, kind \\ :definite) do
    entries = Map.to_list(map) ++ [{key, Map.fetch!(map, key)}]
    pairs = Enum.map(entries, fn {key, value} -> [CBOR.encode(key), CBOR.encode(value)] end)

    case kind do
      :definite -> IO.iodata_to_binary([<<5::3, length(entries)::5>>, pairs])
      :indefinite -> IO.iodata_to_binary([<<0xBF>>, pairs, <<0xFF>>])
    end
  end

  defp replace_cbor(term, original, replacement) do
    encoded = CBOR.encode(term)
    original = CBOR.encode(original)
    assert length(:binary.matches(encoded, original)) == 1
    :binary.replace(encoded, original, replacement)
  end

  defp put_protected([_protected | rest], encoded), do: [bytes(encoded) | rest]
  defp bytes(value), do: %CBOR.Tag{tag: :bytes, value: value}
  defp encode(value), do: value |> CBOR.encode() |> encode64()
  defp encode64(value), do: Base.url_encode64(value, padding: false)
end
