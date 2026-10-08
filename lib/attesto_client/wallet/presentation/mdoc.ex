if Code.ensure_loaded?(CBOR) do
  defmodule AttestoClient.Wallet.Presentation.Mdoc do
    @moduledoc """
    Build an OID4VP `mso_mdoc` presentation - a full ISO 18013-5
    `DeviceResponse` - the holder-side mirror of
    `Attesto.Mdoc.verify_device_response/4`.

    `build_device_response/4` preserves the issuer signature and selected
    issuer-signed items, then signs `DeviceAuthentication` as a detached ES256
    `COSE_Sign1` over the OID4VP 1.0 redirect-flow session transcript.
    `:claim_paths` selects issuer-signed namespace elements; omitted paths
    include all elements. Device-signed namespaces are empty.

    For encrypted responses, `:response_encryption_jwk` supplies the exact
    recipient public key selected from authenticated request metadata. Its
    SHA-256 JWK thumbprint binds the handover to the encryption recipient.
    Unencrypted responses use a null thumbprint.
    """

    alias Attesto.{Cose, JWS, Thumbprint}

    @doc_status 0
    @version "1.0"

    # Attesto's mdoc decoder caps raw CBOR at 1 MiB. Apply the equivalent
    # unpadded Base64URL ceiling before decoding so an oversized held
    # credential cannot allocate its full decoded representation first.
    @max_issuer_signed_bytes 1_048_576
    @max_encoded_issuer_signed_bytes div(@max_issuer_signed_bytes * 4 + 2, 3)

    @type error :: :invalid_credential | :invalid_key

    @doc """
    Build a base64url-encoded `DeviceResponse` for a single held `mso_mdoc`
    credential.

    `held` is the entry `AttestoClient.Wallet.request_credential/3` returned
    for an `mso_mdoc` credential (`:credential` the base64url `IssuerSigned`
    structure, `:doc_type` the verified document type). `holder_key` is the
    device's *private* key (a `JOSE.JWK`, a JWK map, or a PEM string) matching
    the public device key the issuer bound in the credential's MSO -
    ES256/P-256 only, per `Attesto.Cose`. `request` supplies `:client_id`,
    `:nonce`, and `:response_uri` for the `OpenID4VPHandover` (a
    `AttestoClient.Wallet.PresentationRequest` struct or an equivalent map).
    """
    @spec build_device_response(map(), map(), JOSE.JWK.t() | map() | String.t(), keyword()) ::
            {:ok, String.t()} | {:error, error()}
    def build_device_response(held, request, holder_key, opts \\ [])

    def build_device_response(%{credential: _} = held, request, holder_key, opts)
        when is_list(opts) do
      do_build(held, request, holder_key, opts)
    rescue
      _error -> {:error, :invalid_key}
    catch
      _kind, _reason -> {:error, :invalid_key}
    end

    def build_device_response(_held, _request, _holder_key, _opts),
      do: {:error, :invalid_credential}

    defp do_build(held, request, holder_key, opts) do
      with {:ok, issuer_signed} <- decode_issuer_signed(held),
           {:ok, issuer_signed} <-
             filter_namespaces(issuer_signed, Keyword.get(opts, :claim_paths, :all)),
           {:ok, doc_type} <- doc_type(held),
           {:ok, pem} <- holder_pem(holder_key),
           {:ok, session_transcript} <- session_transcript(request, opts) do
        device_namespaces_tagged = embedded_cbor(%{})

        device_authentication_bytes =
          ["DeviceAuthentication", session_transcript, doc_type, device_namespaces_tagged]
          |> embedded_cbor()
          |> CBOR.encode()

        {:ok, device_auth_cose, ""} =
          pem |> Cose.sign1_detached(device_authentication_bytes, []) |> CBOR.decode()

        document = %{
          "docType" => doc_type,
          "issuerSigned" => issuer_signed,
          "deviceSigned" => %{
            "nameSpaces" => device_namespaces_tagged,
            "deviceAuth" => %{"deviceSignature" => device_auth_cose}
          }
        }

        response =
          %{"documents" => [document], "status" => @doc_status, "version" => @version}
          |> CBOR.encode()
          |> Base.url_encode64(padding: false)

        {:ok, response}
      end
    end

    defp decode_issuer_signed(%{credential: credential})
         when is_binary(credential) and
                byte_size(credential) <= @max_encoded_issuer_signed_bytes do
      with {:ok, bytes} <- JWS.decode64(credential),
           {:ok, %{"issuerAuth" => _issuer_auth, "nameSpaces" => _name_spaces} = issuer_signed,
            ""} <-
             CBOR.decode(bytes) do
        {:ok, issuer_signed}
      else
        _other -> {:error, :invalid_credential}
      end
    end

    defp decode_issuer_signed(_held), do: {:error, :invalid_credential}

    defp doc_type(%{doc_type: doc_type}) when is_binary(doc_type) and doc_type != "",
      do: {:ok, doc_type}

    defp doc_type(_held), do: {:error, :invalid_credential}

    defp holder_pem(pem) when is_binary(pem), do: {:ok, pem}

    defp holder_pem(%JOSE.JWK{} = jwk) do
      case JOSE.JWK.to_pem(jwk) do
        {_type, pem} when is_binary(pem) -> {:ok, pem}
        _other -> {:error, :invalid_key}
      end
    end

    defp holder_pem(%{} = jwk_map) do
      jwk_map |> JOSE.JWK.from_map() |> holder_pem()
    end

    defp holder_pem(_other), do: {:error, :invalid_key}

    # OID4VP "Handover and SessionTranscript Definitions" (redirect flow):
    # SessionTranscript = [null, null, OpenID4VPHandover], where
    # OpenID4VPHandover = ["OpenID4VPHandover", sha256(OpenID4VPHandoverInfo)]
    # and OpenID4VPHandoverInfo = [client_id, nonce, jwkThumbprint, response_uri].
    # Encrypted responses use the recipient JWK's raw SHA-256 thumbprint bytes.
    defp session_transcript(
           %{client_id: client_id, nonce: nonce, response_uri: response_uri},
           opts
         )
         when is_binary(client_id) and client_id != "" and is_binary(nonce) and nonce != "" and
                is_binary(response_uri) and response_uri != "" do
      with {:ok, thumbprint} <- encryption_thumbprint(Keyword.get(opts, :response_encryption_jwk)) do
        hash =
          [client_id, nonce, thumbprint, response_uri]
          |> CBOR.encode()
          |> then(&:crypto.hash(:sha256, &1))

        {:ok, [nil, nil, ["OpenID4VPHandover", bytes(hash)]]}
      end
    end

    defp session_transcript(_request, _opts), do: {:error, :invalid_credential}

    defp encryption_thumbprint(nil), do: {:ok, nil}

    defp encryption_thumbprint(jwk) do
      with {:ok, encoded} <- Thumbprint.of_jwk(jwk),
           {:ok, raw} <- JWS.decode64(encoded),
           do: {:ok, bytes(raw)}
    end

    defp filter_namespaces(issuer_signed, :all), do: {:ok, issuer_signed}

    defp filter_namespaces(%{"nameSpaces" => namespaces} = issuer_signed, paths)
         when is_list(paths) do
      kept =
        Enum.reduce(namespaces, %{}, fn {namespace, items}, acc ->
          selected = Enum.filter(items, &requested_item?(&1, namespace, paths))
          if selected == [], do: acc, else: Map.put(acc, namespace, selected)
        end)

      {:ok, Map.put(issuer_signed, "nameSpaces", kept)}
    end

    defp filter_namespaces(_issuer_signed, _paths), do: {:error, :invalid_credential}

    defp requested_item?(
           %CBOR.Tag{tag: 24, value: %CBOR.Tag{tag: :bytes, value: encoded}},
           namespace,
           paths
         ) do
      case CBOR.decode(encoded) do
        {:ok, %{"elementIdentifier" => element}, ""} ->
          Enum.any?(paths, fn
            [^namespace, ^element | _rest] -> true
            _ -> false
          end)

        _ ->
          false
      end
    end

    defp requested_item?(_item, _namespace, _paths), do: false

    defp embedded_cbor(value), do: %CBOR.Tag{tag: 24, value: bytes(CBOR.encode(value))}
    defp bytes(value) when is_binary(value), do: %CBOR.Tag{tag: :bytes, value: value}
  end
else
  defmodule AttestoClient.Wallet.Presentation.Mdoc do
    @moduledoc "Requires the optional `:cbor` dependency."

    def build_device_response(_held, _request, _holder_key, _opts \\ []),
      do: {:error, :unsupported_mdoc}
  end
end
