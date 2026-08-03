if Code.ensure_loaded?(CBOR) do
  defmodule AttestoClient.Wallet.Presentation.Mdoc do
    @moduledoc """
    Build an OID4VP `mso_mdoc` presentation - a full ISO 18013-5
    `DeviceResponse` - the holder-side mirror of
    `Attesto.Mdoc.verify_device_response/4`.

    `build_device_response/4` re-embeds the held credential's `IssuerSigned`
    structure unchanged, signs `DeviceAuthentication` as a detached ES256
    `COSE_Sign1` over the OID4VP `SessionTranscript`/`OpenID4VPHandover`
    (`draft-ietf-oauth-openid4vp` "Handover and SessionTranscript
    Definitions", redirect-flow form - the same construction
    `Attesto.Mdoc.verify_device_response/4` expects), and assembles the
    `DeviceResponse`. `DeviceNameSpaces` (the device-signed, as opposed to
    issuer-signed, namespace) is always empty: this slice presents the
    credential's issuer-signed claims as a whole and does not filter
    individual `IssuerSigned` items to the requested claim set. Only
    unencrypted `direct_post` is supported - the handover's JWK thumbprint is
    always absent (`nil`), matching `direct_post.jwt` being out of scope for
    `AttestoClient.Wallet.Presentation` in this slice.
    """

    alias Attesto.{Cose, JWS}

    @doc_status 0
    @version "1.0"

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
      do_build(held, request, holder_key)
    rescue
      _error -> {:error, :invalid_key}
    catch
      _kind, _reason -> {:error, :invalid_key}
    end

    def build_device_response(_held, _request, _holder_key, _opts),
      do: {:error, :invalid_credential}

    defp do_build(held, request, holder_key) do
      with {:ok, issuer_signed} <- decode_issuer_signed(held),
           {:ok, doc_type} <- doc_type(held),
           {:ok, pem} <- holder_pem(holder_key),
           {:ok, session_transcript} <- session_transcript(request) do
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

    defp decode_issuer_signed(%{credential: credential}) when is_binary(credential) do
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
    # Unencrypted direct_post is the only response mode this builder supports,
    # so jwkThumbprint is always null.
    defp session_transcript(%{client_id: client_id, nonce: nonce, response_uri: response_uri})
         when is_binary(client_id) and client_id != "" and is_binary(nonce) and nonce != "" and
                is_binary(response_uri) and response_uri != "" do
      handover_info_hash =
        [client_id, nonce, nil, response_uri]
        |> CBOR.encode()
        |> then(&:crypto.hash(:sha256, &1))
        |> bytes()

      {:ok, [nil, nil, ["OpenID4VPHandover", handover_info_hash]]}
    end

    defp session_transcript(_request), do: {:error, :invalid_credential}

    defp embedded_cbor(value), do: %CBOR.Tag{tag: 24, value: bytes(CBOR.encode(value))}
    defp bytes(value) when is_binary(value), do: %CBOR.Tag{tag: :bytes, value: value}
  end
else
  defmodule AttestoClient.Wallet.Presentation.Mdoc do
    @moduledoc "Requires the optional `:cbor` dependency."

    @dep_error "AttestoClient.Wallet.Presentation.Mdoc requires the optional :cbor dependency. " <>
                 "Add {:cbor, \"~> 1.0\"} to your deps."

    def build_device_response(_held, _request, _holder_key, _opts \\ []), do: raise(@dep_error)
  end
end
