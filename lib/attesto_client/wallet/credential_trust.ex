defmodule AttestoClient.Wallet.CredentialTrust do
  @moduledoc false

  alias Attesto.JWS
  alias AttestoClient.Wallet.Presentation.CertificateTrust

  @formats ~w(dc+sd-jwt vc+sd-jwt mso_mdoc)
  @max_chain_length 8
  @max_cert_bytes 65_536

  @spec validate_options(keyword()) :: :ok | {:error, atom()}
  def validate_options(opts) do
    case Keyword.get(opts, :haip, false) do
      false -> :ok
      true -> validate_haip_options(opts)
      _invalid -> {:error, :invalid_haip_options}
    end
  end

  defp validate_haip_options(opts) do
    cond do
      Keyword.get(opts, :format) not in @formats ->
        {:error, :unsupported_haip_format}

      not valid_anchors?(Keyword.get(opts, :trusted_certificates)) ->
        {:error, :missing_trusted_certificates}

      not valid_policy?(Keyword.get(opts, :certificate_trust)) ->
        {:error, :invalid_haip_options}

      true ->
        :ok
    end
  end

  defp valid_anchors?(anchors) when is_list(anchors) and length(anchors) in 1..@max_chain_length,
    do: Enum.all?(anchors, &(is_binary(&1) and byte_size(&1) in 1..@max_cert_bytes))

  defp valid_anchors?(_anchors), do: false
  defp valid_policy?(nil), do: true
  defp valid_policy?(policy), do: is_function(policy, 1)

  @spec resolve(String.t(), String.t(), keyword()) ::
          {:ok, term(), map() | nil} | {:error, term()}
  def resolve(format, credential, opts) do
    if Keyword.get(opts, :haip, false) do
      with {:ok, chain} <- certificate_chain(format, credential),
           {:ok, verified} <- CertificateTrust.verify(chain, trust_options(format, opts)),
           :ok <- signature_key_strength(format, credential, verified.public_key) do
        provenance = %{
          authority_key_identifiers: verified.authority_key_identifiers,
          issuer_certificate_chain: chain
        }

        {:ok, verified.public_key, provenance}
      end
    else
      {:ok, Keyword.get(opts, :trusted), nil}
    end
  end

  defp trust_options("mso_mdoc", opts), do: Keyword.put(opts, :purpose, :mdoc_issuer)
  defp trust_options(_format, opts), do: Keyword.put(opts, :purpose, :generic)

  @spec attach(map(), map() | nil) :: map()
  def attach(held, nil), do: held
  def attach(held, provenance), do: Map.merge(held, provenance)

  defp certificate_chain(format, credential) when format in ~w(dc+sd-jwt vc+sd-jwt) do
    issuer_jwt = credential |> :binary.split("~") |> hd()

    with {:ok, header} <- JWS.peek_json(issuer_jwt, :protected),
         do: CertificateTrust.decode_x5c(header["x5c"])
  end

  defp certificate_chain("mso_mdoc", credential), do: mdoc_chain(credential)
  defp certificate_chain(_format, _credential), do: {:error, :unsupported_haip_format}

  defp signature_key_strength(format, credential, key) when format in ~w(dc+sd-jwt vc+sd-jwt) do
    issuer_jwt = credential |> :binary.split("~") |> hd()

    with {:ok, header} <- JWS.peek_json(issuer_jwt, :protected) do
      check_ps256_strength(header["alg"], key)
    end
  end

  # The mdoc verifier supports only ES256/P-256; it rejects other COSE algorithms.
  defp signature_key_strength("mso_mdoc", _credential, _key), do: :ok

  defp check_ps256_strength("PS256", key) do
    case JWS.verification_candidates(key, alg: "PS256", accepted_algs: ["PS256"], fapi?: true) do
      [_ | _] -> :ok
      [] -> {:error, :invalid_signature}
    end
  end

  defp check_ps256_strength(_algorithm, _key), do: :ok

  if Code.ensure_loaded?(CBOR) do
    @max_cbor_bytes 1_048_576
    @max_encoded_cbor_bytes div(@max_cbor_bytes * 4 + 2, 3)

    defp mdoc_chain(credential) do
      with {:ok, bytes} <- mdoc_bytes(credential),
           {:ok, %{"issuerAuth" => [_protected, unprotected, _payload, _signature]}, ""} <-
             CBOR.decode(bytes),
           true <- is_map(unprotected),
           {:ok, chain} <- der_chain(unprotected[33]) do
        {:ok, chain}
      else
        _invalid -> {:error, :invalid_certificate}
      end
    rescue
      _error -> {:error, :invalid_certificate}
    catch
      _kind, _reason -> {:error, :invalid_certificate}
    end

    defp mdoc_bytes(credential) when byte_size(credential) <= @max_encoded_cbor_bytes do
      decoded =
        if String.valid?(credential) and Regex.match?(~r/\A[A-Za-z0-9_-]+\z/, credential),
          do: JWS.decode64(credential, max_encoded_bytes: @max_encoded_cbor_bytes),
          else: {:ok, credential}

      bound_cbor(decoded)
    end

    defp mdoc_bytes(_credential), do: {:error, :invalid_certificate}

    defp bound_cbor({:ok, bytes}) when byte_size(bytes) in 1..@max_cbor_bytes, do: {:ok, bytes}
    defp bound_cbor(_invalid), do: {:error, :invalid_certificate}

    defp der_chain(%CBOR.Tag{tag: :bytes} = certificate), do: der_chain([certificate])

    defp der_chain(chain) when is_list(chain) and length(chain) in 1..@max_chain_length do
      chain
      |> Enum.reduce_while({:ok, []}, fn certificate, {:ok, acc} ->
        case der_bytes(certificate) do
          {:ok, der} -> {:cont, {:ok, [der | acc]}}
          error -> {:halt, error}
        end
      end)
      |> reverse_chain()
    end

    defp der_chain(_invalid), do: {:error, :invalid_certificate}

    defp der_bytes(%CBOR.Tag{tag: :bytes, value: der})
         when is_binary(der) and byte_size(der) in 1..@max_cert_bytes,
         do: {:ok, der}

    defp der_bytes(_invalid), do: {:error, :invalid_certificate}

    defp reverse_chain({:ok, chain}), do: {:ok, Enum.reverse(chain)}
    defp reverse_chain(error), do: error
  else
    defp mdoc_chain(_credential), do: {:error, :unsupported_mdoc}
  end
end
