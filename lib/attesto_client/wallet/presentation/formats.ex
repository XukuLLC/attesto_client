defmodule AttestoClient.Wallet.Presentation.Formats do
  @moduledoc false
  alias Attesto.JWS
  alias AttestoClient.Builder

  @sd_formats ~w(dc+sd-jwt vc+sd-jwt)
  @jose_fields ~w(sd-jwt_alg_values kb-jwt_alg_values)
  @cose_fields ~w(issuerauth_alg_values deviceauth_alg_values)

  def resolve(client_id, signed, opts) when is_map(signed) do
    case authoritative_metadata(client_id, signed, opts) do
      metadata when is_map(metadata) ->
        with :ok <- validate(metadata), do: {:ok, metadata}

      _ ->
        {:error, :invalid_verifier_metadata}
    end
  end

  def resolve(_client_id, _signed, _opts), do: {:error, :invalid_verifier_metadata}

  defp authoritative_metadata("x509_hash:" <> _, signed, _opts), do: signed

  defp authoritative_metadata(_client_id, signed, opts) do
    case Keyword.get(opts, :verifier_metadata, %{}) do
      trusted when is_map(trusted) -> Map.merge(signed, trusted)
      _ -> :invalid
    end
  end

  def validate(%{"vp_formats_supported" => formats})
      when is_map(formats) and map_size(formats) in 1..32 do
    if Enum.all?(formats, &valid_format?/1), do: :ok, else: {:error, :invalid_verifier_metadata}
  end

  def validate(_metadata), do: {:error, :invalid_verifier_metadata}

  defp valid_format?({format, parameters})
       when is_binary(format) and byte_size(format) in 1..128 and is_map(parameters) do
    cond do
      format in @sd_formats -> Enum.all?(@jose_fields, &valid_algorithms?(parameters, &1, :jose))
      format == "mso_mdoc" -> Enum.all?(@cose_fields, &valid_algorithms?(parameters, &1, :cose))
      true -> true
    end
  end

  defp valid_format?(_entry), do: false

  defp valid_algorithms?(parameters, field, kind) do
    case Map.fetch(parameters, field) do
      :error ->
        true

      {:ok, values} when is_list(values) and length(values) in 1..64 ->
        Enum.all?(values, &valid_algorithm?(&1, kind))

      _ ->
        false
    end
  end

  defp valid_algorithm?(value, :jose),
    do: is_binary(value) and byte_size(value) in 1..128 and String.valid?(value)

  defp valid_algorithm?(value, :cose),
    do: is_integer(value) and value in -2_147_483_648..2_147_483_647

  def check_credential(metadata, %{format: format, credential: credential}, key, opts)
      when format in @sd_formats do
    with {:ok, parameters} <- parameters(metadata, format),
         {:ok, issuer} <- issuer_jwt(credential),
         {:ok, issuer_alg} <- jose_algorithm(issuer),
         {:ok, jwk} <- Builder.normalize_key(key),
         {:ok, holder_alg} <- Builder.resolve_alg(jwk, opts),
         true <- permitted?(parameters, "sd-jwt_alg_values", issuer_alg),
         true <-
           permitted?(
             parameters,
             "kb-jwt_alg_values",
             fully_specified(holder_alg, Builder.public_jwk(jwk))
           ) do
      :ok
    else
      _ -> {:error, :incompatible_verifier_format}
    end
  end

  def check_credential(metadata, %{format: "mso_mdoc", credential: credential}, _key, _opts) do
    check_mdoc_credential(metadata, credential)
  end

  def check_credential(_metadata, _held, _key, _opts), do: {:error, :incompatible_verifier_format}

  def check_response(metadata, query, vp_token) do
    formats = Map.new(query["credentials"], &{&1["id"], &1["format"]})

    if Enum.all?(vp_token, fn {id, presentations} ->
         Enum.all?(presentations, &(check_presentation(metadata, formats[id], &1) == :ok))
       end), do: :ok, else: {:error, :incompatible_verifier_format}
  end

  defp check_presentation(metadata, format, presentation) when format in @sd_formats do
    case parameters(metadata, format) do
      {:ok, parameters} ->
        if Enum.any?(@jose_fields, &Map.has_key?(parameters, &1)),
          do: check_sd_presentation(parameters, presentation),
          else: :ok

      error ->
        error
    end
  end

  defp check_presentation(metadata, "mso_mdoc", presentation) do
    case parameters(metadata, "mso_mdoc") do
      {:ok, parameters} ->
        if Enum.any?(@cose_fields, &Map.has_key?(parameters, &1)),
          do: check_mdoc_presentation(parameters, presentation),
          else: :ok

      error ->
        error
    end
  end

  defp check_presentation(_metadata, _format, _presentation),
    do: {:error, :incompatible_verifier_format}

  defp check_sd_presentation(parameters, presentation) do
    with {:ok, issuer} <- issuer_jwt(presentation),
         {:ok, issuer_alg} <- jose_algorithm(issuer),
         {:ok, holder} <- holder_jwt(presentation),
         {:ok, claims} <- JWS.peek_json(issuer, :payload),
         {:ok, holder_alg} <- jose_algorithm(holder, holder_binding_key(claims)),
         true <- permitted?(parameters, "sd-jwt_alg_values", issuer_alg),
         true <- permitted?(parameters, "kb-jwt_alg_values", holder_alg) do
      :ok
    else
      _ -> {:error, :incompatible_verifier_format}
    end
  end

  defp holder_binding_key(%{"cnf" => %{"jwk" => key}}) when is_map(key), do: key
  defp holder_binding_key(_claims), do: nil

  defp parameters(metadata, format) do
    case get_in(metadata, ["vp_formats_supported", format]) do
      parameters when is_map(parameters) -> {:ok, parameters}
      _ -> {:error, :incompatible_verifier_format}
    end
  end

  defp permitted?(parameters, field, algorithm) do
    case Map.fetch(parameters, field) do
      :error -> true
      {:ok, accepted} -> algorithm in accepted
    end
  end

  defp issuer_jwt(value) when is_binary(value) and byte_size(value) <= 1_048_576 do
    case :binary.split(value, "~") do
      [jwt, _rest] when jwt != "" -> {:ok, jwt}
      _ -> {:error, :invalid_credential}
    end
  end

  defp issuer_jwt(_value), do: {:error, :invalid_credential}

  defp holder_jwt(value) do
    segments = String.split(value, "~", parts: 1003)
    holder = List.last(segments)

    if length(segments) in 2..1002 and holder != "",
      do: {:ok, holder},
      else: {:error, :invalid_credential}
  end

  defp jose_algorithm(jwt, key \\ nil) do
    with {:ok, %{"alg" => algorithm}} <- JWS.peek_json(jwt, :protected),
         true <- is_binary(algorithm),
         do: {:ok, fully_specified(algorithm, key)},
         else: (_ -> {:error, :invalid_credential})
  end

  defp fully_specified("EdDSA", %{"kty" => "OKP", "crv" => "Ed25519"}), do: "Ed25519"
  defp fully_specified("EdDSA", %{"kty" => "OKP", "crv" => "Ed448"}), do: "Ed448"
  defp fully_specified(algorithm, _key), do: algorithm

  if Code.ensure_loaded?(CBOR) do
    defp check_mdoc_credential(metadata, credential) do
      with {:ok, parameters} <- parameters(metadata, "mso_mdoc"),
           {:ok, issuer_signed} <- decode_cbor(credential),
           {:ok, alg} <- cose_algorithm(issuer_signed["issuerAuth"]),
           true <- cose_permitted?(parameters, "issuerauth_alg_values", alg),
           true <- cose_permitted?(parameters, "deviceauth_alg_values", -7) do
        :ok
      else
        _ -> {:error, :incompatible_verifier_format}
      end
    end

    defp check_mdoc_presentation(parameters, presentation) do
      with {:ok, %{"documents" => documents}} <- decode_cbor(presentation),
           true <- is_list(documents) and length(documents) in 1..64,
           true <- Enum.all?(documents, &permitted_document?(&1, parameters)) do
        :ok
      else
        _ -> {:error, :incompatible_verifier_format}
      end
    end

    defp permitted_document?(
           %{
             "issuerSigned" => %{"issuerAuth" => issuer},
             "deviceSigned" => %{"deviceAuth" => %{"deviceSignature" => holder}}
           },
           parameters
         ) do
      with {:ok, issuer_alg} <- cose_algorithm(issuer),
           {:ok, holder_alg} <- cose_algorithm(holder) do
        cose_permitted?(parameters, "issuerauth_alg_values", issuer_alg) and
          cose_permitted?(parameters, "deviceauth_alg_values", holder_alg)
      else
        _ -> false
      end
    end

    defp permitted_document?(_document, _parameters), do: false

    # This implementation emits ES256/P-256 COSE (-7). OID4VP also allows
    # the fully specified identifier ESP256 (-9) for that same operation.
    defp cose_permitted?(parameters, field, -7) do
      permitted?(parameters, field, -7) or permitted?(parameters, field, -9)
    end

    defp cose_permitted?(_parameters, _field, _unsupported), do: false

    defp decode_cbor(value) when is_binary(value) and byte_size(value) <= 1_048_576 do
      with {:ok, bytes} <- JWS.decode64(value),
           {:ok, map, ""} when is_map(map) <- CBOR.decode(bytes),
           do: {:ok, map},
           else: (_ -> {:error, :invalid_credential})
    rescue
      _ -> {:error, :invalid_credential}
    catch
      _, _ -> {:error, :invalid_credential}
    end

    defp decode_cbor(_value), do: {:error, :invalid_credential}

    defp cose_algorithm([
           %CBOR.Tag{tag: :bytes, value: protected},
           _unprotected,
           _payload,
           _signature
         ]) do
      case CBOR.decode(protected) do
        {:ok, %{1 => algorithm}, ""} when is_integer(algorithm) -> {:ok, algorithm}
        _ -> {:error, :invalid_credential}
      end
    rescue
      _ -> {:error, :invalid_credential}
    catch
      _, _ -> {:error, :invalid_credential}
    end

    defp cose_algorithm(_parts), do: {:error, :invalid_credential}
  else
    defp check_mdoc_credential(_metadata, _credential), do: {:error, :unsupported_mdoc}

    defp check_mdoc_presentation(_parameters, _presentation),
      do: {:error, :incompatible_verifier_format}
  end
end
