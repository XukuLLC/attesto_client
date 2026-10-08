defmodule AttestoClient.Wallet.Presentation.Encryption do
  @moduledoc false

  alias Attesto.JWS
  alias AttestoClient.CryptoJWE

  def context(%{profile: :haip, response_mode: mode}) when mode != "direct_post.jwt",
    do: {:error, :invalid_encryption_metadata}

  def context(%{response_mode: "direct_post", client_metadata: metadata}) when is_map(metadata) do
    with :ok <- advertised_keys(metadata), do: {:ok, nil}
  end

  def context(%{response_mode: "direct_post"}), do: {:error, :invalid_encryption_metadata}

  def context(%{response_mode: "direct_post.jwt", client_metadata: metadata} = request)
      when is_map(metadata) do
    with :ok <- profile_metadata(request),
         %{"keys" => keys} when is_list(keys) and length(keys) in 1..64 <-
           Map.get(metadata, "jwks"),
         :ok <- unique_kids(keys),
         %{} = key <- Enum.find(keys, &usable_key?/1),
         {:ok, enc} <- content_algorithm(metadata) do
      {:ok, %{key: key, enc: enc}}
    else
      _ -> {:error, :invalid_encryption_metadata}
    end
  end

  def context(%{response_mode: "direct_post.jwt"}), do: {:error, :invalid_encryption_metadata}
  def context(_request), do: {:error, :unsupported_response_mode}

  defp profile_metadata(%{profile: :haip, client_metadata: metadata}) do
    values = Map.get(metadata, "encrypted_response_enc_values_supported")

    if is_list(values) and length(values) <= 64 and Enum.all?(values, &is_binary/1) and
         "A128GCM" in values and "A256GCM" in values,
       do: :ok,
       else: {:error, :invalid_encryption_metadata}
  end

  defp profile_metadata(%{profile: profile}) when profile != :generic,
    do: {:error, :invalid_encryption_metadata}

  defp profile_metadata(_request), do: :ok

  def encrypt(%{key: key, enc: enc}, payload) when is_binary(payload) do
    header = %{"alg" => "ECDH-ES", "enc" => enc, "typ" => "JWT", "kid" => key["kid"]}
    CryptoJWE.encrypt(key, payload, header)
  end

  defp unique_kids(keys) do
    kids = for key <- keys, is_map(key), do: key["kid"]

    if length(kids) == length(keys) and
         Enum.all?(kids, &(is_binary(&1) and byte_size(&1) in 1..256)) and
         length(kids) == length(Enum.uniq(kids)),
       do: :ok,
       else: {:error, :invalid_encryption_metadata}
  end

  defp advertised_keys(metadata) do
    case Map.fetch(metadata, "jwks") do
      :error -> :ok
      {:ok, %{"keys" => keys}} when is_list(keys) and length(keys) in 1..64 -> unique_kids(keys)
      _ -> {:error, :invalid_encryption_metadata}
    end
  end

  defp content_algorithm(metadata) do
    case Map.get(metadata, "encrypted_response_enc_values_supported", ["A128GCM"]) do
      values when is_list(values) and values != [] ->
        case Enum.find(["A256GCM", "A128GCM"], &(&1 in values)) do
          nil -> {:error, :unsupported_encryption}
          enc -> {:ok, enc}
        end

      _ ->
        {:error, :invalid_encryption_metadata}
    end
  end

  defp usable_key?(
         %{"kty" => "EC", "crv" => "P-256", "alg" => "ECDH-ES", "x" => x, "y" => y} = key
       ) do
    not Map.has_key?(key, "d") and Map.get(key, "use") in [nil, "enc"] and
      valid_operations?(Map.get(key, "key_ops")) and valid_coordinate?(x) and valid_coordinate?(y) and
      valid_point?(key)
  end

  defp usable_key?(_key), do: false
  defp valid_operations?(nil), do: true

  defp valid_operations?(ops) when is_list(ops),
    do: ops != [] and Enum.all?(ops, &(&1 in ["deriveKey", "deriveBits"]))

  defp valid_operations?(_ops), do: false

  defp valid_coordinate?(encoded) when is_binary(encoded) and byte_size(encoded) == 43,
    do: match?({:ok, <<_::binary-size(32)>>}, JWS.decode64(encoded))

  defp valid_coordinate?(_encoded), do: false

  defp valid_point?(key) do
    jwk = JOSE.JWK.from_map(key)
    {_type, pem} = JOSE.JWK.to_pem(jwk)
    [{:SubjectPublicKeyInfo, der, :not_encrypted}] = :public_key.pem_decode(pem)

    {{:ECPoint, point}, {:namedCurve, _oid}} =
      :public_key.pem_entry_decode({:SubjectPublicKeyInfo, der, :not_encrypted})

    :crypto.compute_key(:ecdh, point, <<1::256>>, :secp256r1)
    true
  rescue
    _ -> false
  catch
    _, _ -> false
  end
end
