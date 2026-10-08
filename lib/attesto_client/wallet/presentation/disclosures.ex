defmodule AttestoClient.Wallet.Presentation.Disclosures do
  @moduledoc false
  alias Attesto.JWS

  @max_bytes 1_048_576

  def filter(credential, paths)
      when is_binary(credential) and byte_size(credential) <= @max_bytes do
    case String.split(credential, "~") do
      [issuer | rest] when issuer != "" and rest != [] -> filter_parts(issuer, rest, paths)
      _ -> {:error, :invalid_credential}
    end
  end

  def filter(_credential, _paths), do: {:error, :invalid_credential}

  defp filter_parts(issuer, rest, paths) do
    with true <- List.last(rest) == "" and length(rest) <= 1001,
         {:ok, claims} <- JWS.peek_json(issuer, :payload),
         {:ok, alg} <- hash_algorithm(claims),
         {:ok, disclosures} <- decode_disclosures(Enum.drop(rest, -1), alg) do
      locations = locate(claims, [], disclosures, %{}, 0)
      kept = Enum.filter(Enum.drop(rest, -1), &keep?(&1, locations, paths))
      {:ok, Enum.join([issuer | kept] ++ [""], "~"), alg}
    else
      _ -> {:error, :invalid_credential}
    end
  end

  defp hash_algorithm(claims) do
    case Map.get(claims, "_sd_alg", "sha-256") do
      "sha-256" -> {:ok, :sha256}
      "sha-384" -> {:ok, :sha384}
      "sha-512" -> {:ok, :sha512}
      _ -> {:error, :unsupported_sd_alg}
    end
  end

  defp decode_disclosures(encoded, alg) do
    Enum.reduce_while(encoded, {:ok, %{}}, fn disclosure, {:ok, acc} ->
      with true <- byte_size(disclosure) <= 262_144,
           {:ok, bytes} <- JWS.decode64(disclosure),
           {:ok, value} when is_list(value) and length(value) in [2, 3] <- JSON.decode(bytes) do
        digest = :crypto.hash(alg, disclosure) |> Base.url_encode64(padding: false)
        {:cont, {:ok, Map.put(acc, digest, {disclosure, value})}}
      else
        _ -> {:halt, {:error, :invalid_credential}}
      end
    end)
  end

  defp locate(_value, _path, _disclosures, locations, depth) when depth > 64, do: locations

  defp locate(map, path, disclosures, locations, depth) when is_map(map) do
    locations =
      Enum.reduce(Map.get(map, "_sd", []), locations, fn digest, acc ->
        case Map.get(disclosures, digest) do
          {encoded, [_salt, name, value]} when is_binary(name) ->
            next = path ++ [name]
            locate(value, next, disclosures, Map.put(acc, encoded, next), depth + 1)

          _ ->
            acc
        end
      end)

    Enum.reduce(Map.drop(map, ["_sd", "_sd_alg"]), locations, fn {key, value}, acc ->
      locate(value, path ++ [key], disclosures, acc, depth + 1)
    end)
  end

  defp locate(list, path, disclosures, locations, depth) when is_list(list) do
    list
    |> Enum.with_index()
    |> Enum.reduce(locations, fn {value, index}, acc ->
      next = path ++ [index]
      locate_array_item(value, next, disclosures, acc, depth)
    end)
  end

  defp locate(_value, _path, _disclosures, locations, _depth), do: locations

  defp locate_array_item(%{"..." => digest}, path, disclosures, locations, depth) do
    case Map.get(disclosures, digest) do
      {encoded, [_salt, disclosed]} ->
        locate(disclosed, path, disclosures, Map.put(locations, encoded, path), depth + 1)

      _ ->
        locations
    end
  end

  defp locate_array_item(value, path, disclosures, locations, depth),
    do: locate(value, path, disclosures, locations, depth + 1)

  defp keep?(encoded, locations, :all), do: Map.has_key?(locations, encoded)

  defp keep?(encoded, locations, paths) do
    case Map.fetch(locations, encoded) do
      {:ok, path} -> Enum.any?(paths, &(prefix?(&1, path) or prefix?(path, &1)))
      :error -> false
    end
  end

  defp prefix?([], _path), do: true
  defp prefix?([nil | rest], [_index | path]), do: prefix?(rest, path)
  defp prefix?([key | rest], [key | path]), do: prefix?(rest, path)
  defp prefix?(_prefix, _path), do: false
end
