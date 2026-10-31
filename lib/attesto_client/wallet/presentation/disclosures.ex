defmodule AttestoClient.Wallet.Presentation.Disclosures do
  @moduledoc false
  alias Attesto.{JWS, SdJwt}

  @max_bytes 1_048_576
  @max_disclosure_bytes 262_144
  @hash_algorithms %{"sha-256" => :sha256, "sha-384" => :sha384, "sha-512" => :sha512}

  def filter(credential, paths)
      when is_binary(credential) and byte_size(credential) <= @max_bytes do
    case String.split(credential, "~") do
      [issuer | rest] when issuer != "" and rest != [] -> filter_parts(issuer, rest, paths)
      _ -> {:error, :invalid_credential}
    end
  end

  def filter(_credential, _paths), do: {:error, :invalid_credential}

  # Disclosures are decoded and validated by `Attesto.SdJwt.decode_disclosures/2`,
  # the same rules the Verifier applies, so the Holder never presents a
  # Disclosure the Verifier would reject. Each is kept with its encoded form so
  # the presentation carries the issuer's exact bytes.
  defp filter_parts(issuer, rest, paths) do
    encoded = Enum.drop(rest, -1)

    with true <- List.last(rest) == "" and length(rest) <= 1001,
         true <- Enum.all?(encoded, &(byte_size(&1) <= @max_disclosure_bytes)),
         {:ok, claims} <- JWS.peek_json(issuer, :payload),
         {:ok, sd_alg, hash_alg} <- hash_algorithm(claims),
         {:ok, by_digest} <- SdJwt.decode_disclosures(encoded, sd_alg) do
      disclosures =
        Map.new(encoded, fn disclosure ->
          digest = SdJwt.digest(disclosure, sd_alg)
          {digest, {disclosure, Map.fetch!(by_digest, digest)}}
        end)

      locations = locate(claims, [], disclosures, %{}, 0)
      kept = Enum.filter(encoded, &keep?(&1, locations, paths))
      {:ok, Enum.join([issuer | kept] ++ [""], "~"), hash_alg}
    else
      _ -> {:error, :invalid_credential}
    end
  end

  defp hash_algorithm(claims) do
    sd_alg = Map.get(claims, "_sd_alg", "sha-256")

    case Map.fetch(@hash_algorithms, sd_alg) do
      {:ok, hash_alg} -> {:ok, sd_alg, hash_alg}
      :error -> {:error, :unsupported_sd_alg}
    end
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
