defmodule AttestoClient.Wallet.Presentation.DCQL do
  @moduledoc false

  @formats ~w(dc+sd-jwt vc+sd-jwt mso_mdoc)

  def validate(%{"credentials" => queries} = query) when is_list(queries) and queries != [] do
    ids = Enum.map(queries, &query_id/1)

    if length(queries) <= 64 and Enum.all?(queries, &valid_query?/1) and
         length(ids) == length(Enum.uniq(ids)) and valid_sets?(query, ids) do
      :ok
    else
      {:error, :invalid_dcql_query}
    end
  end

  def validate(_query), do: {:error, :invalid_dcql_query}

  def select(query, held) when is_list(held) do
    with :ok <- validate(query) do
      matches =
        Map.new(query["credentials"], fn q -> {q["id"], Enum.find(held, &matches?(&1, q))} end)

      choose_sets(query, matches)
    end
  end

  def select(_query, _held), do: {:error, :invalid_dcql_query}

  def validate_selection(query, selection) when is_map(selection) do
    with :ok <- validate(query),
         true <- map_size(selection) > 0,
         true <- Enum.all?(selection, &selected_match?(&1, query)),
         {:ok, _} <- choose_sets(query, selection) do
      :ok
    else
      {:error, _} = error -> error
      _ -> {:error, :invalid_selection}
    end
  end

  def validate_selection(_query, _selection), do: {:error, :invalid_selection}

  defp selected_match?({id, held}, query) do
    case Enum.find(query["credentials"], &(&1["id"] == id)) do
      nil -> false
      credential_query -> matches?(held, credential_query)
    end
  end

  def validate_response_ids(query, ids) do
    with :ok <- validate(query),
         {:ok, _selected} <- choose_sets(query, Map.new(ids, &{&1, true})),
         do: :ok
  end

  def paths(query, held) do
    case Map.get(query, "claims") do
      nil ->
        []

      claims ->
        claims
        |> selected_claims(Map.get(query, "claim_sets"), held)
        |> Enum.map(& &1["path"])
    end
  end

  def matches?(%{format: format, claims: claims} = held, %{"format" => format} = query)
      when format in @formats and is_map(claims) do
    meta_matches?(held, query) and authority_matches?(held, query) and
      claims_match?(held, query)
  end

  def matches?(_held, _query), do: false

  def values_at(value, path) do
    case resolve_values(value, path) do
      {:ok, values} -> values
      :error -> []
    end
  end

  defp resolve_values(value, []), do: {:ok, [value]}

  defp resolve_values(map, [key | rest]) when is_map(map) and is_binary(key) do
    case Map.fetch(map, key) do
      {:ok, value} -> resolve_values(value, rest)
      :error -> {:ok, []}
    end
  end

  defp resolve_values(list, [nil | rest]) when is_list(list) do
    list
    |> Enum.reduce_while({:ok, []}, fn value, {:ok, acc} ->
      case resolve_values(value, rest) do
        {:ok, values} -> {:cont, {:ok, [values | acc]}}
        :error -> {:halt, :error}
      end
    end)
    |> flatten_values()
  end

  defp resolve_values(list, [index | rest])
       when is_list(list) and is_integer(index) and index >= 0 do
    case Enum.fetch(list, index) do
      {:ok, value} -> resolve_values(value, rest)
      :error -> {:ok, []}
    end
  end

  defp resolve_values(_value, _path), do: :error

  defp flatten_values({:ok, chunks}), do: {:ok, chunks |> Enum.reverse() |> Enum.flat_map(& &1)}
  defp flatten_values(:error), do: :error

  defp query_id(%{"id" => id}), do: id
  defp query_id(_query), do: nil

  defp valid_query?(%{"id" => id, "format" => format} = query) do
    valid_id?(id) and is_binary(format) and format != "" and
      valid_optional_map?(query, "meta") and valid_boolean?(query, "multiple") and
      valid_boolean?(query, "require_cryptographic_holder_binding") and
      valid_claims?(query) and valid_authorities?(Map.get(query, "trusted_authorities"))
  end

  defp valid_query?(_query), do: false

  defp valid_id?(id) when is_binary(id),
    do: byte_size(id) in 1..128 and Regex.match?(~r/\A[A-Za-z0-9_-]+\z/, id)

  defp valid_id?(_id), do: false
  defp valid_optional_map?(map, key), do: not Map.has_key?(map, key) or is_map(map[key])
  defp valid_boolean?(map, key), do: not Map.has_key?(map, key) or is_boolean(map[key])

  defp valid_claims?(%{"claims" => claims} = query) when is_list(claims) and claims != [] do
    ids = Enum.map(claims, &query_id/1) |> Enum.reject(&is_nil/1)

    length(claims) <= 128 and Enum.all?(claims, &valid_claim?(&1, query["format"])) and
      length(ids) == length(Enum.uniq(ids)) and valid_claim_sets?(query, ids, length(claims))
  end

  defp valid_claims?(query),
    do: not Map.has_key?(query, "claims") and not Map.has_key?(query, "claim_sets")

  defp valid_claim?(%{"path" => path} = claim, format) when is_list(path) and path != [] do
    length(path) <= 32 and valid_path?(path, format) and
      (not Map.has_key?(claim, "id") or valid_id?(claim["id"])) and valid_values?(claim)
  end

  defp valid_claim?(_claim, _format), do: false

  defp valid_path?([namespace, element], "mso_mdoc")
       when is_binary(namespace) and namespace != "" and is_binary(element) and element != "",
       do: true

  defp valid_path?(_path, "mso_mdoc"), do: false
  defp valid_path?(path, _format), do: Enum.all?(path, &path_segment?/1)

  defp path_segment?(value),
    do: (is_binary(value) and value != "") or is_nil(value) or (is_integer(value) and value >= 0)

  defp valid_values?(%{"values" => values}) when is_list(values) and values != [],
    do: Enum.all?(values, &(is_binary(&1) or is_integer(&1) or is_boolean(&1)))

  defp valid_values?(claim), do: not Map.has_key?(claim, "values")

  defp valid_claim_sets?(%{"claim_sets" => sets}, ids, count),
    do: length(ids) == count and valid_options?(sets, ids)

  defp valid_claim_sets?(_query, _ids, _count), do: true

  defp valid_sets?(%{"credential_sets" => sets}, ids) when is_list(sets) and sets != [],
    do: length(sets) <= 64 and Enum.all?(sets, &valid_set?(&1, ids))

  defp valid_sets?(query, _ids), do: not Map.has_key?(query, "credential_sets")

  defp valid_set?(%{"options" => options} = set, ids),
    do: valid_boolean?(set, "required") and valid_options?(options, ids)

  defp valid_set?(_set, _ids), do: false

  defp valid_options?(options, ids) when is_list(options) and options != [] do
    length(options) <= 64 and
      Enum.all?(options, fn option ->
        is_list(option) and option != [] and length(option) == length(Enum.uniq(option)) and
          Enum.all?(option, &(&1 in ids))
      end)
  end

  defp valid_options?(_options, _ids), do: false

  defp valid_authorities?(nil), do: true

  defp valid_authorities?(authorities) when is_list(authorities) and authorities != [] do
    Enum.all?(authorities, fn
      %{"type" => type, "values" => values} ->
        is_binary(type) and is_list(values) and values != [] and Enum.all?(values, &is_binary/1)

      _ ->
        false
    end)
  end

  defp valid_authorities?(_authorities), do: false

  defp choose_sets(%{"credential_sets" => sets}, matches) do
    Enum.reduce_while(sets, {:ok, %{}}, fn set, {:ok, selected} ->
      choose_set(set, matches, selected)
    end)
  end

  defp choose_sets(query, matches) do
    case Enum.find(query["credentials"], &is_nil(matches[&1["id"]])) do
      nil -> {:ok, matches}
      missing -> {:error, {:no_match, missing["id"]}}
    end
  end

  defp choose_set(set, matches, selected) do
    case Enum.find(set["options"], &option_available?(&1, matches)) do
      nil ->
        if Map.get(set, "required", true),
          do: {:halt, {:error, :access_denied}},
          else: {:cont, {:ok, selected}}

      ids ->
        {:cont, {:ok, Map.merge(selected, Map.take(matches, ids))}}
    end
  end

  defp option_available?(ids, matches), do: Enum.all?(ids, &(not is_nil(matches[&1])))

  defp meta_matches?(%{format: "mso_mdoc"} = held, query),
    do: get_in(query, ["meta", "doctype_value"]) in [nil, Map.get(held, :doc_type)]

  defp meta_matches?(held, query) do
    case get_in(query, ["meta", "vct_values"]) do
      nil -> true
      values when is_list(values) and values != [] -> held.claims["vct"] in values
      _ -> false
    end
  end

  defp authority_matches?(held, query) do
    case Map.get(query, "trusted_authorities") do
      nil -> true
      authorities -> Enum.any?(authorities, &authority_match?(&1, held))
    end
  end

  defp authority_match?(%{"type" => "aki", "values" => values}, held),
    do: Enum.any?(values, &(&1 in Map.get(held, :authority_key_identifiers, [])))

  defp authority_match?(_authority, _held), do: false

  defp claims_match?(held, query) do
    case Map.get(query, "claims") do
      nil -> true
      claims -> selected_claims(claims, Map.get(query, "claim_sets"), held) != :no_match
    end
  end

  defp selected_claims(claims, nil, held),
    do: if(Enum.all?(claims, &claim_matches?(held, &1)), do: claims, else: :no_match)

  defp selected_claims(claims, sets, held) do
    by_id = Map.new(claims, &{&1["id"], &1})

    case Enum.find(sets, &Enum.all?(&1, fn id -> claim_matches?(held, by_id[id]) end)) do
      nil -> :no_match
      ids -> Enum.map(ids, &by_id[&1])
    end
  end

  defp claim_matches?(held, claim) do
    values = values_at(held.claims, claim["path"])

    values != [] and
      (not Map.has_key?(claim, "values") or Enum.any?(values, &(&1 in claim["values"])))
  end
end
