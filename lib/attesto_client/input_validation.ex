defmodule AttestoClient.InputValidation do
  @moduledoc false

  @spec required_string(keyword() | map(), atom() | String.t(), term(), keyword()) ::
          {:ok, String.t()} | {:error, term()}
  def required_string(container, key, error, opts \\ []) do
    value = fetch(container, key)
    max_bytes = Keyword.get(opts, :max_bytes, :infinity)

    if is_binary(value) and value != "" and within_limit?(value, max_bytes),
      do: {:ok, value},
      else: {:error, error}
  end

  defp fetch(container, key) when is_list(container) do
    if Keyword.keyword?(container), do: Keyword.get(container, key), else: nil
  end

  defp fetch(container, key) when is_map(container) and is_atom(key),
    do: Attesto.MapParams.fetch(container, key)

  defp fetch(container, key) when is_map(container), do: Map.get(container, key)
  defp fetch(_container, _key), do: nil

  defp within_limit?(_value, :infinity), do: true

  defp within_limit?(value, max_bytes) when is_integer(max_bytes) and max_bytes > 0,
    do: byte_size(value) <= max_bytes

  defp within_limit?(_value, _max_bytes), do: false
end
