defmodule AttestoClient.StrictJSON do
  @moduledoc false

  @spec decode_object(binary()) :: {:ok, map()} | {:error, :invalid_json}
  def decode_object(bytes) when is_binary(bytes) do
    decoders = [
      object_start: fn _previous -> %{} end,
      object_push: &push_member/3,
      object_finish: fn object, previous -> {object, previous} end
    ]

    case JSON.decode(bytes, nil, decoders) do
      {%{} = map, nil, ""} -> {:ok, map}
      _invalid -> {:error, :invalid_json}
    end
  rescue
    _error -> {:error, :invalid_json}
  catch
    :duplicate_member -> {:error, :invalid_json}
  end

  def decode_object(_bytes), do: {:error, :invalid_json}

  defp push_member(key, value, object) do
    if Map.has_key?(object, key), do: throw(:duplicate_member), else: Map.put(object, key, value)
  end
end
