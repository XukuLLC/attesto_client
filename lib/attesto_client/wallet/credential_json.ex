defmodule AttestoClient.Wallet.CredentialJSON do
  @moduledoc false

  @spec decode(binary()) :: {:ok, map()} | {:error, :invalid_credential_response}
  def decode(bytes) when is_binary(bytes) do
    decoders = [
      object_start: fn _previous -> %{} end,
      object_push: &push_member/3,
      object_finish: fn object, previous -> {object, previous} end
    ]

    case JSON.decode(bytes, nil, decoders) do
      {%{} = map, nil, ""} -> {:ok, map}
      _invalid -> {:error, :invalid_credential_response}
    end
  rescue
    _error -> {:error, :invalid_credential_response}
  catch
    :duplicate_member -> {:error, :invalid_credential_response}
  end

  def decode(_bytes), do: {:error, :invalid_credential_response}

  defp push_member(key, value, object) do
    if Map.has_key?(object, key), do: throw(:duplicate_member), else: Map.put(object, key, value)
  end
end
