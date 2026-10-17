defmodule AttestoClient.Wallet.CredentialJSON do
  @moduledoc false

  @spec decode(binary()) :: {:ok, map()} | {:error, :invalid_credential_response}
  def decode(bytes) when is_binary(bytes) do
    case AttestoClient.StrictJSON.decode_object(bytes) do
      {:ok, map} -> {:ok, map}
      {:error, :invalid_json} -> {:error, :invalid_credential_response}
    end
  end

  def decode(_bytes), do: {:error, :invalid_credential_response}
end
