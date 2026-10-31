defmodule AttestoClient.StrictJSON do
  @moduledoc false

  # Duplicate member names and nesting deeper than 32 levels are rejected by
  # the shared Attesto decoder (Attesto >= 2.8.0).
  @spec decode_object(binary()) :: {:ok, map()} | {:error, :invalid_json}
  def decode_object(bytes), do: Attesto.StrictJSON.decode(bytes)
end
