defmodule AttestoClient.HTTPPolicy do
  @moduledoc false

  @default_timeout_ms 10_000

  @spec timeout(keyword()) :: {:ok, pos_integer()} | {:error, :invalid_timeout}
  def timeout(opts) when is_list(opts) do
    case Keyword.get(opts, :timeout, @default_timeout_ms) do
      timeout when is_integer(timeout) and timeout > 0 -> {:ok, timeout}
      _invalid -> {:error, :invalid_timeout}
    end
  end
end
