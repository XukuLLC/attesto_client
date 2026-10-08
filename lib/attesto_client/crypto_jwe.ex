defmodule AttestoClient.CryptoJWE do
  @moduledoc false

  # The dependency floor supplies the bounded JWE implementation in Attesto 2.3.
  # Retain a controlled diagnostic for manually assembled runtimes that omit it.
  @spec encrypt(term(), binary(), map(), keyword()) :: {:ok, binary()} | {:error, atom()}
  def encrypt(key, plaintext, header, opts \\ []) do
    invoke(:encrypt, [key, plaintext, header, opts])
  end

  @spec decrypt(term(), binary(), keyword()) :: {:ok, binary(), map()} | {:error, atom()}
  def decrypt(key, compact, opts \\ []) do
    invoke(:decrypt, [key, compact, opts])
  end

  defp invoke(operation, arguments) do
    if Code.ensure_loaded?(Attesto.JWE) and
         function_exported?(Attesto.JWE, operation, length(arguments)),
       do: apply(Attesto.JWE, operation, arguments),
       else: {:error, :unsupported_core_version}
  rescue
    _error -> {:error, :invalid_jwe}
  catch
    _kind, _reason -> {:error, :invalid_jwe}
  end
end
