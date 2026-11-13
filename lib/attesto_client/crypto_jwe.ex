defmodule AttestoClient.CryptoJWE do
  @moduledoc false

  @deprecated "Use Attesto.JWE.encrypt/4"
  @spec encrypt(term(), binary(), map(), keyword()) :: {:ok, binary()} | {:error, atom()}
  def encrypt(key, plaintext, header, opts \\ []) do
    invoke(:encrypt, [key, plaintext, header, opts])
  end

  @deprecated "Use Attesto.JWE.decrypt/3"
  @spec decrypt(term(), binary(), keyword()) :: {:ok, binary(), map()} | {:error, atom()}
  def decrypt(key, compact, opts \\ []) do
    invoke(:decrypt, [key, compact, opts])
  end

  defp invoke(operation, arguments) do
    apply(Attesto.JWE, operation, arguments)
  rescue
    _error -> {:error, :invalid_jwe}
  catch
    _kind, _reason -> {:error, :invalid_jwe}
  end
end
