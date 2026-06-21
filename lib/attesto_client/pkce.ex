defmodule AttestoClient.PKCE do
  @moduledoc """
  Generate RFC 7636 PKCE verifier/challenge pairs for OAuth clients.

  This is the client-side mirror of `Attesto.PKCE.verify/3`: the client creates
  a fresh `code_verifier`, sends the corresponding S256 `code_challenge` in the
  authorization request, then presents the verifier at the token endpoint.

  Only S256 is produced. `plain` is deliberately not supported.
  """

  @doc """
  Generate a fresh RFC 7636 `code_verifier`.

  The verifier is 43 base64url characters from 32 bytes of CSPRNG output. That
  sits at the RFC 7636 lower bound and uses a subset of the allowed unreserved
  alphabet (`A-Z`, `a-z`, `0-9`, `-`, `_`).
  """
  @spec code_verifier() :: String.t()
  def code_verifier do
    32
    |> :crypto.strong_rand_bytes()
    |> Base.url_encode64(padding: false)
  end

  @doc """
  Compute the S256 `code_challenge` for `code_verifier`.

  Returns `{:ok, challenge}` for a well-formed verifier, or
  `{:error, :invalid_verifier}`. Delegates to `Attesto.PKCE.challenge/1`, the
  same primitive the server side verifies against.
  """
  @spec code_challenge(String.t()) :: {:ok, String.t()} | {:error, :invalid_verifier}
  def code_challenge(code_verifier), do: Attesto.PKCE.challenge(code_verifier)
end
