defmodule AttestoClient.Wallet.RecipientKey do
  @moduledoc false

  # Key rules shared by the two places a Wallet encrypts to a key the other
  # party published: OID4VCI credential request encryption and OID4VP
  # `direct_post.jwt` responses. Both encrypt ECDH-ES to a P-256 key through
  # `Attesto.JWE`, so a key is chosen only if `Attesto.JWE` will accept it and
  # the agreement can succeed: a public point on the curve, declared for
  # ECDH-ES, and not restricted to another use.

  alias Attesto.CredentialEncryption

  @max_kid_bytes 256

  @doc false
  @spec usable?(term()) :: boolean()
  def usable?(key), do: CredentialEncryption.valid_recipient_jwk?(key)

  @doc false
  # `use` absent or `enc`, and `key_ops` absent or limited to key agreement.
  @spec ecdh_usage?(map()) :: boolean()
  # A present JSON null `use` or `key_ops` is malformed, not omitted.
  def ecdh_usage?(key) when is_map(key), do: CredentialEncryption.ecdh_usage?(key)

  @doc false
  @spec kid?(term()) :: boolean()
  def kid?(%{"kid" => kid}), do: is_binary(kid) and byte_size(kid) in 1..@max_kid_bytes
  def kid?(_key), do: false

  @doc false
  # Every key carries a distinct `kid`, so the key a message names is unambiguous.
  @spec distinct_kids?(list()) :: boolean()
  def distinct_kids?(keys) when is_list(keys),
    do: Enum.all?(keys, &kid?/1) and length(Enum.uniq_by(keys, & &1["kid"])) == length(keys)
end
