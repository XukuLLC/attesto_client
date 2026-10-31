defmodule AttestoClient.Wallet.RecipientKey do
  @moduledoc false

  # Key rules shared by the two places a Wallet encrypts to a key the other
  # party published: OID4VCI credential request encryption and OID4VP
  # `direct_post.jwt` responses. Both encrypt ECDH-ES to a P-256 key through
  # `Attesto.JWE`, so a key is chosen only if `Attesto.JWE` will accept it and
  # the agreement can succeed: a public point on the curve, declared for
  # ECDH-ES, and not restricted to another use.

  alias Attesto.JWS

  @private_members ~w(d p q dp dq qi oth k)
  @max_kid_bytes 256

  @doc false
  @spec usable?(term()) :: boolean()
  def usable?(%{"kty" => "EC", "crv" => "P-256", "alg" => "ECDH-ES", "x" => x, "y" => y} = key) do
    not Enum.any?(@private_members, &Map.has_key?(key, &1)) and ecdh_usage?(key) and
      coordinate?(x) and
      coordinate?(y) and on_curve?(key)
  end

  def usable?(_key), do: false

  @doc false
  # `use` absent or `enc`, and `key_ops` absent or limited to key agreement.
  @spec ecdh_usage?(map()) :: boolean()
  def ecdh_usage?(key) when is_map(key),
    do: Map.get(key, "use") in [nil, "enc"] and key_ops?(Map.get(key, "key_ops"))

  @doc false
  @spec kid?(term()) :: boolean()
  def kid?(%{"kid" => kid}), do: is_binary(kid) and byte_size(kid) in 1..@max_kid_bytes
  def kid?(_key), do: false

  @doc false
  # Every key carries a distinct `kid`, so the key a message names is unambiguous.
  @spec distinct_kids?(list()) :: boolean()
  def distinct_kids?(keys) when is_list(keys),
    do: Enum.all?(keys, &kid?/1) and length(Enum.uniq_by(keys, & &1["kid"])) == length(keys)

  defp key_ops?(nil), do: true

  defp key_ops?(ops) when is_list(ops) and ops != [],
    do: Enum.all?(ops, &(&1 in ["deriveKey", "deriveBits"]))

  defp key_ops?(_ops), do: false

  defp coordinate?(encoded) when is_binary(encoded) and byte_size(encoded) == 43,
    do: match?({:ok, <<_::binary-size(32)>>}, JWS.decode64(encoded))

  defp coordinate?(_encoded), do: false

  defp on_curve?(key) do
    {_type, pem} = key |> JOSE.JWK.from_map() |> JOSE.JWK.to_pem()
    [{:SubjectPublicKeyInfo, der, :not_encrypted}] = :public_key.pem_decode(pem)

    {{:ECPoint, point}, {:namedCurve, _oid}} =
      :public_key.pem_entry_decode({:SubjectPublicKeyInfo, der, :not_encrypted})

    :crypto.compute_key(:ecdh, point, <<1::256>>, :secp256r1)
    true
  rescue
    _ -> false
  catch
    _, _ -> false
  end
end
