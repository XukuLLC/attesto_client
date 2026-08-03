defmodule AttestoClient.Wallet.Proof do
  @moduledoc """
  Build the OID4VCI holder key proof of possession
  (`draft-ietf-oauth-openid4vci` §8.2.1.1), the wallet-side mirror of
  `Attesto.CredentialProof.verify_jwt/2`.

  A proof is a JWT, typed `openid4vci-proof+jwt`, whose header carries the
  holder's *public* key (as `jwk`) and whose payload proves the wallet holds
  the matching private key at request time:

    * `aud` - the Credential Issuer Identifier (`:credential_issuer`).
    * `iat` - issuance time.
    * `nonce` - the `c_nonce` the issuer previously handed out, when it did.
    * `iss` - the `client_id`, required for the authorization_code flow.

  Signing and key-bound `:alg`/`:kid` validation behave as in
  `AttestoClient.RequestObject` / `AttestoClient.ClientAssertion` (shared
  `AttestoClient.Builder` internals).
  """

  alias AttestoClient.Builder

  # draft-ietf-oauth-openid4vci §8.2.1.1: explicit typing of a key proof, a
  # defence against cross-JWT confusion. Not overridable - unlike the request
  # object's FAPI typ, this exact value is what
  # `Attesto.CredentialProof.verify_jwt/2` requires.
  @proof_typ "openid4vci-proof+jwt"

  @type jwk :: JOSE.JWK.t() | map()

  @type build_opt ::
          {:credential_issuer, String.t()}
          | {:nonce, String.t()}
          | {:client_id, String.t()}
          | {:alg, String.t()}
          | {:kid, String.t()}
          | {:now, integer()}

  @type error ::
          :invalid_key
          | :invalid_credential_issuer
          | :invalid_time
          | :unsupported_alg
          | :unsupported_key
          | {:signing_failed, String.t()}

  @doc """
  Build a signed holder key proof, returning `{:ok, compact_jws}` or
  `{:error, reason}`. Fails fast on invalid input (see the error type).

  `jwk` is the holder's key (private half required for signing). Required
  option: `:credential_issuer` (the proof's `aud`). Pass `:nonce` with the
  issuer's `c_nonce` when it supplied one, and `:client_id` for the
  authorization_code flow (becomes `iss`); `:alg`, `:kid`, and `:now` behave
  as in `AttestoClient.RequestObject.build/2`.
  """
  @spec build(jwk(), [build_opt()]) :: {:ok, String.t()} | {:error, error()}
  def build(jwk, opts) when is_list(opts) do
    with {:ok, jose_jwk} <- Builder.normalize_key(jwk),
         {:ok, credential_issuer} <-
           Builder.require_string(opts, :credential_issuer, :invalid_credential_issuer),
         {:ok, now} <- validate_now(opts),
         {:ok, alg} <- Builder.resolve_alg(jose_jwk, opts) do
      claims =
        %{"aud" => credential_issuer, "iat" => now}
        |> put_optional("nonce", Keyword.get(opts, :nonce))
        |> put_optional("iss", Keyword.get(opts, :client_id))

      header =
        %{"alg" => alg, "typ" => @proof_typ, "jwk" => public_jwk(jose_jwk)}
        |> Builder.put_kid(jose_jwk, opts)

      Builder.sign(jose_jwk, header, claims)
    end
  end

  defp public_jwk(jose_jwk) do
    {_type, map} = JOSE.JWK.to_public_map(jose_jwk)
    map
  end

  defp put_optional(map, _key, nil), do: map
  defp put_optional(map, key, value), do: Map.put(map, key, value)

  # NumericDate is a non-negative seconds count (RFC 7519 §2); `iat` must not
  # be built from a negative `now`.
  defp validate_now(opts) do
    case Keyword.fetch(opts, :now) do
      :error -> {:ok, System.system_time(:second)}
      {:ok, n} when is_integer(n) and n >= 0 -> {:ok, n}
      {:ok, _invalid} -> {:error, :invalid_time}
    end
  end
end
