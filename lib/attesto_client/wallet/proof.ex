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
          | {:key_attestation, String.t()}
          | {:alg, String.t()}
          | {:kid, String.t()}
          | {:now, integer()}

  @type error ::
          :invalid_key
          | :invalid_credential_issuer
          | :invalid_nonce
          | :invalid_client_id
          | :invalid_key_attestation
          | :invalid_kid
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
  as in `AttestoClient.RequestObject.build/2`. Pass `:key_attestation` (a
  compact JWT from `AttestoClient.KeyAttestation.build/2`) to carry it in the
  proof's `key_attestation` header, vouching that this key is securely stored.
  """
  @spec build(jwk(), [build_opt()]) :: {:ok, String.t()} | {:error, error()}
  def build(jwk, opts) when is_list(opts) do
    with {:ok, jose_jwk} <- Builder.normalize_key(jwk),
         {:ok, credential_issuer} <-
           Builder.require_string(opts, :credential_issuer, :invalid_credential_issuer),
         {:ok, nonce} <- optional_string(opts, :nonce, :invalid_nonce),
         {:ok, client_id} <- optional_string(opts, :client_id, :invalid_client_id),
         {:ok, key_attestation} <-
           optional_string(opts, :key_attestation, :invalid_key_attestation),
         {:ok, now} <- Builder.validate_now(opts),
         {:ok, kid} <- Builder.resolve_kid(jose_jwk, opts),
         {:ok, alg} <- Builder.resolve_alg(jose_jwk, opts) do
      claims =
        %{"aud" => credential_issuer, "iat" => now}
        |> put_optional("nonce", nonce)
        |> put_optional("iss", client_id)

      header =
        %{"alg" => alg, "typ" => @proof_typ, "jwk" => Builder.public_jwk(jose_jwk)}
        |> put_optional("key_attestation", key_attestation)
        |> Builder.put_kid(kid)

      Builder.sign(jose_jwk, header, claims)
    end
  end

  defp optional_string(opts, key, error) do
    case Keyword.fetch(opts, key) do
      :error -> {:ok, nil}
      {:ok, value} when is_binary(value) and value != "" -> {:ok, value}
      {:ok, _invalid} -> {:error, error}
    end
  end

  defp put_optional(map, _key, nil), do: map
  defp put_optional(map, key, value), do: Map.put(map, key, value)
end
