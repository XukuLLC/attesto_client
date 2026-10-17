defmodule AttestoClient.DPoP do
  @moduledoc """
  Build DPoP proof JWTs (RFC 9449 §4), the client-side mirror of
  `Attesto.DPoP.verify_proof/2`.

  A proof is a JWT, typed `dpop+jwt`, whose header carries the client's *public*
  key (as `jwk`) and whose payload binds the proof to a single HTTP request:

    * `htm` - the request method (`"POST"`, `"GET"`, ...), uppercased.
    * `htu` - the request URI with any query and fragment stripped (§4.2).
    * `iat` - issuance time.
    * `jti` - a unique identifier the server tracks against replay.
    * `ath` - `base64url(SHA-256(access_token))`, present only when the proof
      accompanies an access token (the resource-request leg, §4.2); it binds the
      proof to that token so a leaked proof cannot be paired with another.
    * `nonce` - a server-supplied DPoP nonce, echoed when the server has
      demanded one (a `use_dpop_nonce` error carrying a `DPoP-Nonce` header).

  Signing and key-bound `:alg`/`:kid` validation are provided by
  `Attesto.DPoP.Proof`, keeping proof construction and verification on the
  same implementation. The proof's public `jwk` is this key, and the server
  pins the token to its `jkt` thumbprint.
  """

  alias Attesto.DPoP.Proof

  @type jwk :: JOSE.JWK.t() | map()

  @type build_opt ::
          {:access_token, String.t()}
          | {:nonce, String.t()}
          | {:alg, String.t()}
          | {:kid, String.t()}
          | {:now, integer() | DateTime.t()}
          | {:jti, String.t()}

  @type error ::
          :invalid_key
          | :invalid_kid
          | :invalid_htm
          | :invalid_htu
          | :invalid_access_token
          | :invalid_nonce
          | :invalid_time
          | :invalid_jti
          | :unsupported_alg
          | :unsupported_key
          | {:signing_failed, String.t()}

  @doc """
  Build a signed DPoP proof for a request to `htu` with method `htm`, returning
  `{:ok, compact_jws}` or `{:error, reason}`. Fails fast on invalid input.

  `jwk` is the DPoP key (private half required for signing). `htm` is the HTTP
  method and `htu` the target URI; the URI's query and fragment are stripped to
  form the `htu` claim. Pass `:access_token` on a resource request so the proof
  carries the `ath` binding, and `:nonce` to echo a server-demanded DPoP nonce.
  `:alg`, `:kid`, and `:now` behave as in `AttestoClient.Wallet.Proof.build/2`.
  """
  @spec proof(jwk(), String.t(), String.t(), [build_opt()]) ::
          {:ok, String.t()} | {:error, error()}
  def proof(jwk, htm, htu, opts \\ []) when is_binary(htm) and is_binary(htu) and is_list(opts) do
    Proof.build(jwk, htm, htu, opts)
  end

  @doc false
  @spec resolve_alg(JOSE.JWK.t(), keyword()) ::
          {:ok, String.t()}
          | {:error, :unsupported_alg | :unsupported_key | {:signing_failed, String.t()}}
  def resolve_alg(%JOSE.JWK{} = jose_jwk, opts) when is_list(opts) do
    Proof.resolve_alg(jose_jwk, opts)
  end
end
