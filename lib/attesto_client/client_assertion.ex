defmodule AttestoClient.ClientAssertion do
  @moduledoc """
  Build `private_key_jwt` client-authentication assertions (RFC 7523 §2.2 /
  OpenID Connect Core §9), signed with the client's own private key.

  This is the client-side mirror of `Attesto.ClientAssertion.verify/5`: the
  authorization server verifies the assertion at its token / PAR / introspection
  endpoints; the client builds one to authenticate. The assertion is a JWT whose
  `iss` and `sub` are the `client_id` and whose `aud` is the authorization
  server (its issuer identifier or the concrete endpoint URL, per the server's
  policy - RFC 7523 §3 / FAPI 2.0 prefers the issuer).

  ## Claims (RFC 7523 §3)

    * `iss` = `sub` = the `client_id`.
    * `aud` = the authorization server identifier the assertion is presented to.
    * `jti` = a unique identifier (the server rejects replays).
    * `iat`, `exp` = issuance and a short expiry.

  Signing uses the client key directly (a `JOSE.JWK` or a JWK map); the algorithm
  defaults to the key's natural algorithm (`Attesto.SigningAlg.infer/1`: the FAPI
  algorithms PS256/ES256/EdDSA for the corresponding key types) and may be
  overridden with `:alg`.
  """

  alias AttestoClient.Builder

  # RFC 7523 §2.2 / OpenID Connect Core §9: the fixed assertion type a client
  # sends in `client_assertion_type`.
  @assertion_type "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

  # RFC 7523 §3: assertions are short-lived; the server bounds the lifetime.
  @default_lifetime_seconds 60

  @type jwk :: JOSE.JWK.t() | map()

  @type build_opt ::
          {:client_id, String.t()}
          | {:audience, String.t()}
          | {:alg, String.t()}
          | {:kid, String.t()}
          | {:lifetime, pos_integer()}
          | {:now, integer()}
          | {:jti, String.t()}

  @doc """
  The RFC 7523 §2.2 `client_assertion_type` value a client submits alongside the
  assertion.
  """
  @spec assertion_type() :: String.t()
  def assertion_type, do: @assertion_type

  @doc """
  Build a signed `private_key_jwt` assertion, returning `{:ok, compact_jws}` or
  `{:error, reason}`.

  Fails fast on invalid input rather than signing it: an empty `:client_id` or
  `:audience`, a non-positive `:lifetime`, an empty `:jti`, or an unsupported
  `:alg` (including `"none"`) return `{:error, reason}`. A key/algorithm mismatch
  surfaces as `{:error, {:signing_failed, message}}`.

  `jwk` is the client's private key (a `JOSE.JWK` or a JWK map).

  Required options:

    * `:client_id` - the client identifier (becomes `iss` and `sub`).
    * `:audience` - the authorization server the assertion is addressed to
      (`aud`).

  Optional:

    * `:alg` - the JWS algorithm; defaults to the key's natural algorithm.
    * `:kid` - the JOSE `kid` header; defaults to the key's own `kid` when the
      JWK carries one, otherwise omitted.
    * `:lifetime` - seconds until `exp`; defaults to `#{@default_lifetime_seconds}`.
    * `:now` - issuance time (Unix seconds), for deterministic tests.
    * `:jti` - the assertion identifier; defaults to a fresh random value.
  """
  @type error ::
          :invalid_client_id
          | :invalid_audience
          | :invalid_lifetime
          | :invalid_jti
          | :unsupported_alg
          | :unsupported_key
          | {:signing_failed, String.t()}

  @spec build(jwk(), [build_opt()]) :: {:ok, String.t()} | {:error, error()}
  def build(jwk, opts) when is_list(opts) do
    jose_jwk = Builder.to_jose_jwk(jwk)

    with {:ok, client_id} <- Builder.require_string(opts, :client_id, :invalid_client_id),
         {:ok, audience} <- Builder.require_string(opts, :audience, :invalid_audience),
         {:ok, lifetime} <- Builder.validate_lifetime(opts, @default_lifetime_seconds),
         {:ok, jti} <- Builder.validate_jti(opts),
         {:ok, alg} <- Builder.resolve_alg(jose_jwk, opts) do
      now = Builder.now(opts)

      claims = %{
        "iss" => client_id,
        "sub" => client_id,
        "aud" => audience,
        "iat" => now,
        "exp" => now + lifetime,
        "jti" => jti
      }

      header = Builder.put_kid(%{"alg" => alg}, jose_jwk, opts)
      Builder.sign(jose_jwk, header, claims)
    end
  end
end
