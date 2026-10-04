defmodule AttestoClient.ClientAssertion do
  @moduledoc """
  Build `private_key_jwt` client-authentication assertions (RFC 7523 §2.2 /
  OpenID Connect Core §9), signed with the client's own private key.

  This is the client-side mirror of `Attesto.ClientAssertion.verify/5`: the
  authorization server verifies the assertion at its token / PAR / introspection
  endpoints; the client builds one to authenticate. The assertion is a JWT whose
  `iss` and `sub` are the `client_id` and whose `aud` is the authorization
  server issuer identifier, as required by `draft-ietf-oauth-rfc7523bis-11`.
  Assertions carry the `client-authentication+jwt` type header. Endpoint URLs
  are not valid audiences under the revised profile.

  ## Claims (RFC 7523 §3)

    * `iss` = `sub` = the `client_id`.
    * `aud` = the authorization server identifier the assertion is presented to.
    * `jti` = a unique identifier (the server rejects replays).
    * `iat`, `exp` = issuance and a short expiry.

  Signing uses the client key directly (a `JOSE.JWK` or a JWK map); the algorithm
  defaults to the key's natural algorithm (`Attesto.SigningAlg.infer/1`:
  RS256 for RSA, the curve-matched ES algorithm for EC, or legacy `EdDSA` for
  Edwards keys) and may be overridden with `:alg`. A FAPI client using RSA must
  therefore select `alg: "PS256"` explicitly; FAPI does not permit the inferred
  RS256 default. An explicit algorithm is validated against the key before
  signing; in particular, `Ed25519` and `Ed448` require their matching OKP
  curves.
  """

  alias AttestoClient.Builder

  # RFC 7523 §2.2 / OpenID Connect Core §9: the fixed assertion type a client
  # sends in `client_assertion_type`.
  @assertion_type "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

  # RFC 7523 §3: assertions are short-lived; the server bounds the lifetime.
  @default_lifetime_seconds 60
  @signing_failure_message "signing operation failed"

  @type jwk :: JOSE.JWK.t() | map()

  @type build_opt ::
          {:client_id, String.t()}
          | {:audience, String.t()}
          | {:alg, String.t()}
          | {:kid, String.t()}
          | {:typ, String.t() | nil}
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
  `:alg` (including `"none"`) returns `{:error, :unsupported_alg}`. A supported
  algorithm that is incompatible with the key returns the existing
  `{:error, {:signing_failed, message}}` tuple before signing.

  `jwk` is the client's private key (a `JOSE.JWK` or a JWK map).

  Required options:

    * `:client_id` - the client identifier (becomes `iss` and `sub`).
    * `:audience` - the authorization server's issuer identifier (`aud`).

  Optional:

    * `:alg` - the JWS algorithm; defaults to the key's natural algorithm. Set
      `"PS256"` explicitly for an RSA client under FAPI.
    * `:kid` - the JOSE `kid` header; defaults to the key's own `kid` when the
      JWK carries one, otherwise omitted.
    * `:typ` - the JOSE type header; defaults to `client-authentication+jwt`.
      Set `nil` to omit it or a non-empty string for a registered legacy type.
    * `:lifetime` - seconds until `exp`; defaults to `#{@default_lifetime_seconds}`.
    * `:now` - issuance time (Unix seconds), for deterministic tests.
    * `:jti` - the assertion identifier; defaults to a fresh random value.
  """
  @type error ::
          :invalid_key
          | :invalid_client_id
          | :invalid_audience
          | :invalid_lifetime
          | :invalid_jti
          | :invalid_typ
          | :unsupported_alg
          | :unsupported_key
          | {:signing_failed, String.t()}

  @spec build(jwk(), [build_opt()]) :: {:ok, String.t()} | {:error, error()}
  def build(jwk, opts) when is_list(opts) do
    with {:ok, jose_jwk} <- Builder.normalize_key(jwk),
         {:ok, client_id} <- Builder.require_string(opts, :client_id, :invalid_client_id),
         {:ok, audience} <- Builder.require_string(opts, :audience, :invalid_audience),
         {:ok, typ} <- assertion_typ(opts),
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

      header = %{"alg" => alg}
      header = if is_nil(typ), do: header, else: Map.put(header, "typ", typ)
      header = Builder.put_kid(header, jose_jwk, opts)
      sign_assertion(jose_jwk, header, claims)
    end
  end

  defp assertion_typ(opts) do
    case Keyword.get(opts, :typ, "client-authentication+jwt") do
      nil -> {:ok, nil}
      value when is_binary(value) and value != "" -> {:ok, value}
      _invalid -> {:error, :invalid_typ}
    end
  end

  # JOSE.JWT.sign/3 supplies typ=JWT when absent. The lower-level signer lets
  # callers explicitly omit typ for peers that still require a legacy header.
  defp sign_assertion(jose_jwk, header, claims) do
    {_jws, compact} =
      jose_jwk
      |> JOSE.JWS.sign(JSON.encode!(claims), header)
      |> JOSE.JWS.compact()

    {:ok, compact}
  rescue
    _error -> {:error, {:signing_failed, @signing_failure_message}}
  end
end
