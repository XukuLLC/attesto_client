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

  alias Attesto.SigningAlg

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
  Build a signed `private_key_jwt` assertion, returning `{:ok, compact_jws}`.

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
  @spec build(jwk(), [build_opt()]) :: {:ok, String.t()}
  def build(jwk, opts) when is_list(opts) do
    jose_jwk = to_jose_jwk(jwk)
    client_id = Keyword.fetch!(opts, :client_id)
    audience = Keyword.fetch!(opts, :audience)
    now = now(opts)

    claims = %{
      "iss" => client_id,
      "sub" => client_id,
      "aud" => audience,
      "iat" => now,
      "exp" => now + lifetime(opts),
      "jti" => jti(opts)
    }

    header = jose_header(jose_jwk, jwk, opts)
    {_protected, compact} = jose_jwk |> JOSE.JWT.sign(header, claims) |> JOSE.JWS.compact()
    {:ok, compact}
  end

  defp jose_header(jose_jwk, original, opts) do
    alg = Keyword.get(opts, :alg) || SigningAlg.infer(jose_jwk)

    case kid(original, opts) do
      nil -> %{"alg" => alg}
      kid -> %{"alg" => alg, "kid" => kid}
    end
  end

  defp to_jose_jwk(%JOSE.JWK{} = jwk), do: jwk
  defp to_jose_jwk(map) when is_map(map), do: JOSE.JWK.from_map(map)

  # An explicit `:kid` wins; otherwise carry the JWK map's own `kid` (when the
  # client supplied one) so the server can select the key, defaulting to no kid.
  defp kid(original, opts) do
    Keyword.get(opts, :kid) || map_kid(original)
  end

  defp map_kid(map) when is_map(map) and not is_struct(map), do: Map.get(map, "kid")
  defp map_kid(_original), do: nil

  defp lifetime(opts) do
    case Keyword.get(opts, :lifetime) do
      n when is_integer(n) and n > 0 -> n
      _ -> @default_lifetime_seconds
    end
  end

  defp jti(opts) do
    case Keyword.get(opts, :jti) do
      jti when is_binary(jti) and jti != "" -> jti
      _ -> 16 |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false)
    end
  end

  defp now(opts) do
    case Keyword.get(opts, :now) do
      n when is_integer(n) -> n
      _ -> System.system_time(:second)
    end
  end
end
