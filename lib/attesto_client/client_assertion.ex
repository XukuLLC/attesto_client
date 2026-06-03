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

  # The asymmetric JWS algorithms an explicit `:alg` may name; `none` and any
  # unknown value are rejected. Inherited from attesto so client and server share
  # one allow-list.
  @allowed_algs SigningAlg.allowed()

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
          | {:signing_failed, String.t()}

  @spec build(jwk(), [build_opt()]) :: {:ok, String.t()} | {:error, error()}
  def build(jwk, opts) when is_list(opts) do
    jose_jwk = to_jose_jwk(jwk)

    with {:ok, client_id} <- require_string(opts, :client_id, :invalid_client_id),
         {:ok, audience} <- require_string(opts, :audience, :invalid_audience),
         {:ok, lifetime} <- validate_lifetime(opts),
         {:ok, jti} <- validate_jti(opts),
         {:ok, alg} <- resolve_alg(jose_jwk, opts) do
      now = now(opts)

      claims = %{
        "iss" => client_id,
        "sub" => client_id,
        "aud" => audience,
        "iat" => now,
        "exp" => now + lifetime,
        "jti" => jti
      }

      header = jose_header(alg, jose_jwk, opts)
      sign(jose_jwk, header, claims)
    end
  end

  # A security artifact builder fails fast: explicit bad input is rejected rather
  # than silently signed, so a host bug surfaces here, not as a server rejection.
  defp require_string(opts, key, error) do
    case Keyword.get(opts, key) do
      value when is_binary(value) and value != "" -> {:ok, value}
      _ -> {:error, error}
    end
  end

  defp validate_lifetime(opts) do
    case Keyword.fetch(opts, :lifetime) do
      :error -> {:ok, @default_lifetime_seconds}
      {:ok, n} when is_integer(n) and n > 0 -> {:ok, n}
      {:ok, _invalid} -> {:error, :invalid_lifetime}
    end
  end

  defp validate_jti(opts) do
    case Keyword.fetch(opts, :jti) do
      :error -> {:ok, 16 |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false)}
      {:ok, jti} when is_binary(jti) and jti != "" -> {:ok, jti}
      {:ok, _invalid} -> {:error, :invalid_jti}
    end
  end

  # An explicit `:alg` is honoured only if it is a supported asymmetric algorithm
  # (`none` and any unknown value are rejected); otherwise the key's natural
  # algorithm is inferred. A key/alg mismatch (e.g. RS256 with an EC key) is
  # caught at signing time as {:signing_failed, _}.
  defp resolve_alg(jose_jwk, opts) do
    case Keyword.get(opts, :alg) do
      nil -> {:ok, SigningAlg.infer(jose_jwk)}
      alg when alg in @allowed_algs -> {:ok, alg}
      _ -> {:error, :unsupported_alg}
    end
  end

  defp jose_header(alg, jose_jwk, opts) do
    case kid(jose_jwk, opts) do
      nil -> %{"alg" => alg}
      kid -> %{"alg" => alg, "kid" => kid}
    end
  end

  defp sign(jose_jwk, header, claims) do
    {_protected, compact} = jose_jwk |> JOSE.JWT.sign(header, claims) |> JOSE.JWS.compact()
    {:ok, compact}
  rescue
    error -> {:error, {:signing_failed, Exception.message(error)}}
  end

  defp to_jose_jwk(%JOSE.JWK{} = jwk), do: jwk
  defp to_jose_jwk(map) when is_map(map), do: JOSE.JWK.from_map(map)

  # An explicit `:kid` wins; otherwise carry the key's own `kid` so the server
  # can select the verification key, reading it from a JOSE.JWK struct as well as
  # a raw JWK map. Defaults to no kid.
  defp kid(jose_jwk, opts) do
    Keyword.get(opts, :kid) || jwk_kid(jose_jwk)
  end

  defp jwk_kid(%JOSE.JWK{} = jwk) do
    {_type, map} = JOSE.JWK.to_map(jwk)
    Map.get(map, "kid")
  end

  defp now(opts) do
    case Keyword.get(opts, :now) do
      n when is_integer(n) -> n
      _ -> System.system_time(:second)
    end
  end
end
