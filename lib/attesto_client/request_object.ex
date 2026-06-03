defmodule AttestoClient.RequestObject do
  @moduledoc """
  Build signed authorization request objects (JAR, RFC 9101), the client-side
  mirror of `Attesto.RequestObject.verify/3`.

  A request object is a JWT that carries the authorization request parameters as
  claims, signed with the client's own key, so the authorization server can
  authenticate and integrity-check the request (RFC 9101; FAPI 2.0 Message
  Signing §5.3.1 requires it). This builds one; the authorization server (via
  attesto) verifies it at the PAR or authorization endpoint.

  ## Claims

  The caller's authorization parameters (`:params` - `response_type`,
  `redirect_uri`, `scope`, `state`, `nonce`, `code_challenge`, …) become
  top-level claims. The builder adds the request-object envelope, which always
  wins over `:params`:

    * `iss` = the `client_id` (RFC 9101 §2.1).
    * `aud` = the authorization server (`:audience`, its issuer identifier).
    * `iat`, `nbf`, `exp` = issuance / not-before / expiry; FAPI 2.0 Message
      Signing §5.3.1 requires `nbf` and `exp`.
    * `jti` = a unique identifier.

  The JOSE header `typ` defaults to `"oauth-authz-req+jwt"` (RFC 9101 §10.8 /
  FAPI 2.0 Message Signing §5.3.1 explicit typing); it is accepted by attesto's
  generic policy too, so it is safe for non-FAPI servers and may be overridden
  with `:typ`. Signing and `:alg`/`:kid`/validation behave as in
  `AttestoClient.ClientAssertion`.
  """

  alias AttestoClient.Builder

  # RFC 9101 §10.8 / FAPI 2.0 Message Signing §5.3.1: explicit typing of a
  # request object, a defence against cross-JWT confusion.
  @fapi_typ "oauth-authz-req+jwt"

  # FAPI 2.0 Message Signing §5.3.1 bounds the lifetime to 60 minutes; default to
  # a short window well inside it and never build one outside the bound.
  @default_lifetime_seconds 300
  @max_lifetime_seconds 3600

  @type jwk :: JOSE.JWK.t() | map()

  @type build_opt ::
          {:client_id, String.t()}
          | {:audience, String.t()}
          | {:params, %{optional(String.t()) => term()}}
          | {:typ, String.t()}
          | {:alg, String.t()}
          | {:kid, String.t()}
          | {:lifetime, pos_integer()}
          | {:now, integer()}
          | {:jti, String.t()}

  @type error ::
          :invalid_key
          | :invalid_client_id
          | :invalid_audience
          | :invalid_params
          | :invalid_typ
          | :invalid_lifetime
          | :invalid_time
          | :invalid_jti
          | :unsupported_alg
          | :unsupported_key
          | {:signing_failed, String.t()}

  @doc """
  Build a signed request object, returning `{:ok, compact_jws}` or
  `{:error, reason}`. Fails fast on invalid input (see the error type).

  `jwk` is the client's private key. Required options: `:client_id`,
  `:audience`. The authorization parameters go in `:params` (a string-keyed
  map, defaulting to `%{}`). See the module docs for `:typ` and the envelope
  claims; `:alg`, `:kid`, `:lifetime`, `:now`, and `:jti` behave as in
  `AttestoClient.ClientAssertion.build/2`.
  """
  @spec build(jwk(), [build_opt()]) :: {:ok, String.t()} | {:error, error()}
  def build(jwk, opts) when is_list(opts) do
    with {:ok, jose_jwk} <- Builder.normalize_key(jwk),
         {:ok, client_id} <- Builder.require_string(opts, :client_id, :invalid_client_id),
         {:ok, audience} <- Builder.require_string(opts, :audience, :invalid_audience),
         {:ok, params} <- validate_params(opts),
         {:ok, typ} <- validate_typ(opts),
         {:ok, lifetime} <-
           Builder.validate_lifetime(opts, @default_lifetime_seconds, @max_lifetime_seconds),
         {:ok, now} <- validate_now(opts),
         {:ok, jti} <- Builder.validate_jti(opts),
         {:ok, alg} <- Builder.resolve_alg(jose_jwk, opts) do
      claims =
        Map.merge(params, %{
          "iss" => client_id,
          "aud" => audience,
          "iat" => now,
          "nbf" => now,
          "exp" => now + lifetime,
          "jti" => jti
        })

      header = Builder.put_kid(%{"alg" => alg, "typ" => typ}, jose_jwk, opts)
      Builder.sign(jose_jwk, header, claims)
    end
  end

  # The authorization parameters must be a string-keyed map (they become JWT
  # claims); anything else is rejected rather than producing a malformed object.
  defp validate_params(opts) do
    case Keyword.get(opts, :params, %{}) do
      params when is_map(params) ->
        if Enum.all?(Map.keys(params), &is_binary/1),
          do: {:ok, params},
          else: {:error, :invalid_params}

      _other ->
        {:error, :invalid_params}
    end
  end

  defp validate_typ(opts) do
    case Keyword.get(opts, :typ, @fapi_typ) do
      typ when is_binary(typ) ->
        if String.trim(typ) == "", do: {:error, :invalid_typ}, else: {:ok, typ}

      _other ->
        {:error, :invalid_typ}
    end
  end

  # NumericDate is a non-negative seconds count (RFC 7519 §2); a request object's
  # iat/nbf/exp must not be built from a negative `now`.
  defp validate_now(opts) do
    case Keyword.fetch(opts, :now) do
      :error -> {:ok, System.system_time(:second)}
      {:ok, n} when is_integer(n) and n >= 0 -> {:ok, n}
      {:ok, _invalid} -> {:error, :invalid_time}
    end
  end
end
