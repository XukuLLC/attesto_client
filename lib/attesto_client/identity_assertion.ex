defmodule AttestoClient.IdentityAssertion do
  @moduledoc """
  Build Identity Assertion JWT Authorization Grant assertions (ID-JAG / EMA).

  This is the client-side mirror of `Attesto.IdentityAssertion.verify/3`: the
  client constructs a short-lived JWT bearer grant assertion and the
  authorization server verifies it against a trusted issuer JWKS. The assertion
  is presented to the token endpoint as the RFC 7523 §4 JWT-bearer grant
  (`grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`, `assertion=<jwt>`).

  The JOSE header `typ` is fixed to `"oauth-id-jag+jwt"`, matching attesto's
  verifier. The required claim set is the draft's ID-JAG set:

    * `iss` - trusted identity-assertion issuer.
    * `sub` - asserted user subject.
    * `aud` - resource authorization server issuer.
    * `client_id` - client presenting the assertion.
    * `jti` - unique assertion identifier.
    * `iat` / `exp` - short validity window.

  Extra string-keyed claims may be added for deployment-specific identity data
  (`scope`, `email`, tenant claims, etc.) as long as they do not collide with the
  registered claims above.
  """

  alias AttestoClient.Builder

  @typ "oauth-id-jag+jwt"
  @default_lifetime_seconds 300
  @reserved_claims ~w(iss sub aud client_id jti exp iat nbf)

  @type jwk :: JOSE.JWK.t() | map()

  @type build_opt ::
          {:issuer, String.t()}
          | {:audience, String.t()}
          | {:client_id, String.t()}
          | {:subject, String.t()}
          | {:claims, %{optional(String.t()) => term()}}
          | {:alg, String.t()}
          | {:kid, String.t()}
          | {:lifetime, pos_integer()}
          | {:now, non_neg_integer()}
          | {:jti, String.t()}
          | {:nbf, non_neg_integer()}

  @type error ::
          :invalid_key
          | :invalid_issuer
          | :invalid_audience
          | :invalid_client_id
          | :invalid_subject
          | :invalid_claims
          | :reserved_claim_conflict
          | :invalid_lifetime
          | :invalid_time
          | :invalid_jti
          | :unsupported_alg
          | :unsupported_key
          | {:signing_failed, String.t()}

  @doc """
  Build a signed ID-JAG assertion, returning `{:ok, compact_jws}` or
  `{:error, reason}`.

  Required options: `:issuer`, `:audience`, `:client_id`, and `:subject`.
  Optional `:claims` must be a string-keyed map and cannot collide with the
  registered ID-JAG claims.
  """
  @spec build(jwk(), [build_opt()]) :: {:ok, String.t()} | {:error, error()}
  def build(jwk, opts) when is_list(opts) do
    with {:ok, jose_jwk} <- Builder.normalize_key(jwk),
         {:ok, issuer} <- Builder.require_string(opts, :issuer, :invalid_issuer),
         {:ok, audience} <- Builder.require_string(opts, :audience, :invalid_audience),
         {:ok, client_id} <- Builder.require_string(opts, :client_id, :invalid_client_id),
         {:ok, subject} <- Builder.require_string(opts, :subject, :invalid_subject),
         {:ok, claims} <- validate_claims(opts),
         {:ok, lifetime} <- Builder.validate_lifetime(opts, @default_lifetime_seconds),
         {:ok, now} <- validate_now(opts),
         {:ok, nbf} <- validate_nbf(opts),
         {:ok, jti} <- Builder.validate_jti(opts),
         {:ok, alg} <- Builder.resolve_alg(jose_jwk, opts) do
      registered =
        %{
          "iss" => issuer,
          "sub" => subject,
          "aud" => audience,
          "client_id" => client_id,
          "jti" => jti,
          "iat" => now,
          "exp" => now + lifetime
        }
        |> put_optional("nbf", nbf)

      header = Builder.put_kid(%{"alg" => alg, "typ" => @typ}, jose_jwk, opts)
      Builder.sign(jose_jwk, header, Map.merge(claims, registered))
    end
  end

  defp validate_claims(opts) do
    case Keyword.get(opts, :claims, %{}) do
      claims when is_map(claims) ->
        cond do
          not Enum.all?(Map.keys(claims), &is_binary/1) ->
            {:error, :invalid_claims}

          Enum.any?(Map.keys(claims), &(&1 in @reserved_claims)) ->
            {:error, :reserved_claim_conflict}

          true ->
            {:ok, claims}
        end

      _other ->
        {:error, :invalid_claims}
    end
  end

  defp validate_now(opts) do
    case Keyword.fetch(opts, :now) do
      :error -> {:ok, System.system_time(:second)}
      {:ok, n} when is_integer(n) and n >= 0 -> {:ok, n}
      {:ok, _invalid} -> {:error, :invalid_time}
    end
  end

  defp validate_nbf(opts) do
    case Keyword.fetch(opts, :nbf) do
      :error -> {:ok, nil}
      {:ok, nbf} when is_integer(nbf) and nbf >= 0 -> {:ok, nbf}
      {:ok, _invalid} -> {:error, :invalid_time}
    end
  end

  defp put_optional(claims, _key, nil), do: claims
  defp put_optional(claims, key, value), do: Map.put(claims, key, value)
end
