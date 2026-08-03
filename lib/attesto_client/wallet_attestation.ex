defmodule AttestoClient.WalletAttestation do
  @moduledoc """
  Build the two JWTs of OAuth 2.0 Attestation-Based Client Authentication
  (`draft-ietf-oauth-attestation-based-client-auth-10`), the client-side mirror
  of `Attesto.WalletAttestation.verify/3` and the client-auth method OID4VCI
  recommends for native-app wallets over `private_key_jwt`/mTLS.

  Two artifacts, signed by two different keys:

    * `attestation/2` - the **Client Attestation JWT**
      (`typ` `oauth-client-attestation+jwt`), issued by the Wallet Provider
      (Client Attester) and signed by its key. It binds the wallet instance's
      public key into `cnf` and names the instance's `client_id` in `sub`. It is
      long-lived and reused across many requests; an `:x5c` header lets the
      server chain the signer to a configured trust anchor.

    * `pop/2` - the **Client Attestation PoP JWT**
      (`typ` `oauth-client-attestation-pop+jwt`), minted fresh per request and
      signed by the *instance* key (the private half of the attestation's `cnf`
      key), proving possession to one `aud` (the server's identifier).

  The client presents them in the `OAuth-Client-Attestation` and
  `OAuth-Client-Attestation-PoP` headers; `AttestoClient.OAuthHTTP`'s
  `{:client_attestation, ...}` client-auth attaches both. Signing and key-bound
  `:alg`/`:kid` validation behave as in `AttestoClient.Wallet.Proof` (shared
  `AttestoClient.Builder` internals).
  """

  alias AttestoClient.Builder

  @attestation_typ "oauth-client-attestation+jwt"
  @pop_typ "oauth-client-attestation-pop+jwt"

  # The Client Attestation is long-lived relative to a single request but still
  # bounded; the PoP is short-lived per the draft's freshness checks.
  @default_attestation_lifetime_seconds 3600
  @default_pop_lifetime_seconds 120

  @type jwk :: JOSE.JWK.t() | map()

  @type attestation_opt ::
          {:client_id, String.t()}
          | {:instance_key, jwk()}
          | {:x5c, [String.t()]}
          | {:lifetime, pos_integer()}
          | {:alg, String.t()}
          | {:kid, String.t()}
          | {:now, integer()}

  @type pop_opt ::
          {:client_id, String.t()}
          | {:audience, String.t()}
          | {:challenge, String.t()}
          | {:lifetime, pos_integer()}
          | {:jti, String.t()}
          | {:alg, String.t()}
          | {:kid, String.t()}
          | {:now, integer()}

  @type error ::
          :invalid_key
          | :invalid_client_id
          | :invalid_audience
          | :invalid_instance_key
          | :invalid_lifetime
          | :invalid_jti
          | :unsupported_alg
          | :unsupported_key
          | {:signing_failed, String.t()}

  @doc """
  Build a Client Attestation JWT, returning `{:ok, compact_jws}` or
  `{:error, reason}`. Fails fast on invalid input.

  `provider_key` is the Wallet Provider (Client Attester) private key that signs
  the attestation. Required options:

    * `:client_id` - the wallet instance's client identifier (becomes `sub`).
    * `:instance_key` - the wallet instance's key; its public half is embedded
      as the `cnf` confirmation JWK the PoP must be signed by.

  Optional: `:x5c` (a list of base64 DER certificates for the `x5c` header, so
  the server can chain the signer to a trust anchor), `:lifetime` (seconds to
  `exp`, default `#{@default_attestation_lifetime_seconds}`), and `:alg`,
  `:kid`, `:now` as in `AttestoClient.Wallet.Proof.build/2`.
  """
  @spec attestation(jwk(), [attestation_opt()]) :: {:ok, String.t()} | {:error, error()}
  def attestation(provider_key, opts) when is_list(opts) do
    with {:ok, provider_jwk} <- Builder.normalize_key(provider_key),
         {:ok, client_id} <- Builder.require_string(opts, :client_id, :invalid_client_id),
         {:ok, instance_public} <- instance_public_jwk(opts),
         {:ok, lifetime} <-
           Builder.validate_lifetime(opts, @default_attestation_lifetime_seconds),
         {:ok, now} <- validate_now(opts),
         {:ok, alg} <- Builder.resolve_alg(provider_jwk, opts) do
      claims = %{
        "sub" => client_id,
        "iat" => now,
        "exp" => now + lifetime,
        "cnf" => %{"jwk" => instance_public}
      }

      header =
        %{"alg" => alg, "typ" => @attestation_typ}
        |> put_x5c(Keyword.get(opts, :x5c))
        |> Builder.put_kid(provider_jwk, opts)

      Builder.sign(provider_jwk, header, claims)
    end
  end

  @doc """
  Build a Client Attestation PoP JWT, returning `{:ok, compact_jws}` or
  `{:error, reason}`. Fails fast on invalid input.

  `instance_key` is the wallet instance private key - the private half of the
  attestation's `cnf` key. Required options:

    * `:client_id` - the wallet instance's client identifier (becomes `iss`).
    * `:audience` - the server's identifier the PoP is presented to (`aud`);
      an AS issuer URL or a resource identifier, single-valued.

  Optional: `:challenge` (echo a server-issued Challenge), `:jti` (default a
  fresh random value), `:lifetime` (seconds to `exp`, default
  `#{@default_pop_lifetime_seconds}`), and `:alg`, `:kid`, `:now`.
  """
  @spec pop(jwk(), [pop_opt()]) :: {:ok, String.t()} | {:error, error()}
  def pop(instance_key, opts) when is_list(opts) do
    with {:ok, instance_jwk} <- Builder.normalize_key(instance_key),
         {:ok, client_id} <- Builder.require_string(opts, :client_id, :invalid_client_id),
         {:ok, audience} <- Builder.require_string(opts, :audience, :invalid_audience),
         {:ok, lifetime} <- Builder.validate_lifetime(opts, @default_pop_lifetime_seconds),
         {:ok, jti} <- Builder.validate_jti(opts),
         {:ok, now} <- validate_now(opts),
         {:ok, alg} <- Builder.resolve_alg(instance_jwk, opts) do
      claims =
        %{
          "iss" => client_id,
          "aud" => audience,
          "jti" => jti,
          "iat" => now,
          "exp" => now + lifetime
        }
        |> put_optional("challenge", Keyword.get(opts, :challenge))

      header = Builder.put_kid(%{"alg" => alg, "typ" => @pop_typ}, instance_jwk, opts)
      Builder.sign(instance_jwk, header, claims)
    end
  end

  defp instance_public_jwk(opts) do
    with {:ok, instance_jwk} <- normalize_instance_key(Keyword.get(opts, :instance_key)) do
      {_type, public} = JOSE.JWK.to_public_map(instance_jwk)
      {:ok, public}
    end
  end

  defp normalize_instance_key(nil), do: {:error, :invalid_instance_key}

  defp normalize_instance_key(key) do
    case Builder.normalize_key(key) do
      {:ok, jwk} -> {:ok, jwk}
      {:error, _reason} -> {:error, :invalid_instance_key}
    end
  end

  defp put_x5c(header, [_ | _] = x5c), do: Map.put(header, "x5c", x5c)
  defp put_x5c(header, _absent), do: header

  defp put_optional(map, _key, nil), do: map
  defp put_optional(map, key, value), do: Map.put(map, key, value)

  defp validate_now(opts) do
    case Keyword.fetch(opts, :now) do
      :error -> {:ok, System.system_time(:second)}
      {:ok, n} when is_integer(n) and n >= 0 -> {:ok, n}
      {:ok, _invalid} -> {:error, :invalid_time}
    end
  end
end
