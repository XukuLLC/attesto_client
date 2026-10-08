defmodule AttestoClient.WalletAttestation do
  @moduledoc """
  Build the two JWTs of OAuth 2.0 Attestation-Based Client Authentication
  (`draft-ietf-oauth-attestation-based-client-auth-11`), the client-side mirror
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

  `OAuthHTTP` retries `use_attestation_challenge` once with a fresh PoP and
  the response's `OAuth-Client-Attestation-Challenge`. Set `:challenge` in
  the client-auth options to use a Challenge obtained proactively. Its
  `:attestation_challenge_received` callback receives Challenge response
  headers, including successful responses, so a host can retain the newest
  Challenge for its next request. The callback receives one string.

  Independent DPoP can accompany this authentication method using a separate
  proof and key. The optional `attest_jwt_client_auth_dpop` combined mode is
  not implemented; both attestation headers remain required.
  """

  alias AttestoClient.Builder
  alias AttestoClient.OAuthHTTP
  alias AttestoClient.Wallet.CredentialJSON

  @attestation_typ "oauth-client-attestation+jwt"
  @pop_typ "oauth-client-attestation-pop+jwt"

  # The Client Attestation is long-lived relative to a single request but still
  # bounded; the PoP is short-lived per the draft's freshness checks.
  @default_attestation_lifetime_seconds 3600
  @default_pop_lifetime_seconds 120

  @type jwk :: JOSE.JWK.t() | map()

  @type attestation_opt ::
          {:client_id, String.t()}
          | {:issuer, String.t()}
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
          | :invalid_issuer
          | :invalid_client_id
          | :invalid_audience
          | :invalid_challenge
          | :invalid_instance_key
          | :invalid_lifetime
          | :invalid_jti
          | :unsupported_alg
          | :unsupported_key
          | {:signing_failed, String.t()}

  @doc """
  Obtain a Client Attestation Challenge from an advertised challenge endpoint.

  Sends an empty, unauthenticated POST using the same endpoint screening and
  timeout protections as the OAuth HTTP layer. Requires HTTP 200, JSON, and a
  nonempty `attestation_challenge`; rejects duplicate JSON members. Response
  bytes are limited to 16 KiB and challenge/nonce values to 4 KiB.

  Returns `%{challenge: challenge, dpop_nonce: nonce_or_nil, expires_in: seconds_or_nil}`.
  Supply `challenge` in the client-auth tuple's options, and `dpop_nonce` as
  the `:dpop_nonce` request option when using DPoP. The most recently received
  challenge and DPoP nonce supersede older values. `expires_in` is an optional
  positive-integer extension, not a field required by the attestation draft.

  Options include `:timeout` (milliseconds), `:resolver`, and `:req_options`.
  Select the endpoint from trusted server metadata; this call performs no
  issuer discovery and stores no challenge globally.
  """
  @spec fetch_challenge(String.t(), keyword()) ::
          {:ok,
           %{challenge: String.t(), dpop_nonce: String.t() | nil, expires_in: pos_integer() | nil}}
          | {:error, term()}
  def fetch_challenge(endpoint, opts \\ []) when is_list(opts) do
    with {:ok, response} <- OAuthHTTP.post_challenge(endpoint, opts),
         :ok <- challenge_response(response),
         {:ok, body} <- challenge_json(response.body),
         {:ok, challenge} <- fetched_challenge(body),
         {:ok, nonce} <- fetched_dpop_nonce(response),
         {:ok, lifetime} <- challenge_lifetime(body) do
      {:ok, %{challenge: challenge, dpop_nonce: nonce, expires_in: lifetime}}
    end
  end

  defp challenge_response(%Req.Response{status: 200} = response) do
    case Req.Response.get_header(response, "content-type") do
      [type] ->
        if type |> String.split(";", parts: 2) |> hd() |> String.trim() |> String.downcase() ==
             "application/json",
           do: :ok,
           else: {:error, :invalid_challenge_response}

      _invalid ->
        {:error, :invalid_challenge_response}
    end
  end

  defp challenge_response(%Req.Response{status: status}), do: {:error, {:http_status, status}}

  defp challenge_json(bytes) when is_binary(bytes) and byte_size(bytes) <= 16_384 do
    case CredentialJSON.decode(bytes) do
      {:ok, body} -> {:ok, body}
      _invalid -> {:error, :invalid_challenge_response}
    end
  end

  defp challenge_json(_invalid), do: {:error, :invalid_challenge_response}

  defp fetched_challenge(%{"attestation_challenge" => challenge})
       when is_binary(challenge) and byte_size(challenge) in 1..4_096,
       do: {:ok, challenge}

  defp fetched_challenge(_invalid), do: {:error, :invalid_challenge_response}

  defp fetched_dpop_nonce(response) do
    case Req.Response.get_header(response, "dpop-nonce") do
      [] -> {:ok, nil}
      [nonce] when is_binary(nonce) and byte_size(nonce) in 1..4_096 -> {:ok, nonce}
      _invalid -> {:error, :invalid_challenge_response}
    end
  end

  defp challenge_lifetime(body) do
    case Map.fetch(body, "expires_in") do
      :error -> {:ok, nil}
      {:ok, seconds} when is_integer(seconds) and seconds > 0 -> {:ok, seconds}
      _invalid -> {:error, :invalid_challenge_response}
    end
  end

  @doc """
  Build a Client Attestation JWT, returning `{:ok, compact_jws}` or
  `{:error, reason}`. Fails fast on invalid input.

  `provider_key` is the Wallet Provider (Client Attester) private key that signs
  the attestation. Required options:

    * `:client_id` - the wallet instance's client identifier (becomes `sub`).
    * `:instance_key` - the wallet instance's key; its public half is embedded
      as the `cnf` confirmation JWK the PoP must be signed by.

  Optional: `:issuer` names the Client Attester in the `iss` claim where the
  ecosystem uses that claim; draft 11 does not require it. `:x5c` is optional
  for the generic builder, but HAIP's Appendix E format requires the provider
  certificate and any intermediate certificates, excluding the trust anchor,
  in this base64 DER certificate list. The authorization server validates
  signature, certificate trust and attestation validity. Renewals may retain
  the same client subject and instance key without retaining the same JWT.
  Other options include `:lifetime` (seconds to
  `exp`, default `#{@default_attestation_lifetime_seconds}`), and `:alg`,
  `:kid`, `:now` as in `AttestoClient.Wallet.Proof.build/2`.
  """
  @spec attestation(jwk(), [attestation_opt()]) :: {:ok, String.t()} | {:error, error()}
  def attestation(provider_key, opts) when is_list(opts) do
    with {:ok, provider_jwk} <- Builder.normalize_key(provider_key),
         {:ok, client_id} <- Builder.require_string(opts, :client_id, :invalid_client_id),
         {:ok, issuer} <- attester_issuer(opts),
         {:ok, instance_public} <- instance_public_jwk(opts),
         {:ok, lifetime} <-
           Builder.validate_lifetime(opts, @default_attestation_lifetime_seconds),
         {:ok, now} <- Builder.validate_now(opts),
         {:ok, alg} <- Builder.resolve_alg(provider_jwk, opts) do
      claims = %{
        "sub" => client_id,
        "iat" => now,
        "exp" => now + lifetime,
        "cnf" => %{"jwk" => instance_public}
      }

      claims = if issuer, do: Map.put(claims, "iss", issuer), else: claims

      header =
        %{"alg" => alg, "typ" => @attestation_typ}
        |> Builder.put_x5c(Keyword.get(opts, :x5c))
        |> Builder.put_kid(provider_jwk, opts)

      Builder.sign(provider_jwk, header, claims)
    end
  end

  defp attester_issuer(opts) do
    case Keyword.fetch(opts, :issuer) do
      :error -> {:ok, nil}
      {:ok, issuer} when is_binary(issuer) and byte_size(issuer) in 1..2_048 -> {:ok, issuer}
      {:ok, _invalid} -> {:error, :invalid_issuer}
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
         :ok <- validate_challenge(Keyword.get(opts, :challenge)),
         {:ok, lifetime} <- Builder.validate_lifetime(opts, @default_pop_lifetime_seconds),
         {:ok, jti} <- Builder.validate_jti(opts),
         {:ok, now} <- Builder.validate_now(opts),
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

  defp validate_challenge(nil), do: :ok
  defp validate_challenge(challenge) when is_binary(challenge), do: :ok
  defp validate_challenge(_invalid), do: {:error, :invalid_challenge}

  defp normalize_instance_key(nil), do: {:error, :invalid_instance_key}

  defp normalize_instance_key(key) do
    case Builder.normalize_key(key) do
      {:ok, jwk} -> {:ok, jwk}
      {:error, _reason} -> {:error, :invalid_instance_key}
    end
  end

  defp put_optional(map, _key, nil), do: map
  defp put_optional(map, key, value), do: Map.put(map, key, value)
end
