defmodule AttestoClient.KeyAttestation do
  @moduledoc """
  Build an OID4VCI Key Attestation JWT (OpenID4VCI 1.0 "Key Attestation in JWT
  format" §D.1), the client-side mirror of `Attesto.KeyAttestation.verify/2`.

  A key attestation, issued by the wallet's key-storage component or its Wallet
  Provider, vouches that a set of public keys are held in a class of secure
  storage. A wallet attaches one to a Credential Request in the `key_attestation`
  JOSE header of its `jwt` proof (see `AttestoClient.Wallet.Proof`); the issuer,
  configured to trust the signer, then requires the proof's key to appear in the
  attestation's `attested_keys`.

  Signing and key-bound `:alg`/`:kid` validation behave as in
  `AttestoClient.Wallet.Proof` (shared `AttestoClient.Builder` internals).
  """

  alias AttestoClient.Builder

  @typ "key-attestation+jwt"

  # Bounded lifetime: the spec requires `exp` when the attestation rides a `jwt`
  # proof (the only use here), so it is always present.
  @default_lifetime_seconds 300

  @type jwk :: JOSE.JWK.t() | map()

  @type build_opt ::
          {:attested_keys, [jwk()]}
          | {:key_storage, [String.t()]}
          | {:user_authentication, [String.t()]}
          | {:certification, String.t()}
          | {:nonce, String.t()}
          | {:x5c, [String.t()]}
          | {:lifetime, pos_integer()}
          | {:alg, String.t()}
          | {:kid, String.t()}
          | {:now, integer()}

  @type error ::
          :invalid_key
          | :invalid_attested_keys
          | :invalid_key_storage
          | :invalid_user_authentication
          | :invalid_certification
          | :invalid_nonce
          | :invalid_x5c
          | :invalid_kid
          | :invalid_lifetime
          | :unsupported_alg
          | :unsupported_key
          | :invalid_time
          | {:signing_failed, String.t()}

  @doc """
  Build a key attestation JWT, returning `{:ok, compact_jws}` or
  `{:error, reason}`. Fails fast on invalid input.

  `provider_key` is the key-storage / Wallet Provider private key that signs the
  attestation. Required option `:attested_keys` is a non-empty list of the keys
  the attestation vouches for (`JOSE.JWK`s or JWK maps); their public halves are
  embedded, and the proof's holder key must be among them.

  Optional: `:key_storage` / `:user_authentication` (attack-potential-resistance
  string lists), `:certification` (an absolute HTTP(S) URL), `:nonce` (echo the
  issuer's `c_nonce`), `:x5c` (base64 DER certificates for the header),
  `:lifetime` (seconds to `exp`, default `#{@default_lifetime_seconds}`), and
  `:alg`, `:kid`, `:now` as in `AttestoClient.Wallet.Proof.build/2`.
  """
  @spec build(jwk(), [build_opt()]) :: {:ok, String.t()} | {:error, error()}
  def build(provider_key, opts) when is_list(opts) do
    with {:ok, provider_jwk} <- Builder.normalize_key(provider_key),
         {:ok, attested_keys} <- attested_public_keys(Keyword.get(opts, :attested_keys)),
         {:ok, key_storage} <- optional_string_list(opts, :key_storage, :invalid_key_storage),
         {:ok, user_authentication} <-
           optional_string_list(opts, :user_authentication, :invalid_user_authentication),
         {:ok, certification} <- optional_url(opts, :certification, :invalid_certification),
         {:ok, nonce} <- optional_string(opts, :nonce, :invalid_nonce),
         {:ok, x5c} <- Builder.validate_x5c(opts),
         {:ok, lifetime} <- Builder.validate_lifetime(opts, @default_lifetime_seconds),
         {:ok, now} <- Builder.validate_now(opts),
         {:ok, kid} <- Builder.resolve_kid(provider_jwk, opts),
         {:ok, alg} <- Builder.resolve_alg(provider_jwk, opts) do
      claims =
        %{"iat" => now, "exp" => now + lifetime, "attested_keys" => attested_keys}
        |> Attesto.MapParams.put_optional("key_storage", key_storage)
        |> Attesto.MapParams.put_optional("user_authentication", user_authentication)
        |> Attesto.MapParams.put_optional("certification", certification)
        |> Attesto.MapParams.put_optional("nonce", nonce)

      header =
        %{"alg" => alg, "typ" => @typ}
        |> Builder.put_x5c(x5c)
        |> Builder.put_kid(kid)

      Builder.sign(provider_jwk, header, claims)
    end
  end

  defp attested_public_keys([_ | _] = keys) do
    Enum.reduce_while(keys, {:ok, []}, fn key, {:ok, acc} ->
      case attested_public_key(key) do
        {:ok, public} ->
          {:cont, {:ok, [public | acc]}}

        {:error, :invalid_attested_keys} ->
          {:halt, {:error, :invalid_attested_keys}}
      end
    end)
    |> case do
      {:ok, publics} -> {:ok, Enum.reverse(publics)}
      {:error, reason} -> {:error, reason}
    end
  end

  defp attested_public_keys(_absent), do: {:error, :invalid_attested_keys}

  defp attested_public_key(key) do
    case Builder.normalize_key(key) do
      {:ok, jwk} ->
        Builder.public_jwk_result(jwk, :invalid_attested_keys)

      {:error, _reason} ->
        {:error, :invalid_attested_keys}
    end
  end

  defp optional_string_list(opts, key, error) do
    case Keyword.fetch(opts, key) do
      :error ->
        {:ok, nil}

      {:ok, [_ | _] = values} ->
        if Enum.all?(values, &(is_binary(&1) and &1 != "")),
          do: {:ok, values},
          else: {:error, error}

      {:ok, _invalid} ->
        {:error, error}
    end
  end

  defp optional_string(opts, key, error) do
    case Keyword.fetch(opts, key) do
      :error -> {:ok, nil}
      {:ok, value} when is_binary(value) and value != "" -> {:ok, value}
      {:ok, _invalid} -> {:error, error}
    end
  end

  defp optional_url(opts, key, error) do
    with {:ok, value} <- optional_string(opts, key, error) do
      validate_optional_url(value, error)
    end
  end

  defp validate_optional_url(nil, _error), do: {:ok, nil}

  defp validate_optional_url(value, error) do
    if Attesto.URI.https_identifier?(value, allow_http: true),
      do: {:ok, value},
      else: {:error, error}
  end
end
