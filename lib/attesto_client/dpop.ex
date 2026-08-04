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

  Signing and key-bound `:alg`/`:kid` validation behave as in
  `AttestoClient.Wallet.Proof` (shared `AttestoClient.Builder` internals): the
  proof's public `jwk` is this key, and the server pins the token to its
  `jkt` thumbprint.
  """

  alias Attesto.DPoP, as: Verify
  alias AttestoClient.Builder

  # RFC 9449 §4.2: the fixed proof type. Not overridable.
  @proof_typ "dpop+jwt"

  @type jwk :: JOSE.JWK.t() | map()

  @type build_opt ::
          {:access_token, String.t()}
          | {:nonce, String.t()}
          | {:alg, String.t()}
          | {:kid, String.t()}
          | {:now, integer()}
          | {:jti, String.t()}

  @type error ::
          :invalid_key
          | :invalid_htm
          | :invalid_htu
          | :invalid_time
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
    with {:ok, jose_jwk} <- Builder.normalize_key(jwk),
         {:ok, method} <- normalize_htm(htm),
         {:ok, uri} <- normalize_htu(htu),
         {:ok, now} <- Builder.validate_now(opts),
         {:ok, jti} <- Builder.validate_jti(opts),
         {:ok, alg} <- Builder.resolve_alg(jose_jwk, opts) do
      claims =
        %{"htm" => method, "htu" => uri, "iat" => now, "jti" => jti}
        |> put_optional("ath", ath(Keyword.get(opts, :access_token)))
        |> put_optional("nonce", Keyword.get(opts, :nonce))

      header =
        %{"alg" => alg, "typ" => @proof_typ, "jwk" => Builder.public_jwk(jose_jwk)}
        |> Builder.put_kid(jose_jwk, opts)

      Builder.sign(jose_jwk, header, claims)
    end
  end

  defp normalize_htm(htm) do
    case String.trim(htm) do
      "" -> {:error, :invalid_htm}
      method -> {:ok, String.upcase(method)}
    end
  end

  # RFC 9449 §4.2: `htu` is the request URI without query or fragment.
  defp normalize_htu(htu) do
    case URI.new(htu) do
      {:ok, %URI{scheme: scheme, host: host} = uri}
      when is_binary(scheme) and is_binary(host) ->
        {:ok, URI.to_string(%{uri | query: nil, fragment: nil})}

      _ ->
        {:error, :invalid_htu}
    end
  end

  # Reuse the verifier's `ath` computation so client and server agree on the
  # exact SHA-256/base64url encoding.
  defp ath(nil), do: nil

  defp ath(access_token) when is_binary(access_token) and access_token != "",
    do: Verify.compute_ath(access_token)

  defp ath(_invalid), do: nil

  defp put_optional(map, _key, nil), do: map
  defp put_optional(map, key, value), do: Map.put(map, key, value)
end
