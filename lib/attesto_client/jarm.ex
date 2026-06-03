defmodule AttestoClient.JARM do
  @moduledoc """
  Verify JWT Secured Authorization Response Mode (JARM) responses, the
  client-side mirror of `Attesto.JARM.response_jwt/4`.

  When a client requests a JWT response mode, the authorization server returns
  the authorization response as a single signed JWT (the `response` parameter).
  This verifies that JWT - signature, issuer, audience, and expiry - and returns
  the response parameters (FAPI 2.0 Message Signing §5.4 / the JARM spec). It is
  a verifier, not a flow runner: the host extracts `response` from the redirect
  (or form post) and passes it here.

  ## Checks (JARM §2.4)

    * **Signature** verifies against one of the authorization server's JWKS keys,
      restricted to an algorithm allow-list (`:accepted_algs`, default the FAPI
      algorithms PS256/ES256/EdDSA - `none` is never accepted). When the JWT
      header carries a `kid`, only the matching key is tried.
    * `iss` equals the expected authorization server identifier (`:issuer`).
    * `aud` contains the client's `client_id` (`:client_id`).
    * `exp` is present and in the future.

  On success it returns `{:ok, claims}`, the full claim set - the caller reads
  the response parameters (`code`/`state` on success, or `error`/
  `error_description`/`state` on an error response).
  """

  alias Attesto.SigningAlg

  @type jwks :: %{optional(String.t()) => term()} | [map()]

  @type verify_opt ::
          {:issuer, String.t()}
          | {:client_id, String.t()}
          | {:accepted_algs, [String.t()]}
          | {:now, integer()}

  @type error ::
          :invalid_jwks
          | :missing_issuer
          | :missing_client_id
          | :invalid_signature
          | :invalid_issuer
          | :invalid_audience
          | :missing_exp
          | :expired

  @doc """
  Verify a JARM `response` JWT against the authorization server's `jwks`,
  returning `{:ok, claims}` or `{:error, reason}`.

  Required options: `:issuer` (the expected authorization server identifier) and
  `:client_id` (the expected audience). Optional: `:accepted_algs` (default the
  FAPI algorithms) and `:now` (Unix seconds, for tests).
  """
  @spec verify(String.t(), jwks(), [verify_opt()]) :: {:ok, map()} | {:error, error()}
  def verify(response_jwt, jwks, opts) when is_binary(response_jwt) and is_list(opts) do
    with {:ok, keys} <- normalize_jwks(jwks),
         {:ok, issuer} <- require_opt(opts, :issuer, :missing_issuer),
         {:ok, client_id} <- require_opt(opts, :client_id, :missing_client_id),
         {:ok, claims} <- verify_signature(response_jwt, keys, accepted_algs(opts)),
         :ok <- check_issuer(claims, issuer),
         :ok <- check_audience(claims, client_id),
         :ok <- check_expiry(claims, now(opts)) do
      {:ok, claims}
    end
  end

  defp normalize_jwks(%{"keys" => keys}) when is_list(keys), do: normalize_jwks(keys)

  defp normalize_jwks(keys) when is_list(keys) do
    if Enum.all?(keys, &is_map/1), do: {:ok, keys}, else: {:error, :invalid_jwks}
  end

  defp normalize_jwks(_other), do: {:error, :invalid_jwks}

  defp require_opt(opts, key, error) do
    case Keyword.get(opts, key) do
      value when is_binary(value) and value != "" -> {:ok, value}
      _ -> {:error, error}
    end
  end

  # The FAPI signing algorithms by default (PS256/ES256/EdDSA); `none` can never
  # be supplied because it is not an asymmetric algorithm in attesto's set.
  defp accepted_algs(opts) do
    case Keyword.get(opts, :accepted_algs) do
      algs when is_list(algs) and algs != [] -> algs
      _ -> SigningAlg.fapi_algs()
    end
  end

  # Verify the compact JWS against the JWKS, restricted to `algs` (a strict
  # allow-list, so an alg-confusion or `none` token is rejected). When the header
  # names a kid, only that key is tried. Any malformed input fails closed as an
  # invalid signature rather than raising.
  defp verify_signature(jwt, keys, algs) do
    candidates = filter_by_kid(keys, header_kid(jwt))

    Enum.find_value(candidates, {:error, :invalid_signature}, fn key_map ->
      verify_with_key(key_map, algs, jwt)
    end)
  rescue
    _error -> {:error, :invalid_signature}
  end

  defp verify_with_key(key_map, algs, jwt) do
    case JOSE.JWT.verify_strict(JOSE.JWK.from_map(key_map), algs, jwt) do
      {true, %JOSE.JWT{fields: claims}, %JOSE.JWS{}} -> {:ok, claims}
      _other -> nil
    end
  rescue
    _error -> nil
  end

  defp header_kid(jwt) do
    jwt |> JOSE.JWS.peek_protected() |> JSON.decode!() |> Map.get("kid")
  rescue
    _error -> nil
  end

  defp filter_by_kid(keys, nil), do: keys
  defp filter_by_kid(keys, kid), do: Enum.filter(keys, &(Map.get(&1, "kid") == kid))

  defp check_issuer(claims, issuer) do
    if Map.get(claims, "iss") == issuer, do: :ok, else: {:error, :invalid_issuer}
  end

  defp check_audience(claims, client_id) do
    case Map.get(claims, "aud") do
      ^client_id -> :ok
      auds when is_list(auds) -> if client_id in auds, do: :ok, else: {:error, :invalid_audience}
      _other -> {:error, :invalid_audience}
    end
  end

  defp check_expiry(claims, now) do
    case Map.get(claims, "exp") do
      exp when is_integer(exp) -> if exp > now, do: :ok, else: {:error, :expired}
      _other -> {:error, :missing_exp}
    end
  end

  defp now(opts) do
    case Keyword.get(opts, :now) do
      n when is_integer(n) -> n
      _ -> System.system_time(:second)
    end
  end
end
