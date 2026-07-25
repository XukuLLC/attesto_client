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
      algorithms PS256/ES256/EdDSA/Ed25519 - `none` is never accepted). The
      default also enforces the FAPI RSA-strength and Ed25519-only key policy.
      When the JWT header carries a `kid`, exactly one suitable matching key
      must exist.
    * `iss` equals the expected authorization server identifier (`:issuer`).
    * `aud` equals, or (an all-string array) contains, the client's `client_id`
      (`:client_id`); a mixed-type `aud` array is malformed.
    * `iat`, when present, is a non-negative NumericDate not meaningfully in the
      future (a 60-second clock-skew tolerance).
    * `exp` is present and in the future.

  On success it returns `{:ok, claims}`, the full claim set - the caller reads
  the response parameters (`code`/`state` on success, or `error`/
  `error_description`/`state` on an error response).
  """

  alias Attesto.SigningAlg
  alias AttestoClient.Verifier

  # Clock-skew tolerance for `iat`, matching attesto's token verification.
  @clock_skew_seconds 60

  @type jwks :: %{optional(String.t()) => term()} | [map()]

  @type verify_opt ::
          {:issuer, String.t()}
          | {:client_id, String.t()}
          | {:accepted_algs, [String.t()]}
          | {:enforce_fapi_alg_policy, boolean()}
          | {:now, integer()}

  @type error ::
          :invalid_jwks
          | :missing_issuer
          | :missing_client_id
          | :unsupported_alg
          | :invalid_token
          | :invalid_signature
          | :ambiguous_key
          | :weak_key
          | :unsupported_critical_header
          | :invalid_policy
          | :invalid_issuer
          | :invalid_audience
          | :invalid_iat
          | :not_yet_valid
          | :missing_exp
          | :expired

  @doc """
  Verify a JARM `response` JWT against the authorization server's `jwks`,
  returning `{:ok, claims}` or `{:error, reason}`.

  Required options: `:issuer` (the expected authorization server identifier) and
  `:client_id` (the expected audience). Optional: `:accepted_algs` (default the
  FAPI algorithms) and `:now` (Unix seconds, for tests). Supplying an explicit
  `:accepted_algs` list selects a non-FAPI algorithm policy unless
  `:enforce_fapi_alg_policy` is also `true`.
  """
  @spec verify(String.t(), jwks(), [verify_opt()]) :: {:ok, map()} | {:error, error()}
  def verify(response_jwt, jwks, opts) when is_binary(response_jwt) and is_list(opts) do
    now = Verifier.now(opts)

    with {:ok, keys} <- Verifier.normalize_jwks(jwks),
         {:ok, issuer} <- Verifier.require_string(opts, :issuer, :missing_issuer),
         {:ok, client_id} <- Verifier.require_string(opts, :client_id, :missing_client_id),
         {:ok, algs} <- accepted_algs(opts),
         {:ok, enforce_fapi_policy} <- enforce_fapi_policy(opts),
         {:ok, claims, _header, _verified_jwk} <-
           Verifier.verify_signature(response_jwt, keys, algs,
             enforce_fapi_alg_policy: enforce_fapi_policy
           ),
         :ok <- check_issuer(claims, issuer),
         :ok <- check_audience(claims, client_id),
         :ok <- check_issued_at(claims, now),
         :ok <- check_expiry(claims, now) do
      {:ok, claims}
    end
  end

  defp enforce_fapi_policy(opts) do
    default = not Keyword.has_key?(opts, :accepted_algs)

    case Keyword.get(opts, :enforce_fapi_alg_policy, default) do
      value when is_boolean(value) -> {:ok, value}
      _other -> {:error, :invalid_policy}
    end
  end

  # Preserve the shared verifier's long-standing `nil`-means-default behavior
  # for its other public consumers. At this FAPI boundary, however, only an
  # actual non-empty list is an explicit non-FAPI policy; a present `nil` must
  # not disable the curve/strength defaults.
  defp accepted_algs(opts) do
    case Keyword.fetch(opts, :accepted_algs) do
      {:ok, nil} -> {:error, :unsupported_alg}
      _other -> Verifier.accepted_algs(opts, SigningAlg.fapi_algs())
    end
  end

  defp check_issuer(claims, issuer) do
    if Map.get(claims, "iss") == issuer, do: :ok, else: {:error, :invalid_issuer}
  end

  # An `aud` array is honoured only when every member is a string (a mixed-type
  # array is malformed, even if the client_id is present), matching attesto's
  # token/ID-token audience hardening.
  defp check_audience(claims, client_id) do
    case Map.get(claims, "aud") do
      ^client_id ->
        :ok

      auds when is_list(auds) ->
        if Enum.all?(auds, &is_binary/1) and client_id in auds,
          do: :ok,
          else: {:error, :invalid_audience}

      _other ->
        {:error, :invalid_audience}
    end
  end

  # `iat` is optional in JARM, but when present it must be a non-negative
  # NumericDate (RFC 7519 §2) and not meaningfully in the future (a JARM response
  # is consumed immediately); a small skew tolerates a fast issuer clock.
  defp check_issued_at(claims, now) do
    case Map.get(claims, "iat") do
      nil -> :ok
      iat when is_integer(iat) and iat >= 0 -> within_skew(iat, now)
      _other -> {:error, :invalid_iat}
    end
  end

  defp within_skew(iat, now) do
    if iat <= now + @clock_skew_seconds, do: :ok, else: {:error, :not_yet_valid}
  end

  defp check_expiry(claims, now) do
    case Map.get(claims, "exp") do
      exp when is_integer(exp) -> if exp > now, do: :ok, else: {:error, :expired}
      _other -> {:error, :missing_exp}
    end
  end
end
