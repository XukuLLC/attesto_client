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
    * `nbf`, when present, is a non-negative NumericDate no later than the same
      clock-skew window.
    * `exp` is present and in the future.

  On success it returns `{:ok, claims}`, the full claim set - the caller reads
  the response parameters (`code`/`state` on success, or `error`/
  `error_description`/`state` on an error response).
  """

  alias Attesto.SigningAlg
  alias AttestoClient.{ClaimValidation, Verifier}

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
          | :invalid_nbf
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
         :ok <- ClaimValidation.audience(claims, client_id, :invalid_audience),
         :ok <-
           ClaimValidation.issued_at(claims, now,
             invalid_error: :invalid_iat,
             future_error: :not_yet_valid,
             skew: @clock_skew_seconds
           ),
         :ok <-
           ClaimValidation.not_before(claims, now,
             invalid_error: :invalid_nbf,
             future_error: :not_yet_valid,
             skew: @clock_skew_seconds
           ),
         :ok <-
           ClaimValidation.expiration(claims, now,
             missing_error: :missing_exp,
             invalid_error: :missing_exp,
             expired_error: :expired
           ) do
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
end
