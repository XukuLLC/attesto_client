defmodule AttestoClient.IDToken do
  @moduledoc """
  Verify OpenID Connect ID Tokens issued by an authorization server.

  This is the client-side mirror of `Attesto.IDToken.mint/4`. A relying party
  receives an ID Token from the server, fetches (or supplies) the server JWKS,
  and verifies the signed JWT plus the OIDC claims that bind it to the client
  and the authorization response.

  ## Checks

    * signature verifies against the issuer JWKS, selected by `kid`, with
      Attesto's supported asymmetric algorithms.
    * JOSE `typ`, when present, must be `"JWT"`; an access-token type such as
      `"at+jwt"` is rejected.
    * `iss` equals `:issuer`.
    * `aud` equals, or is an all-string array containing, `:client_id`.
    * `azp` equals `:client_id` whenever present, and is required when `aud`
      contains multiple audiences.
    * `sub`, `exp`, and `iat` are present and well-typed; `exp` must be in the
      future and `iat` must not be meaningfully in the future.
    * a supplied `:nonce` must match the token's `nonce` claim.
    * `auth_time`, when present, must not be meaningfully in the future; a
      supplied `:max_age` requires `auth_time` and enforces the age.
    * supplied `:access_token`, `:code`, and `:state` are checked against
      `at_hash`, `c_hash`, and `s_hash` respectively using the ID Token signing
      algorithm's left-half hash construction.

  `:jwks` may be supplied directly. Otherwise the verifier can fetch through
  `AttestoClient.Discovery`: pass `:metadata`, `:jwks_uri`, or just `:issuer`
  with optional `:req_options` / `:well_known`.
  """

  alias Attesto.SecureCompare
  alias Attesto.SigningAlg
  alias AttestoClient.Verifier

  @clock_skew_seconds 60
  @id_token_typ "JWT"

  @type verify_opt ::
          {:issuer, String.t()}
          | {:client_id, String.t()}
          | {:jwks, Verifier.jwks()}
          | {:metadata, map()}
          | {:jwks_uri, String.t()}
          | {:nonce, String.t()}
          | {:max_age, non_neg_integer()}
          | {:access_token, String.t()}
          | {:code, String.t()}
          | {:state, String.t()}
          | {:accepted_algs, [SigningAlg.alg()]}
          | {:now, integer() | DateTime.t()}
          | {:req_options, keyword()}
          | {:well_known, AttestoClient.Discovery.well_known()}

  @type error ::
          :missing_issuer
          | :missing_client_id
          | :invalid_jwks
          | :invalid_metadata
          | :issuer_mismatch
          | :unsupported_alg
          | :invalid_token
          | :invalid_signature
          | :unsupported_critical_header
          | :unexpected_typ
          | :invalid_issuer
          | :invalid_audience
          | :missing_azp
          | :invalid_azp
          | :invalid_claims
          | :missing_exp
          | :expired
          | :invalid_iat
          | :not_yet_valid
          | :nonce_required
          | :nonce_mismatch
          | :invalid_max_age
          | :auth_time_required
          | :invalid_auth_time
          | :max_age_exceeded
          | :missing_at_hash
          | :invalid_at_hash
          | :missing_c_hash
          | :invalid_c_hash
          | :missing_s_hash
          | :invalid_s_hash
          | AttestoClient.Discovery.error()

  @doc """
  Verify `id_token`, returning `{:ok, claims}` or `{:error, reason}`.

  Required options:

    * `:issuer` - expected OpenID Provider issuer.
    * `:client_id` - this relying party's client id.

  JWKS options:

    * `:jwks` - a JWKS map/list supplied by the caller.
    * `:metadata` - discovery metadata containing matching `issuer` and
      `jwks_uri`.
    * `:jwks_uri` - fetch only the JWKS.
    * no JWKS option - fetch discovery from `:issuer`, then fetch its JWKS.
  """
  @spec verify(String.t(), [verify_opt()]) :: {:ok, map()} | {:error, error()}
  def verify(id_token, opts) when is_binary(id_token) and is_list(opts) do
    now = Verifier.now(opts)

    with {:ok, issuer} <- Verifier.require_string(opts, :issuer, :missing_issuer),
         {:ok, client_id} <- Verifier.require_string(opts, :client_id, :missing_client_id),
         {:ok, jwks} <- Verifier.resolve_jwks(opts, issuer),
         {:ok, algs} <- Verifier.accepted_algs(opts),
         {:ok, claims, header} <- Verifier.verify_signature(id_token, jwks, algs),
         :ok <- check_header_typ(header),
         :ok <- check_token_purpose(claims),
         :ok <- check_issuer(claims, issuer),
         :ok <- check_audience_and_azp(claims, client_id),
         :ok <- check_required_claims(claims),
         :ok <- check_expiry(claims, now),
         :ok <- check_issued_at(claims, now),
         :ok <- check_nonce(claims, Keyword.get(opts, :nonce)),
         :ok <- check_max_age(claims, opts, now),
         :ok <-
           check_detached_hash(claims, header, "access_token", "at_hash", :access_token, opts),
         :ok <- check_detached_hash(claims, header, "code", "c_hash", :code, opts),
         :ok <- check_detached_hash(claims, header, "state", "s_hash", :state, opts) do
      {:ok, claims}
    end
  end

  def verify(_id_token, _opts), do: {:error, :invalid_token}

  defp check_header_typ(%{"typ" => @id_token_typ}), do: :ok
  defp check_header_typ(%{"typ" => _other}), do: {:error, :unexpected_typ}
  defp check_header_typ(_header), do: :ok

  defp check_token_purpose(claims) do
    cond do
      Map.has_key?(claims, "scope") -> {:error, :unexpected_typ}
      Map.get(claims, "typ") in ["access", "refresh"] -> {:error, :unexpected_typ}
      true -> :ok
    end
  end

  defp check_issuer(%{"iss" => iss}, issuer) when is_binary(iss) do
    if iss == issuer, do: :ok, else: {:error, :invalid_issuer}
  end

  defp check_issuer(_claims, _issuer), do: {:error, :invalid_issuer}

  defp check_audience_and_azp(claims, client_id) do
    with {:ok, audience_count} <- check_audience(claims, client_id) do
      check_azp(claims, client_id, audience_count)
    end
  end

  defp check_audience(%{"aud" => aud}, client_id) when aud == client_id, do: {:ok, 1}

  defp check_audience(%{"aud" => auds}, client_id) when is_list(auds) do
    if Enum.all?(auds, &is_binary/1) and client_id in auds,
      do: {:ok, length(auds)},
      else: {:error, :invalid_audience}
  end

  defp check_audience(_claims, _client_id), do: {:error, :invalid_audience}

  defp check_azp(%{"azp" => azp}, client_id, _audience_count) do
    if azp == client_id, do: :ok, else: {:error, :invalid_azp}
  end

  defp check_azp(_claims, _client_id, audience_count) when audience_count > 1,
    do: {:error, :missing_azp}

  defp check_azp(_claims, _client_id, _audience_count), do: :ok

  defp check_required_claims(claims) do
    cond do
      not non_empty_binary?(Map.get(claims, "sub")) -> {:error, :invalid_claims}
      not non_negative_integer?(Map.get(claims, "iat")) -> {:error, :invalid_iat}
      true -> :ok
    end
  end

  defp check_expiry(%{"exp" => exp}, now) when is_integer(exp) do
    if exp > now, do: :ok, else: {:error, :expired}
  end

  defp check_expiry(_claims, _now), do: {:error, :missing_exp}

  defp check_issued_at(%{"iat" => iat}, now) when is_integer(iat) and iat >= 0 do
    if iat <= now + @clock_skew_seconds, do: :ok, else: {:error, :not_yet_valid}
  end

  defp check_issued_at(_claims, _now), do: {:error, :invalid_iat}

  defp check_nonce(_claims, nil), do: :ok

  defp check_nonce(claims, expected) when is_binary(expected) and expected != "" do
    case Map.get(claims, "nonce") do
      ^expected -> :ok
      nil -> {:error, :nonce_required}
      _other -> {:error, :nonce_mismatch}
    end
  end

  defp check_nonce(_claims, _expected), do: {:error, :nonce_mismatch}

  defp check_max_age(claims, opts, now) do
    case Keyword.get(opts, :max_age) do
      nil ->
        check_optional_auth_time(claims, now)

      max_age when is_integer(max_age) and max_age >= 0 ->
        check_auth_age(claims, max_age, now)

      _other ->
        {:error, :invalid_max_age}
    end
  end

  defp check_auth_age(claims, max_age, now) do
    case fetch_auth_time(claims, now) do
      {:ok, auth_time} ->
        if auth_time + max_age >= now, do: :ok, else: {:error, :max_age_exceeded}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp check_optional_auth_time(%{"auth_time" => _auth_time} = claims, now) do
    case fetch_auth_time(claims, now) do
      {:ok, _auth_time} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  defp check_optional_auth_time(_claims, _now), do: :ok

  defp fetch_auth_time(%{"auth_time" => auth_time}, now)
       when is_integer(auth_time) and auth_time >= 0 do
    if auth_time <= now + @clock_skew_seconds,
      do: {:ok, auth_time},
      else: {:error, :invalid_auth_time}
  end

  defp fetch_auth_time(%{"auth_time" => _bad}, _now), do: {:error, :invalid_auth_time}
  defp fetch_auth_time(_claims, _now), do: {:error, :auth_time_required}

  defp check_detached_hash(claims, header, _label, claim_name, opt_key, opts) do
    case Keyword.get(opts, opt_key) do
      nil ->
        :ok

      value when is_binary(value) ->
        compare_hash_claim(claims, header, claim_name, value)

      _other ->
        hash_error(claim_name)
    end
  end

  defp compare_hash_claim(claims, header, claim_name, value) do
    expected = hash_claim(value, Map.get(header, "alg"))

    case Map.get(claims, claim_name) do
      actual when is_binary(actual) ->
        if SecureCompare.equal?(actual, expected), do: :ok, else: hash_error(claim_name)

      _missing ->
        missing_hash_error(claim_name)
    end
  rescue
    _error -> hash_error(claim_name)
  end

  defp hash_claim(value, alg) when is_binary(value) and is_binary(alg) do
    alg
    |> SigningAlg.hash_alg()
    |> :crypto.hash(value)
    |> binary_part(0, SigningAlg.hash_half_bytes(alg))
    |> Base.url_encode64(padding: false)
  end

  defp missing_hash_error("at_hash"), do: {:error, :missing_at_hash}
  defp missing_hash_error("c_hash"), do: {:error, :missing_c_hash}
  defp missing_hash_error("s_hash"), do: {:error, :missing_s_hash}

  defp hash_error("at_hash"), do: {:error, :invalid_at_hash}
  defp hash_error("c_hash"), do: {:error, :invalid_c_hash}
  defp hash_error("s_hash"), do: {:error, :invalid_s_hash}

  defp non_empty_binary?(value), do: is_binary(value) and value != ""
  defp non_negative_integer?(value), do: is_integer(value) and value >= 0
end
