defmodule AttestoClient.Verifier do
  @moduledoc false

  alias Attesto.{JWS, NumericDate, SigningAlg}
  alias AttestoClient.Discovery

  @minimum_rsa_bits 2048

  @type compact_segments :: {binary(), binary(), binary()}

  @type jwks :: %{optional(String.t()) => term()} | [map()] | map()

  @spec require_string(keyword(), atom(), term()) :: {:ok, String.t()} | {:error, term()}
  def require_string(opts, key, error),
    do: AttestoClient.InputValidation.required_string(opts, key, error)

  @spec now(keyword()) :: non_neg_integer()
  def now(opts), do: NumericDate.now(opts, default: :system, invalid_override: :fallback)

  @spec accepted_algs(keyword(), [SigningAlg.alg()]) ::
          {:ok, [SigningAlg.alg()]} | {:error, :unsupported_alg}
  def accepted_algs(opts, default \\ SigningAlg.allowed()) do
    case Keyword.get(opts, :accepted_algs) do
      nil ->
        {:ok, default}

      algs when is_list(algs) and algs != [] ->
        if Enum.all?(algs, &(&1 in SigningAlg.allowed())),
          do: {:ok, algs},
          else: {:error, :unsupported_alg}

      _other ->
        {:error, :unsupported_alg}
    end
  end

  @spec resolve_jwks(keyword(), String.t()) ::
          {:ok, [map()]}
          | {:error,
             :invalid_jwks
             | :invalid_metadata
             | :issuer_mismatch
             | Discovery.error()}
  def resolve_jwks(opts, issuer) do
    case Keyword.fetch(opts, :jwks) do
      {:ok, jwks} -> normalize_jwks(jwks)
      :error -> fetch_jwks(opts, issuer)
    end
  end

  @spec verify_signature(String.t(), [map()], [SigningAlg.alg()], keyword()) ::
          {:ok, map(), map(), JOSE.JWK.t()}
          | {:error,
             :invalid_token
             | :unsupported_alg
             | :unsupported_critical_header
             | :invalid_signature
             | :ambiguous_key
             | :weak_key}
  def verify_signature(jwt, keys, accepted_algs, opts \\ [])

  def verify_signature(jwt, keys, accepted_algs, opts)
      when is_binary(jwt) and is_list(keys) and is_list(accepted_algs) and is_list(opts) do
    with {:ok, header} <-
           JWS.protected_header(jwt,
             error: :invalid_token,
             crit_error: :unsupported_critical_header
           ),
         :ok <- check_algorithm(header, accepted_algs),
         {:ok, candidate} <- verification_candidate(keys, header, accepted_algs, opts),
         {:ok, claims, {_kid, _alg, verified_jwk}} <-
           JWS.verify_strict(jwt, [candidate],
             accepted_algs: accepted_algs,
             fapi?: Keyword.get(opts, :enforce_fapi_alg_policy, false),
             terminal_error: :invalid_signature,
             malformed_error: :invalid_token,
             malformed_result: :halt,
             claims_map?: true,
             return_key?: true
           ) do
      {:ok, claims, header, verified_jwk}
    end
  rescue
    _error -> {:error, :invalid_token}
  catch
    _kind, _reason -> {:error, :invalid_token}
  end

  def verify_signature(_jwt, _keys, _accepted_algs, _opts), do: {:error, :invalid_token}

  @doc """
  True when `jwt` parses as a compact JWS whose JOSE header `alg` is `"none"`.
  """
  @spec unsigned?(String.t()) :: boolean()
  def unsigned?(jwt) when is_binary(jwt) do
    match?({:ok, %{"alg" => "none"}}, peek_header(jwt))
  end

  def unsigned?(_jwt), do: false

  @doc """
  Decode an **unsigned** (`alg: "none"`) JWT without signature verification,
  returning `{:ok, claims, header}`.

  The compact form must be canonical, the header `alg` must be exactly
  `"none"`, and the signature part must be empty (RFC 7519 §6.1) - a token
  that carries a signature alongside `alg: "none"` is rejected. Callers gate
  this behind an explicit opt-in; it exists for the OIDC Core §3.1.3.7 case
  where a code-flow client registered `id_token_signed_response_alg` `none`
  and TLS server authentication stands in for the signature.
  """
  @spec decode_unsigned(String.t()) :: {:ok, map(), map()} | {:error, :invalid_token}
  def decode_unsigned(jwt) when is_binary(jwt) do
    with {:ok, %{signature_segment: ""}} <-
           JWS.decode_compact(jwt, canonical: true, allow_empty_signature: true),
         {:ok, %{"alg" => "none"} = header} <-
           JWS.protected_header(jwt,
             canonical: true,
             allow_empty_signature: true,
             error: :invalid_token,
             crit_error: :invalid_token
           ),
         {:ok, claims} <- JWS.peek_json(jwt, :payload, canonical: true) do
      {:ok, claims, header}
    else
      _other -> {:error, :invalid_token}
    end
  end

  def decode_unsigned(_jwt), do: {:error, :invalid_token}

  @spec normalize_jwks(jwks()) :: {:ok, [map()]} | {:error, :invalid_jwks}
  def normalize_jwks(%{"keys" => keys}) when is_list(keys), do: normalize_jwks(keys)
  def normalize_jwks(%{"keys" => _invalid}), do: {:error, :invalid_jwks}

  def normalize_jwks([_ | _] = keys) do
    if Enum.all?(keys, &plain_nonempty_map?/1),
      do: {:ok, keys},
      else: {:error, :invalid_jwks}
  end

  def normalize_jwks([]), do: {:error, :invalid_jwks}

  def normalize_jwks(%{} = jwk) do
    if plain_nonempty_map?(jwk), do: {:ok, [jwk]}, else: {:error, :invalid_jwks}
  end

  def normalize_jwks(_other), do: {:error, :invalid_jwks}

  defp plain_nonempty_map?(value),
    do: is_map(value) and not is_struct(value) and map_size(value) > 0

  @doc false
  @spec validate_verification_keys([map()], [SigningAlg.alg()]) ::
          :ok | {:error, :invalid_jwks}
  def validate_verification_keys(keys, accepted_algs)
      when is_list(keys) and is_list(accepted_algs) do
    if Enum.any?(keys, &usable_verification_key?(&1, accepted_algs)),
      do: :ok,
      else: {:error, :invalid_jwks}
  end

  defp fetch_jwks(opts, issuer) do
    with {:ok, jwks_uri} <- jwks_uri(opts, issuer),
         {:ok, jwks} <- Discovery.fetch_jwks(jwks_uri, discovery_opts(opts)) do
      normalize_jwks(jwks)
    end
  end

  defp jwks_uri(opts, issuer) do
    cond do
      is_binary(Keyword.get(opts, :jwks_uri)) ->
        {:ok, Keyword.fetch!(opts, :jwks_uri)}

      is_map(Keyword.get(opts, :metadata)) ->
        Discovery.jwks_uri(Keyword.fetch!(opts, :metadata), issuer)

      true ->
        with {:ok, metadata} <- Discovery.fetch(issuer, discovery_opts(opts)) do
          Discovery.jwks_uri(metadata, issuer)
        end
    end
  end

  defp discovery_opts(opts) do
    opts
    |> Keyword.take([:well_known, :req_options, :resolver, :max_response_bytes, :timeout])
    |> Enum.reject(fn {_key, value} -> is_nil(value) end)
  end

  @doc false
  @spec peek_header(String.t()) :: {:ok, map()} | {:error, :invalid_token}
  def peek_header(jwt) do
    case JWS.peek_json(jwt, :protected, canonical: true) do
      {:ok, header} -> {:ok, header}
      {:error, _reason} -> {:error, :invalid_token}
    end
  end

  defp usable_verification_key?(key, accepted_algs) do
    strict_key_metadata?(key) and
      Enum.any?(accepted_algs, fn alg ->
        match?(
          [_],
          JWS.verification_candidates(
            [key],
            candidate_opts(alg, accepted_algs, [], @minimum_rsa_bits)
          )
        )
      end)
  end

  defp check_algorithm(%{"alg" => alg}, accepted_algs) when is_binary(alg),
    do: if(alg in accepted_algs, do: :ok, else: {:error, :unsupported_alg})

  defp check_algorithm(_header, _accepted_algs), do: {:error, :invalid_signature}

  defp verification_candidate(keys, %{"alg" => alg} = header, accepted_algs, opts) do
    key_policy_opts = Keyword.put(opts, :enforce_fapi_alg_policy, false)

    selection_opts =
      candidate_opts(alg, accepted_algs, key_policy_opts, nil, Map.get(header, "kid"))

    strict_keys = Enum.filter(keys, &strict_key_metadata?/1)

    case JWS.verification_candidates(strict_keys, selection_opts) do
      [] ->
        {:error, :invalid_signature}

      [_one, _two | _rest] ->
        {:error, :ambiguous_key}

      [_candidate] ->
        strong_opts = Keyword.put(selection_opts, :min_rsa_bits, @minimum_rsa_bits)

        case JWS.verification_candidates(strict_keys, strong_opts) do
          [candidate] -> enforce_candidate_policy(candidate, strict_keys, strong_opts, opts)
          [] -> {:error, :weak_key}
        end
    end
  end

  defp enforce_candidate_policy(candidate, keys, selection_opts, opts) do
    if Keyword.get(opts, :enforce_fapi_alg_policy, false) do
      case JWS.verification_candidates(keys, Keyword.put(selection_opts, :fapi?, true)) do
        [_candidate] -> {:ok, candidate}
        [] -> {:error, :invalid_signature}
      end
    else
      {:ok, candidate}
    end
  end

  # Core treats an explicit JSON null like an absent optional JWK member. The
  # client historically rejects present-but-null `use`/`alg`/`key_ops` and
  # non-string key operations, so retain that stricter remote-JWKS boundary
  # before handing candidate construction and cryptographic checks to core.
  defp strict_key_metadata?(key) do
    optional_sig_use?(Map.fetch(key, "use")) and
      optional_alg?(Map.fetch(key, "alg")) and
      optional_verify_ops?(Map.fetch(key, "key_ops"))
  end

  defp optional_sig_use?(:error), do: true
  defp optional_sig_use?({:ok, "sig"}), do: true
  defp optional_sig_use?(_other), do: false

  defp optional_alg?(:error), do: true
  defp optional_alg?({:ok, alg}), do: is_binary(alg) and alg != ""

  defp optional_verify_ops?(:error), do: true

  defp optional_verify_ops?({:ok, ops}) when is_list(ops),
    do: Enum.all?(ops, &is_binary/1) and "verify" in ops

  defp optional_verify_ops?(_other), do: false

  defp candidate_opts(alg, accepted_algs, opts, minimum_bits, kid \\ nil) do
    [
      alg: alg,
      accepted_algs: accepted_algs,
      fapi?: Keyword.get(opts, :enforce_fapi_alg_policy, false),
      kid: kid,
      min_rsa_bits: minimum_bits,
      ambiguous_kid: :allow,
      malformed_key: :skip
    ]
  end
end
