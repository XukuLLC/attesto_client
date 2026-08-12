defmodule AttestoClient.Verifier do
  @moduledoc false

  alias Attesto.SigningAlg
  alias AttestoClient.Discovery

  @minimum_rsa_bits 2048

  @type jwks :: %{optional(String.t()) => term()} | [map()] | map()

  @spec require_string(keyword(), atom(), term()) :: {:ok, String.t()} | {:error, term()}
  def require_string(opts, key, error) do
    case Keyword.get(opts, key) do
      value when is_binary(value) and value != "" -> {:ok, value}
      _ -> {:error, error}
    end
  end

  @spec now(keyword()) :: non_neg_integer()
  def now(opts) do
    case Keyword.get(opts, :now) do
      %DateTime{} = dt -> DateTime.to_unix(dt, :second)
      n when is_integer(n) -> n
      _ -> System.system_time(:second)
    end
  end

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
             | :unsupported_critical_header
             | :invalid_signature
             | :ambiguous_key
             | :weak_key}
  def verify_signature(jwt, keys, accepted_algs, opts \\ [])

  def verify_signature(jwt, keys, accepted_algs, opts)
      when is_binary(jwt) and is_list(keys) and is_list(accepted_algs) and is_list(opts) do
    with :ok <- check_compact_form(jwt),
         {:ok, header} <- peek_header(jwt),
         :ok <- check_crit(header),
         {:ok, candidates} <- candidates(keys, header, accepted_algs, opts),
         {:ok, claims, verified_jwk} <- verify_against_any(jwt, candidates) do
      {:ok, claims, header, verified_jwk}
    end
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
    with :ok <- check_compact_form(jwt),
         {:ok, %{"alg" => "none"} = header} <- peek_header(jwt),
         :ok <- check_crit_result(header),
         [_header, payload, ""] <- String.split(jwt, "."),
         {:ok, decoded} <- Base.url_decode64(payload, padding: false),
         {:ok, %{} = claims} <- JSON.decode(decoded) do
      {:ok, claims, header}
    else
      _other -> {:error, :invalid_token}
    end
  end

  def decode_unsigned(_jwt), do: {:error, :invalid_token}

  defp check_crit_result(header) do
    case check_crit(header) do
      :ok -> :ok
      {:error, _reason} -> :error
    end
  end

  @spec normalize_jwks(jwks()) :: {:ok, [map()]} | {:error, :invalid_jwks}
  def normalize_jwks(%{"keys" => keys}) when is_list(keys), do: normalize_jwks(keys)

  def normalize_jwks(keys) when is_list(keys) do
    if Enum.all?(keys, &is_map/1), do: {:ok, keys}, else: {:error, :invalid_jwks}
  end

  def normalize_jwks(%{} = jwk), do: {:ok, [jwk]}
  def normalize_jwks(_other), do: {:error, :invalid_jwks}

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
        jwks_uri_from_metadata(Keyword.fetch!(opts, :metadata), issuer)

      true ->
        with {:ok, metadata} <- Discovery.fetch(issuer, discovery_opts(opts)) do
          jwks_uri_from_metadata(metadata, issuer)
        end
    end
  end

  defp jwks_uri_from_metadata(%{"issuer" => issuer, "jwks_uri" => jwks_uri}, issuer)
       when is_binary(jwks_uri) and jwks_uri != "" do
    {:ok, jwks_uri}
  end

  defp jwks_uri_from_metadata(%{"issuer" => _other}, _issuer), do: {:error, :issuer_mismatch}
  defp jwks_uri_from_metadata(_metadata, _issuer), do: {:error, :invalid_metadata}

  defp discovery_opts(opts) do
    opts
    |> Keyword.take([:well_known, :req_options])
    |> Enum.reject(fn {_key, value} -> is_nil(value) end)
  end

  defp check_compact_form(jwt) do
    case String.split(jwt, ".") do
      [_, _, _] = segments ->
        if Enum.all?(segments, &canonical_base64url?/1),
          do: :ok,
          else: {:error, :invalid_token}

      _other ->
        {:error, :invalid_token}
    end
  end

  defp canonical_base64url?(segment) do
    case Base.url_decode64(segment, padding: false) do
      {:ok, decoded} -> Base.url_encode64(decoded, padding: false) == segment
      :error -> false
    end
  end

  @doc false
  @spec peek_header(String.t()) :: {:ok, map()} | {:error, :invalid_token}
  def peek_header(jwt) do
    with [header, _payload, _signature] <- String.split(jwt, ".", parts: 3),
         {:ok, decoded} <- Base.url_decode64(header, padding: false),
         {:ok, %{} = map} <- JSON.decode(decoded) do
      {:ok, map}
    else
      _ -> {:error, :invalid_token}
    end
  end

  defp check_crit(header) do
    if Map.has_key?(header, "crit"), do: {:error, :unsupported_critical_header}, else: :ok
  end

  defp candidates(keys, %{"alg" => alg} = header, accepted_algs, opts) when is_binary(alg) do
    if alg in accepted_algs do
      candidates =
        keys
        |> filter_by_kid(Map.get(header, "kid"))
        |> Enum.filter(&verification_key?/1)
        |> Enum.flat_map(&candidate(&1, [alg]))

      case candidates do
        [] -> {:error, :invalid_signature}
        [candidate] -> validate_key_policy(candidate, opts)
        _multiple -> {:error, :ambiguous_key}
      end
    else
      {:error, :invalid_signature}
    end
  end

  defp candidates(_keys, _header, _accepted_algs, _opts), do: {:error, :invalid_signature}

  # A `kid` must resolve to exactly one eligible key. When the token omits a
  # `kid`, verification remains interoperable with a JWKS containing exactly
  # one eligible signing key, but never guesses between multiple keys.
  defp filter_by_kid(keys, nil), do: keys

  defp filter_by_kid(keys, kid), do: Enum.filter(keys, &(Map.get(&1, "kid") == kid))

  defp verification_key?(key) do
    use_allows_verification? =
      case Map.fetch(key, "use") do
        :error -> true
        {:ok, "sig"} -> true
        {:ok, _invalid} -> false
      end

    operations_allow_verification? =
      case Map.fetch(key, "key_ops") do
        :error ->
          true

        {:ok, operations} when is_list(operations) ->
          Enum.all?(operations, &is_binary/1) and "verify" in operations

        {:ok, _invalid} ->
          false
      end

    use_allows_verification? and operations_allow_verification?
  end

  defp usable_verification_key?(key, accepted_algs) do
    verification_key?(key) and
      key
      |> candidate(accepted_algs)
      |> Enum.any?(&match?({:ok, _candidates}, validate_key_strength(&1)))
  end

  defp candidate(key_map, accepted_algs) do
    # Bound RSA `n` and `e` on their raw base64url strings before JOSE turns
    # them into bignums. A remote JWKS (or a token-selected key within it) is
    # attacker-influenceable; decoding and verifying with a multi-hundred-KB
    # exponent can pin a scheduler for seconds per request.
    if !SigningAlg.rsa_params_ok?(key_map) do
      raise ArgumentError, "RSA verification key parameters are out of safe bounds"
    end

    jwk = JOSE.JWK.from_map(key_map)

    algs =
      key_map
      |> key_algs(jwk)
      |> Enum.filter(&(&1 in accepted_algs))

    case algs do
      [] -> []
      [_ | _] -> [{Map.get(key_map, "kid"), algs, jwk, key_map}]
    end
  rescue
    _error -> []
  end

  defp validate_key_strength({_kid, _algs, _jwk, %{"kty" => "RSA", "n" => modulus}} = candidate)
       when is_binary(modulus) do
    case Base.url_decode64(modulus, padding: false) do
      {:ok, bytes} ->
        if modulus_bits(bytes) >= @minimum_rsa_bits,
          do: {:ok, [candidate]},
          else: {:error, :weak_key}

      :error ->
        {:error, :invalid_signature}
    end
  end

  defp validate_key_strength({_kid, _algs, _jwk, %{"kty" => "RSA"}}),
    do: {:error, :invalid_signature}

  defp validate_key_strength(candidate), do: {:ok, [candidate]}

  defp modulus_bits(bytes) do
    bytes
    |> :binary.decode_unsigned()
    |> Integer.digits(2)
    |> length()
  end

  defp key_algs(%{"alg" => alg}, jwk), do: [SigningAlg.validate_for_key!(alg, jwk)]

  defp key_algs(_key_map, jwk), do: compatible_algs(jwk)

  defp compatible_algs(jwk) do
    case public_fields(jwk) do
      %{"kty" => "RSA"} -> ~w(RS256 PS256)
      %{"kty" => "EC", "crv" => "P-256"} -> ["ES256"]
      %{"kty" => "EC", "crv" => "P-384"} -> ["ES384"]
      %{"kty" => "EC", "crv" => "P-521"} -> ["ES512"]
      %{"kty" => "OKP", "crv" => "Ed25519"} -> ~w(EdDSA Ed25519)
      %{"kty" => "OKP", "crv" => "Ed448"} -> ~w(EdDSA Ed448)
      _other -> []
    end
  end

  defp validate_key_policy(candidate, opts) do
    with {:ok, candidates} <- validate_key_strength(candidate),
         :ok <- validate_fapi_key_policy(candidate, opts) do
      {:ok, candidates}
    end
  end

  defp validate_fapi_key_policy({_kid, [alg], jwk, _map}, opts) do
    if Keyword.get(opts, :enforce_fapi_alg_policy, false) do
      if SigningAlg.fapi_compatible?(alg, jwk),
        do: :ok,
        else: {:error, :invalid_signature}
    else
      :ok
    end
  end

  defp public_fields(jwk) do
    jwk
    |> JOSE.JWK.to_public_map()
    |> elem(1)
  end

  defp verify_against_any(jwt, candidates) do
    Enum.reduce_while(candidates, {:error, :invalid_signature}, fn {_kid, algs, jwk, _map}, acc ->
      case JOSE.JWT.verify_strict(jwk, algs, jwt) do
        {true, %JOSE.JWT{fields: claims}, %JOSE.JWS{}} -> {:halt, {:ok, claims, jwk}}
        {false, _jwt_struct, _jws_struct} -> {:cont, acc}
        _other -> {:halt, {:error, :invalid_token}}
      end
    end)
  rescue
    _error -> {:error, :invalid_token}
  end
end
