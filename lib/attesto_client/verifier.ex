defmodule AttestoClient.Verifier do
  @moduledoc false

  alias Attesto.SigningAlg
  alias AttestoClient.Discovery

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

  @spec verify_signature(String.t(), [map()], [SigningAlg.alg()]) ::
          {:ok, map(), map()}
          | {:error,
             :invalid_token
             | :unsupported_critical_header
             | :invalid_signature}
  def verify_signature(jwt, keys, accepted_algs)
      when is_binary(jwt) and is_list(keys) and is_list(accepted_algs) do
    with :ok <- check_compact_form(jwt),
         {:ok, header} <- peek_header(jwt),
         :ok <- check_crit(header),
         {:ok, claims} <- verify_against_any(jwt, candidates(keys, header, accepted_algs)) do
      {:ok, claims, header}
    end
  end

  def verify_signature(_jwt, _keys, _accepted_algs), do: {:error, :invalid_token}

  @spec normalize_jwks(jwks()) :: {:ok, [map()]} | {:error, :invalid_jwks}
  def normalize_jwks(%{"keys" => keys}) when is_list(keys), do: normalize_jwks(keys)

  def normalize_jwks(keys) when is_list(keys) do
    if Enum.all?(keys, &is_map/1), do: {:ok, keys}, else: {:error, :invalid_jwks}
  end

  def normalize_jwks(%{} = jwk), do: {:ok, [jwk]}
  def normalize_jwks(_other), do: {:error, :invalid_jwks}

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

  defp peek_header(jwt) do
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

  defp candidates(keys, header, accepted_algs) do
    keys
    |> filter_by_kid(Map.get(header, "kid"))
    |> Enum.flat_map(&candidate(&1, accepted_algs))
  end

  defp filter_by_kid(keys, nil), do: keys

  defp filter_by_kid(keys, kid), do: Enum.filter(keys, &(Map.get(&1, "kid") == kid))

  defp candidate(key_map, accepted_algs) do
    jwk = JOSE.JWK.from_map(key_map)

    algs =
      key_map
      |> key_algs(jwk)
      |> Enum.filter(&(&1 in accepted_algs))

    case algs do
      [] -> []
      [_ | _] -> [{Map.get(key_map, "kid"), algs, jwk}]
    end
  rescue
    _error -> []
  end

  defp key_algs(%{"alg" => alg}, jwk) do
    alg = SigningAlg.validate!(alg)

    if alg in compatible_algs(jwk), do: [alg], else: []
  end

  defp key_algs(_key_map, jwk), do: compatible_algs(jwk)

  defp compatible_algs(jwk) do
    case SigningAlg.infer(jwk) do
      "RS256" -> ~w(RS256 PS256)
      alg -> [alg]
    end
  end

  defp verify_against_any(_jwt, []), do: {:error, :invalid_signature}

  defp verify_against_any(jwt, candidates) do
    Enum.reduce_while(candidates, {:error, :invalid_signature}, fn {_kid, algs, jwk}, acc ->
      case JOSE.JWT.verify_strict(jwk, algs, jwt) do
        {true, %JOSE.JWT{fields: claims}, %JOSE.JWS{}} -> {:halt, {:ok, claims}}
        {false, _jwt_struct, _jws_struct} -> {:cont, acc}
        _other -> {:halt, {:error, :invalid_token}}
      end
    end)
  rescue
    _error -> {:error, :invalid_token}
  end
end
