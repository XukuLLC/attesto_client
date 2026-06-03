defmodule AttestoClient.Builder do
  @moduledoc false
  # Shared internals for building signed client artifacts (client assertions and
  # request objects): key normalisation, fail-fast option validation, algorithm
  # resolution, kid extraction, and JOSE signing. Not part of the public API.

  alias Attesto.SigningAlg

  # An explicit `:alg` may name only a supported asymmetric algorithm (`none`
  # and unknown values are rejected); inherited from attesto so client and server
  # share one allow-list.
  @allowed_algs SigningAlg.allowed()

  @spec to_jose_jwk(JOSE.JWK.t() | map()) :: JOSE.JWK.t()
  def to_jose_jwk(%JOSE.JWK{} = jwk), do: jwk
  def to_jose_jwk(map) when is_map(map), do: JOSE.JWK.from_map(map)

  # A non-empty string option, or `{:error, error}` — a security artifact builder
  # rejects bad input rather than signing it.
  @spec require_string(keyword(), atom(), term()) :: {:ok, String.t()} | {:error, term()}
  def require_string(opts, key, error) do
    case Keyword.get(opts, key) do
      value when is_binary(value) and value != "" -> {:ok, value}
      _ -> {:error, error}
    end
  end

  @spec validate_lifetime(keyword(), pos_integer()) ::
          {:ok, pos_integer()} | {:error, :invalid_lifetime}
  def validate_lifetime(opts, default) do
    case Keyword.fetch(opts, :lifetime) do
      :error -> {:ok, default}
      {:ok, n} when is_integer(n) and n > 0 -> {:ok, n}
      {:ok, _invalid} -> {:error, :invalid_lifetime}
    end
  end

  @spec validate_jti(keyword()) :: {:ok, String.t()} | {:error, :invalid_jti}
  def validate_jti(opts) do
    case Keyword.fetch(opts, :jti) do
      :error -> {:ok, random_jti()}
      {:ok, jti} when is_binary(jti) and jti != "" -> {:ok, jti}
      {:ok, _invalid} -> {:error, :invalid_jti}
    end
  end

  # An explicit `:alg` is honoured only if supported; otherwise the key's natural
  # algorithm is inferred. A key/alg mismatch surfaces later at sign/3. An
  # unsupported key type (e.g. a symmetric `oct` key) - for which inference
  # raises inside attesto - is caught here as {:error, :unsupported_key} so the
  # {:ok | :error} contract holds.
  @spec resolve_alg(JOSE.JWK.t(), keyword()) ::
          {:ok, String.t()} | {:error, :unsupported_alg | :unsupported_key}
  def resolve_alg(jose_jwk, opts) do
    case Keyword.get(opts, :alg) do
      nil -> infer_alg(jose_jwk)
      alg when alg in @allowed_algs -> {:ok, alg}
      _ -> {:error, :unsupported_alg}
    end
  end

  defp infer_alg(jose_jwk) do
    {:ok, SigningAlg.infer(jose_jwk)}
  rescue
    _error -> {:error, :unsupported_key}
  end

  # Add the `kid` header: an explicit `:kid` wins, else the key's own embedded
  # kid (read from a JOSE.JWK struct as well as a raw map), else no kid.
  @spec put_kid(map(), JOSE.JWK.t(), keyword()) :: map()
  def put_kid(header, jose_jwk, opts) do
    case Keyword.get(opts, :kid) || jwk_kid(jose_jwk) do
      nil -> header
      kid -> Map.put(header, "kid", kid)
    end
  end

  @spec now(keyword()) :: integer()
  def now(opts) do
    case Keyword.get(opts, :now) do
      n when is_integer(n) -> n
      _ -> System.system_time(:second)
    end
  end

  # Sign claims under the given protected header, returning the compact JWS. A
  # key/algorithm mismatch (e.g. RS256 with an EC key) raises inside JOSE; it is
  # caught and returned as {:signing_failed, _} so build/2 never raises on input.
  @spec sign(JOSE.JWK.t(), map(), map()) ::
          {:ok, String.t()} | {:error, {:signing_failed, String.t()}}
  def sign(jose_jwk, header, claims) do
    {_protected, compact} = jose_jwk |> JOSE.JWT.sign(header, claims) |> JOSE.JWS.compact()
    {:ok, compact}
  rescue
    error -> {:error, {:signing_failed, Exception.message(error)}}
  end

  defp jwk_kid(%JOSE.JWK{} = jwk) do
    {_type, map} = JOSE.JWK.to_map(jwk)
    Map.get(map, "kid")
  end

  defp random_jti, do: 16 |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false)
end
