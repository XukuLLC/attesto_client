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
  @signing_failure_message "signing operation failed"

  # Normalise the client key to a `JOSE.JWK`. A `%JOSE.JWK{}` passes through; a
  # JWK map is parsed, and a malformed/unparseable map (or a non-map) is rejected
  # as {:error, :invalid_key} rather than raising, so the build/2 contract holds.
  @spec normalize_key(JOSE.JWK.t() | map()) :: {:ok, JOSE.JWK.t()} | {:error, :invalid_key}
  def normalize_key(%JOSE.JWK{} = jwk), do: {:ok, jwk}

  def normalize_key(map) when is_map(map) do
    {:ok, JOSE.JWK.from_map(map)}
  rescue
    _error -> {:error, :invalid_key}
  end

  def normalize_key(_other), do: {:error, :invalid_key}

  # A non-empty string option, or `{:error, error}` — a security artifact builder
  # rejects bad input rather than signing it.
  @spec require_string(keyword(), atom(), term()) :: {:ok, String.t()} | {:error, term()}
  def require_string(opts, key, error),
    do: AttestoClient.InputValidation.required_string(opts, key, error)

  # A positive `:lifetime` option (default `default`), optionally capped at `max`
  # (`:infinity` for no cap); anything else is `{:error, :invalid_lifetime}`.
  @spec validate_lifetime(keyword(), pos_integer(), pos_integer() | :infinity) ::
          {:ok, pos_integer()} | {:error, :invalid_lifetime}
  def validate_lifetime(opts, default, max \\ :infinity) do
    case Keyword.fetch(opts, :lifetime) do
      :error -> {:ok, default}
      {:ok, n} when is_integer(n) and n > 0 and (max == :infinity or n <= max) -> {:ok, n}
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
  # algorithm is inferred. The algorithm is bound to the signing key before any
  # claims are signed, including RFC 9864's exact Edwards identifiers. An
  # unsupported key type (e.g. a symmetric `oct` key) - for which inference
  # raises inside attesto - is caught here as {:error, :unsupported_key} so the
  # {:ok | :error} contract holds.
  @spec resolve_alg(JOSE.JWK.t(), keyword()) ::
          {:ok, String.t()}
          | {:error, :unsupported_alg | :unsupported_key | {:signing_failed, String.t()}}
  def resolve_alg(jose_jwk, opts) do
    with {:ok, declared_alg} <- declared_alg(jose_jwk) do
      case Keyword.fetch(opts, :alg) do
        :error -> resolve_default_alg(jose_jwk, declared_alg)
        {:ok, nil} -> resolve_default_alg(jose_jwk, declared_alg)
        {:ok, alg} -> resolve_explicit_alg(jose_jwk, alg, declared_alg)
      end
    end
  end

  defp declared_alg(jose_jwk) do
    {_type, jwk_map} = JOSE.JWK.to_map(jose_jwk)

    case Map.fetch(jwk_map, "alg") do
      :error -> {:ok, nil}
      {:ok, alg} when alg in @allowed_algs -> {:ok, alg}
      {:ok, _invalid} -> {:error, :unsupported_alg}
    end
  end

  defp resolve_default_alg(jose_jwk, nil), do: infer_alg(jose_jwk)
  defp resolve_default_alg(jose_jwk, alg), do: validate_alg_for_key(jose_jwk, alg)

  defp resolve_explicit_alg(jose_jwk, alg, declared_alg)
       when alg in @allowed_algs and declared_alg in [nil, alg],
       do: validate_alg_for_key(jose_jwk, alg)

  defp resolve_explicit_alg(_jose_jwk, _alg, _declared_alg), do: {:error, :unsupported_alg}

  defp infer_alg(jose_jwk) do
    alg = SigningAlg.infer(jose_jwk)
    {:ok, SigningAlg.validate_for_key!(alg, jose_jwk)}
  rescue
    _error -> {:error, :unsupported_key}
  end

  defp validate_alg_for_key(jose_jwk, alg) do
    {:ok, SigningAlg.validate_for_key!(alg, jose_jwk)}
  rescue
    _error -> {:error, {:signing_failed, @signing_failure_message}}
  end

  # Resolve the `kid` header: an explicit `:kid` wins, else the key's own
  # embedded kid (read from a JOSE.JWK struct as well as a raw map), else no
  # kid. A present value must be a non-empty string; accepting arbitrary JSON
  # here produces artifacts that peers cannot reliably select by key id.
  @spec resolve_kid(JOSE.JWK.t(), keyword()) ::
          {:ok, String.t() | nil} | {:error, :invalid_kid}
  def resolve_kid(jose_jwk, opts) do
    case Keyword.fetch(opts, :kid) do
      {:ok, explicit} -> validate_present_kid(explicit)
      :error -> resolve_embedded_kid(jose_jwk)
    end
  end

  defp validate_present_kid(value) when is_binary(value) and value != "", do: {:ok, value}
  defp validate_present_kid(_invalid), do: {:error, :invalid_kid}

  defp resolve_embedded_kid(jose_jwk) do
    {_type, jwk_map} = JOSE.JWK.to_map(jose_jwk)

    case Map.fetch(jwk_map, "kid") do
      :error -> {:ok, nil}
      {:ok, value} -> validate_present_kid(value)
    end
  end

  @spec put_kid(map(), String.t() | nil) :: map()
  def put_kid(header, nil), do: header
  def put_kid(header, kid) when is_binary(kid), do: Map.put(header, "kid", kid)

  # A present `:now` must be a non-negative NumericDate (RFC 7519 §2).
  @spec validate_now(keyword()) :: {:ok, non_neg_integer()} | {:error, :invalid_time}
  def validate_now(opts) do
    case Keyword.fetch(opts, :now) do
      :error -> {:ok, System.system_time(:second)}
      {:ok, n} when is_integer(n) and n >= 0 -> {:ok, n}
      {:ok, _invalid} -> {:error, :invalid_time}
    end
  end

  # The public JWK map for embedding in a JOSE header (`jwk`) or `cnf`.
  @spec public_jwk(JOSE.JWK.t()) :: map()
  def public_jwk(jose_jwk) do
    {_type, map} = JOSE.JWK.to_public_map(jose_jwk)
    map
  end

  @doc false
  @spec public_jwk_result(JOSE.JWK.t(), atom()) :: {:ok, map()} | {:error, atom()}
  def public_jwk_result(jose_jwk, error \\ :invalid_key) when is_atom(error) do
    {:ok, public_jwk(jose_jwk)}
  rescue
    _error -> {:error, error}
  catch
    _kind, _reason -> {:error, error}
  end

  # Validate an optional `x5c` chain before adding it to a protected header.
  # Each entry is serialized as a JSON string; rejecting empty and mixed lists
  # avoids silently dropping a caller typo or emitting a malformed JOSE header.
  @spec validate_x5c(keyword()) :: {:ok, [String.t()] | nil} | {:error, :invalid_x5c}
  def validate_x5c(opts) do
    case Keyword.fetch(opts, :x5c) do
      :error ->
        {:ok, nil}

      {:ok, [_ | _] = x5c} ->
        if Enum.all?(x5c, &(is_binary(&1) and &1 != "")),
          do: {:ok, x5c},
          else: {:error, :invalid_x5c}

      {:ok, _invalid} ->
        {:error, :invalid_x5c}
    end
  end

  # Add a previously validated `x5c` header.
  @spec put_x5c(map(), term()) :: map()
  def put_x5c(header, [_ | _] = x5c), do: Map.put(header, "x5c", x5c)
  def put_x5c(header, nil), do: header

  # Sign claims under the given protected header, returning the compact JWS.
  # Key/algorithm compatibility is checked before this point; backend failures
  # are still caught and returned as {:signing_failed, _} so build/2 does not
  # raise on input.
  @spec sign(JOSE.JWK.t(), map(), map()) ::
          {:ok, String.t()} | {:error, {:signing_failed, String.t()}}
  def sign(jose_jwk, header, claims) do
    protected =
      if header["alg"] in ~w(PS256 PS384 PS512),
        do: Map.put_new(header, "typ", "JWT"),
        else: header

    {:ok, Attesto.JWS.sign_compact_jwk(jose_jwk, protected, claims)}
  rescue
    _error -> {:error, {:signing_failed, @signing_failure_message}}
  end

  defp random_jti, do: Attesto.Secret.generate(16)
end
