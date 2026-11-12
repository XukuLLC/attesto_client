defmodule AttestoClient.ClaimValidation do
  @moduledoc false

  alias Attesto.{Claims, NumericDate}

  @type result :: :ok | {:error, atom()}

  # RFC 7519 §4.1.4 allows "some small leeway, usually no more than a few
  # minutes". Every caller-supplied time tolerance in this package is bounded by
  # the same ceiling.
  @max_tolerance_seconds 300

  @doc "The largest time tolerance, in seconds, a caller may configure."
  @spec max_tolerance_seconds() :: pos_integer()
  def max_tolerance_seconds, do: @max_tolerance_seconds

  @doc """
  Read a time tolerance option: an integer from `0` to
  `max_tolerance_seconds/0`. An absent or `nil` option is `default`.
  """
  @spec tolerance(keyword(), atom(), non_neg_integer()) :: {:ok, non_neg_integer()} | :error
  def tolerance(opts, key, default) when is_list(opts) and is_atom(key) do
    case Keyword.get(opts, key) do
      nil ->
        {:ok, default}

      seconds when is_integer(seconds) and seconds >= 0 and seconds <= @max_tolerance_seconds ->
        {:ok, seconds}

      _invalid ->
        :error
    end
  end

  @spec audience(map(), String.t() | [String.t()], atom()) :: result()
  def audience(claims, expected, error) when is_map(claims) and is_atom(error) do
    if Claims.audience_matches?(Map.get(claims, "aud"), expected, :array),
      do: :ok,
      else: {:error, error}
  end

  @spec expiration(map(), integer(), keyword()) :: result()
  def expiration(claims, now, opts) when is_map(claims) and is_integer(now) and is_list(opts) do
    case NumericDate.fetch(claims, "exp", required: false, non_negative: false) do
      :missing ->
        missing_result(opts)

      {:error, :invalid} ->
        error_result(opts, :invalid_error)

      {:ok, exp} ->
        if NumericDate.not_expired?(exp, now, leeway: Keyword.get(opts, :leeway, 0)),
          do: :ok,
          else: error_result(opts, :expired_error)
    end
  end

  @spec issued_at(map(), integer(), keyword()) :: result()
  def issued_at(claims, now, opts) when is_map(claims) and is_integer(now) and is_list(opts) do
    temporal_upper_bound(claims, "iat", now, opts)
  end

  @doc """
  Reject a token issued longer ago than `max_age` seconds, widened by `skew`.

  `iat` is an already-validated NumericDate. A `nil` `max_age` checks nothing.
  `opts` names the `:too_old_error` and the `:invalid_error` returned for a
  `max_age` that is not a non-negative integer.
  """
  @spec issued_within(integer(), integer(), term(), non_neg_integer(), keyword()) :: result()
  def issued_within(_iat, _now, nil, _skew, _opts), do: :ok

  def issued_within(iat, now, max_age, skew, opts)
      when is_integer(iat) and is_integer(now) and is_integer(max_age) and max_age >= 0 and
             is_integer(skew) and is_list(opts) do
    if now - iat <= max_age + skew, do: :ok, else: error_result(opts, :too_old_error)
  end

  def issued_within(_iat, _now, _invalid, _skew, opts), do: error_result(opts, :invalid_error)

  @spec not_before(map(), integer(), keyword()) :: result()
  def not_before(claims, now, opts) when is_map(claims) and is_integer(now) and is_list(opts) do
    temporal_upper_bound(claims, "nbf", now, opts)
  end

  defp temporal_upper_bound(claims, key, now, opts) do
    non_negative? = Keyword.get(opts, :non_negative, true)

    case NumericDate.fetch(claims, key, required: false, non_negative: non_negative?) do
      :missing ->
        missing_result(opts)

      {:error, :invalid} ->
        error_result(opts, :invalid_error)

      {:ok, value} ->
        if NumericDate.not_before_reached?(value, now, skew: Keyword.get(opts, :skew, 60)),
          do: :ok,
          else: error_result(opts, :future_error)
    end
  end

  defp missing_result(opts) do
    case Keyword.get(opts, :missing_error) do
      nil -> :ok
      error when is_atom(error) -> {:error, error}
    end
  end

  defp error_result(opts, key), do: {:error, Keyword.fetch!(opts, key)}
end
