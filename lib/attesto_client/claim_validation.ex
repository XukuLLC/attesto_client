defmodule AttestoClient.ClaimValidation do
  @moduledoc false

  alias Attesto.{Claims, NumericDate}

  @type result :: :ok | {:error, atom()}

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
        if NumericDate.not_expired?(exp, now),
          do: :ok,
          else: error_result(opts, :expired_error)
    end
  end

  @spec issued_at(map(), integer(), keyword()) :: result()
  def issued_at(claims, now, opts) when is_map(claims) and is_integer(now) and is_list(opts) do
    temporal_upper_bound(claims, "iat", now, opts)
  end

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
