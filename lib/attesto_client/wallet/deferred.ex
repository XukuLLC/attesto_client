defmodule AttestoClient.Wallet.Deferred do
  @moduledoc false

  alias AttestoClient.Deadline

  @spec validate_options(keyword()) :: :ok | {:error, :invalid_deferred_options}
  def validate_options(opts) do
    with {:ok, _limits} <- limits(opts),
         true <- is_boolean(Keyword.get(opts, :deferred_poll, true)),
         true <- valid_endpoint?(Keyword.get(opts, :deferred_credential_endpoint)),
         timeout when is_integer(timeout) and timeout > 0 <- Keyword.get(opts, :timeout, 10_000) do
      :ok
    else
      _invalid -> {:error, :invalid_deferred_options}
    end
  end

  defp valid_endpoint?(nil), do: true
  defp valid_endpoint?(endpoint), do: is_binary(endpoint) and endpoint != ""

  @spec resolve(map(), keyword(), (String.t(), keyword() -> {:ok, map()} | {:error, term()})) ::
          {:ok, map()} | {:error, term()}
  def resolve(response, opts, request) do
    with :ok <- validate_options(opts) do
      case Map.fetch(response, "transaction_id") do
        :error -> {:ok, response}
        {:ok, transaction_id} -> maybe_poll(response, transaction_id, opts, request)
      end
    end
  end

  defp maybe_poll(response, transaction_id, opts, request) do
    cond do
      not is_binary(transaction_id) or transaction_id == "" ->
        {:error, :invalid_transaction_id}

      Keyword.get(opts, :deferred_poll, true) == false ->
        {:ok, response}

      Keyword.get(opts, :deferred_credential_endpoint) == nil ->
        {:ok, response}

      true ->
        run_poll(response, transaction_id, opts, request)
    end
  end

  defp run_poll(response, transaction_id, opts, request) do
    with {:ok, limits} <- limits(opts) do
      result =
        Deadline.run(
          fn -> poll(response, transaction_id, limits.clock.(), 0, limits, opts, request) end,
          limits.timeout
        )

      case result do
        {:error, :timeout} -> {:error, :deferred_timeout}
        other -> other
      end
    end
  end

  defp limits(opts) do
    limits = %{
      timeout: Keyword.get(opts, :deferred_timeout, 120_000),
      attempts: Keyword.get(opts, :deferred_max_attempts, 10),
      clock: Keyword.get(opts, :deferred_clock, fn -> System.monotonic_time(:millisecond) end),
      sleep: Keyword.get(opts, :deferred_sleep, &Process.sleep/1)
    }

    if valid_limits?(limits), do: {:ok, limits}, else: {:error, :invalid_deferred_options}
  end

  defp valid_limits?(limits),
    do:
      is_integer(limits.timeout) and limits.timeout in 1..3_600_000 and
        is_integer(limits.attempts) and limits.attempts in 1..100 and
        is_function(limits.clock, 0) and is_function(limits.sleep, 1)

  defp poll(response, transaction_id, start, attempts, limits, opts, request) do
    with :ok <- check_transaction(response, transaction_id),
         {:ok, wait} <- interval(response),
         {:ok, remaining} <- remaining(start, limits),
         :ok <- budget(attempts, wait, remaining, limits.attempts),
         :ok <- sleep(limits.sleep, wait),
         {:ok, remaining} <- remaining(start, limits),
         {:ok, next} <- request.(transaction_id, request_opts(opts, remaining)) do
      if Map.has_key?(next, "transaction_id"),
        do: poll(next, transaction_id, start, attempts + 1, limits, opts, request),
        else: {:ok, next}
    end
  end

  defp check_transaction(%{"transaction_id" => id}, id), do: :ok
  defp check_transaction(_response, _id), do: {:error, :deferred_transaction_mismatch}

  defp interval(%{"interval" => seconds}) when is_integer(seconds) and seconds > 0,
    do: {:ok, seconds * 1_000}

  defp interval(_response), do: {:error, :invalid_deferred_interval}

  defp remaining(start, limits) when is_integer(start) do
    now = limits.clock.()

    cond do
      not is_integer(now) or now < start -> {:error, :invalid_deferred_clock}
      now - start >= limits.timeout -> {:error, :deferred_timeout}
      true -> {:ok, limits.timeout - (now - start)}
    end
  end

  defp remaining(_start, _limits), do: {:error, :invalid_deferred_clock}

  defp budget(attempts, _wait, _remaining, maximum) when attempts >= maximum,
    do: {:error, :deferred_attempts_exhausted}

  defp budget(_attempts, wait, remaining, _maximum) when wait >= remaining,
    do: {:error, :deferred_timeout}

  defp budget(_attempts, _wait, _remaining, _maximum), do: :ok

  defp sleep(callback, wait) do
    case callback.(wait) do
      :ok -> :ok
      {:error, reason} -> {:error, {:deferred_sleep, reason}}
      _invalid -> {:error, :invalid_deferred_sleep}
    end
  end

  defp request_opts(opts, remaining),
    do: Keyword.put(opts, :timeout, min(Keyword.get(opts, :timeout, 10_000), remaining))
end
