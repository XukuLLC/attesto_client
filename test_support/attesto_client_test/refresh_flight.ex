defmodule AttestoClient.Test.RefreshFlight do
  @moduledoc false

  # Reads the coordinator's in-flight entry directly: a test has no other way
  # to know that a concurrent caller has joined a refresh before releasing it.

  @spec await_waiters(GenServer.server(), term(), pos_integer(), non_neg_integer()) :: :ok
  def await_waiters(coordinator, key, count, attempts \\ 500) do
    waiters = coordinator |> :sys.get_state() |> Map.fetch!(key) |> Map.fetch!(:waiters)

    cond do
      length(waiters) == count ->
        :ok

      attempts == 0 ->
        raise ExUnit.AssertionError,
          message: "#{count} concurrent callers did not join the shared refresh"

      true ->
        Process.sleep(10)
        await_waiters(coordinator, key, count, attempts - 1)
    end
  end
end
