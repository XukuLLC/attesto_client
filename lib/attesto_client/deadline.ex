defmodule AttestoClient.Deadline do
  @moduledoc false

  @spec run((-> term()) | (map() -> term()), pos_integer(), keyword()) ::
          term() | {:error, :timeout | :not_sent | :operation_failed}
  def run(fun, timeout_ms, opts \\ [])

  def run(fun, timeout_ms, opts)
      when (is_function(fun, 0) or is_function(fun, 1)) and is_integer(timeout_ms) and
             timeout_ms > 0 do
    context = context(timeout_ms, opts)
    caller = self()
    ref = make_ref()

    # The operation runs in its own process so it can be killed at the
    # deadline. `$callers` and `$ancestors` name the caller the way `Task` does,
    # so ownership that follows them (`Req.Test` stubs, Ecto sandbox
    # allowances, Mox) reaches work done inside the deadline.
    callers = [caller | Process.get(:"$callers", [])]
    ancestors = [caller | Process.get(:"$ancestors", [])]

    {pid, monitor} =
      spawn_monitor(fn ->
        Process.put(:"$callers", callers)
        Process.put(:"$ancestors", ancestors)
        worker = self()

        watcher =
          spawn_link(fn ->
            caller_monitor = Process.monitor(caller)

            receive do
              {:deadline_complete, ^worker} -> Process.demonitor(caller_monitor, [:flush])
              {:DOWN, ^caller_monitor, :process, ^caller, _reason} -> exit(:caller_down)
            end
          end)

        result =
          try do
            if is_function(fun, 1), do: fun.(context), else: fun.()
          rescue
            _error -> {:error, :operation_failed}
          catch
            _kind, _reason -> {:error, :operation_failed}
          end

        send(caller, {ref, result})
        send(watcher, {:deadline_complete, self()})
      end)

    receive do
      {^ref, result} ->
        Process.demonitor(monitor, [:flush])
        result

      {:DOWN, ^monitor, :process, ^pid, _reason} ->
        {:error, :operation_failed}
    after
      max(0, context.deadline - System.monotonic_time(:millisecond)) + 50 ->
        Process.exit(pid, :kill)
        await_down(monitor, pid)
        flush_result(ref)
        timeout_result(context)
    end
  end

  def run(_fun, _timeout_ms, _opts), do: {:error, :invalid_timeout}

  # A context belongs to one public operation. Nested requests share delivery
  # state; each deadline narrows the budget explicitly through options.
  def options(opts) do
    Keyword.put_new_lazy(opts, :attesto_context, fn ->
      Process.get({AttestoClient.RefreshCoordinator, :callback_context}) ||
        %{deadline: :infinity, writes: :atomics.new(1, []), phase: :atomics.new(1, [])}
    end)
  end

  def context(timeout_ms, opts \\ []) do
    context = opts |> options() |> Keyword.fetch!(:attesto_context)
    %{context | deadline: min(context.deadline, System.monotonic_time(:millisecond) + timeout_ms)}
  end

  def timeout_result(context) do
    if written(context) == 0 and :atomics.get(context.phase, 1) == 1,
      do: {:error, :not_sent},
      else: {:error, :timeout}
  end

  def not_sent(context, cause) do
    cond do
      written(context) == 0 -> :not_sent
      cause == :deadline_exceeded -> :timeout
      true -> :transport_error
    end
  end

  def written(context), do: :atomics.get(context.writes, 1)
  def connecting(context), do: :atomics.put(context.phase, 1, 1)

  def sending(context, method) do
    :atomics.put(context.phase, 1, 2)
    if method not in [:get, :head], do: :atomics.add(context.writes, 1, 1)
    :ok
  end

  # Only the just-refused attempt is removed, never an earlier accepted write.
  def refused(context, previous) do
    :atomics.compare_exchange(context.writes, 1, previous + 1, previous)
    :ok
  end

  defp await_down(monitor, pid) do
    receive do
      {:DOWN, ^monitor, :process, ^pid, _reason} -> :ok
    after
      1_000 -> Process.demonitor(monitor, [:flush])
    end
  end

  defp flush_result(ref) do
    receive do
      {^ref, _late_result} -> :ok
    after
      0 -> :ok
    end
  end
end
