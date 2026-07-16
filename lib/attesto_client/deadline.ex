defmodule AttestoClient.Deadline do
  @moduledoc false

  @spec run((-> term()), pos_integer()) :: term() | {:error, :timeout | :operation_failed}
  def run(fun, timeout_ms)
      when is_function(fun, 0) and is_integer(timeout_ms) and timeout_ms > 0 do
    caller = self()
    ref = make_ref()

    {pid, monitor} =
      spawn_monitor(fn ->
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
            fun.()
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
      timeout_ms ->
        Process.exit(pid, :kill)
        await_down(monitor, pid)
        flush_result(ref)
        {:error, :timeout}
    end
  end

  def run(_fun, _timeout_ms), do: {:error, :invalid_timeout}

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
