defmodule AttestoClient.RefreshCoordinator do
  @moduledoc """
  Single-flight coordinator for refresh-token rotation.

  Concurrent refreshes for the same application-supplied key share exactly one
  operation and receive the same result. Different keys run independently. A
  deadline kills a stuck operation, wakes every waiter, and clears the key for
  a later attempt.

  The key should identify the application's token record without containing a
  token secret. This process does not store token sets after an operation;
  callers must atomically persist successful rotation results according to
  their own retention policy.
  """

  use GenServer

  @type option :: GenServer.option()

  @spec start_link([option()]) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, :ok, opts)
  end

  @doc """
  Run `fun` once for `key`, sharing its result with concurrent callers.
  """
  @spec run(GenServer.server(), term(), (-> term()), pos_integer()) :: term()
  def run(server, key, fun, timeout_ms)
      when is_function(fun, 0) and is_integer(timeout_ms) and timeout_ms > 0 do
    GenServer.call(server, {:run, key, fun, timeout_ms}, timeout_ms + 1_000)
  catch
    :exit, {:timeout, _call} -> {:error, :timeout}
    :exit, reason -> {:error, {:coordinator_exit, reason}}
  end

  def run(_server, _key, _fun, _timeout_ms), do: {:error, :invalid_timeout}

  @impl true
  def init(:ok) do
    Process.flag(:trap_exit, true)
    {:ok, %{}}
  end

  @impl true
  def handle_call({:run, key, fun, timeout_ms}, from, inflight) do
    case Map.fetch(inflight, key) do
      {:ok, entry} ->
        {:noreply, Map.put(inflight, key, %{entry | waiters: [from | entry.waiters]})}

      :error ->
        parent = self()

        {pid, monitor} =
          :erlang.spawn_opt(
            fn ->
              result =
                try do
                  fun.()
                rescue
                  _error -> {:error, :operation_failed}
                catch
                  _kind, _reason -> {:error, :operation_failed}
                end

              send(parent, {:refresh_result, key, self(), result})
            end,
            [:link, :monitor]
          )

        timer = Process.send_after(self(), {:refresh_timeout, key, pid}, timeout_ms)
        entry = %{pid: pid, monitor: monitor, timer: timer, waiters: [from]}
        {:noreply, Map.put(inflight, key, entry)}
    end
  end

  @impl true
  def handle_info({:refresh_result, key, pid, result}, inflight) do
    case Map.fetch(inflight, key) do
      {:ok, %{pid: ^pid} = entry} ->
        Process.cancel_timer(entry.timer)
        Process.demonitor(entry.monitor, [:flush])
        reply_all(entry.waiters, result)
        {:noreply, Map.delete(inflight, key)}

      _stale ->
        {:noreply, inflight}
    end
  end

  def handle_info({:refresh_timeout, key, pid}, inflight) do
    case Map.fetch(inflight, key) do
      {:ok, %{pid: ^pid} = entry} ->
        Process.exit(pid, :kill)
        Process.demonitor(entry.monitor, [:flush])
        reply_all(entry.waiters, {:error, :timeout})
        {:noreply, Map.delete(inflight, key)}

      _stale ->
        {:noreply, inflight}
    end
  end

  def handle_info({:DOWN, monitor, :process, _pid, _reason}, inflight) do
    case Enum.find(inflight, fn {_key, entry} -> entry.monitor == monitor end) do
      {key, entry} ->
        Process.cancel_timer(entry.timer)
        reply_all(entry.waiters, {:error, :operation_failed})
        {:noreply, Map.delete(inflight, key)}

      nil ->
        {:noreply, inflight}
    end
  end

  def handle_info({:EXIT, _pid, _reason}, inflight), do: {:noreply, inflight}

  @impl true
  def terminate(_reason, inflight) do
    Enum.each(inflight, fn {_key, entry} -> Process.exit(entry.pid, :kill) end)
    :ok
  end

  defp reply_all(waiters, result), do: Enum.each(waiters, &GenServer.reply(&1, result))
end
