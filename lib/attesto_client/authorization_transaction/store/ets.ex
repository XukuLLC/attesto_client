defmodule AttestoClient.AuthorizationTransaction.Store.ETS do
  @moduledoc """
  Single-node authorization transaction store backed by a private ETS table.

  Start it under your application's supervisor and pass
  `{#{inspect(__MODULE__)}, pid}` to `AttestoClient.AuthorizationCode.start/2`
  and `AttestoClient.AuthorizationCode.callback/3`. The owning GenServer
  serializes insert and consume operations, providing atomic single-use state.
  Entries expire against monotonic time and are removed lazily on access.

  This implementation is intentionally not distributed. Use a database or
  distributed cache adapter implementing
  `AttestoClient.AuthorizationTransaction.Store` when callbacks can reach
  different nodes.
  """

  use GenServer

  @behaviour AttestoClient.AuthorizationTransaction.Store

  alias AttestoClient.AuthorizationTransaction

  @type option :: GenServer.option() | {:max_entries, pos_integer()}

  @spec start_link([option()]) :: GenServer.on_start()
  def start_link(opts \\ []) do
    {genserver_opts, store_opts} = Keyword.split(opts, [:name, :timeout, :debug, :spawn_opt])
    GenServer.start_link(__MODULE__, store_opts, genserver_opts)
  end

  @impl true
  def put_new(server, state, %AuthorizationTransaction{} = transaction, ttl_ms) do
    GenServer.call(server, {:put_new, state, transaction, ttl_ms})
  end

  @impl true
  def take(server, state), do: GenServer.call(server, {:take, state})

  @impl true
  def init(opts) do
    case Keyword.get(opts, :max_entries, 10_000) do
      max when is_integer(max) and max > 0 ->
        {:ok, %{table: :ets.new(__MODULE__, [:set, :private]), max_entries: max}}

      _invalid ->
        {:stop, :invalid_max_entries}
    end
  end

  @impl true
  def handle_call({:put_new, state, transaction, ttl_ms}, _from, store) do
    now = monotonic_ms()
    purge_expired(store.table, now)

    reply =
      case :ets.lookup(store.table, state) do
        [{^state, expires_at, _old}] when expires_at <= now ->
          true = :ets.delete(store.table, state)
          insert_unless_full(store, state, transaction, now + ttl_ms)

        [] ->
          insert_unless_full(store, state, transaction, now + ttl_ms)

        [_live] ->
          {:error, :already_exists}
      end

    {:reply, reply, store}
  end

  def handle_call({:take, state}, _from, store) do
    now = monotonic_ms()

    reply =
      case :ets.take(store.table, state) do
        [{^state, expires_at, transaction}] when expires_at > now -> {:ok, transaction}
        [{^state, _expired_at, _transaction}] -> {:error, :expired}
        [] -> {:error, :not_found}
      end

    {:reply, reply, store}
  end

  @impl true
  def format_status(status) do
    status
    |> Map.update(:state, :redacted, fn store ->
      %{table: :redacted, max_entries: Map.get(store, :max_entries)}
    end)
    |> Map.update(:message, :redacted, fn _message -> :redacted end)
    |> Map.update(:messages, [], fn messages ->
      if messages == [], do: [], else: [:redacted]
    end)
  end

  defp insert_unless_full(store, state, transaction, expires_at) do
    if :ets.info(store.table, :size) < store.max_entries do
      true = :ets.insert(store.table, {state, expires_at, transaction})
      :ok
    else
      {:error, :capacity_exceeded}
    end
  end

  defp purge_expired(table, now) do
    :ets.select_delete(table, [{{:"$1", :"$2", :"$3"}, [{:"=<", :"$2", now}], [true]}])
  end

  defp monotonic_ms, do: System.monotonic_time(:millisecond)
end
