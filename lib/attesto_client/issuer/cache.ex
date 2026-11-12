defmodule AttestoClient.Issuer.Cache do
  @moduledoc false

  # The decisions of the issuer key cache, with no process, clock, or network
  # in them. `AttestoClient.Issuer` owns the process and the fetch; every
  # function here takes the monotonic time in milliseconds as an argument.
  #
  # A snapshot is one successful fetch: the fetched content plus its
  # generation and the two deadlines. It is fresh until `fresh_until`, then
  # stale until `stale_until`. A failed refresh annotates the retained snapshot
  # with the failure and a retry cooldown, or, before the first snapshot,
  # records them on the cache.

  @enforce_keys [:fresh_ttl, :stale_ttl, :unknown_kid_refresh_interval, :refresh_retry_interval]
  defstruct [
    :fresh_ttl,
    :stale_ttl,
    :unknown_kid_refresh_interval,
    :refresh_retry_interval,
    snapshot: nil,
    generation: 0,
    next_unknown_refresh_at: nil,
    initial_refresh_failure: nil
  ]

  @type snapshot :: %{
          required(:fresh_until) => integer(),
          required(:stale_until) => integer(),
          required(:generation) => pos_integer(),
          required(:refresh_error) => term(),
          required(:retry_after) => integer() | nil,
          optional(atom()) => term()
        }

  @type t :: %__MODULE__{}
  @type refresh_reason :: :initial | :expired | :unknown_kid | :forced

  @spec new(map()) :: t()
  def new(config) do
    %__MODULE__{
      fresh_ttl: config.fresh_ttl,
      stale_ttl: config.stale_ttl,
      unknown_kid_refresh_interval: config.unknown_kid_refresh_interval,
      refresh_retry_interval: config.refresh_retry_interval
    }
  end

  @doc """
  What a reader holding `snapshot` does at `now`: use it, fail with a
  remembered refresh error, or ask for a refresh.
  """
  @spec lookup(snapshot() | nil, integer()) ::
          {:ok, snapshot()}
          | {:error, term()}
          | {:refresh, pos_integer() | nil, :initial | :expired}
  def lookup(nil, _now), do: {:refresh, nil, :initial}

  def lookup(snapshot, now) do
    cond do
      now < snapshot.fresh_until -> {:ok, snapshot}
      retry_active?(snapshot, now) -> retry_result(snapshot, now)
      true -> {:refresh, snapshot.generation, :expired}
    end
  end

  @doc """
  The reader's result after a refresh of an expired `snapshot` failed with
  `reason`: the stale snapshot when the failure is transient and the stale
  interval has not ended, the failure otherwise.
  """
  @spec stale_fallback(snapshot(), integer(), term()) :: {:ok, snapshot()} | {:error, term()}
  def stale_fallback(snapshot, now, reason) do
    if now < snapshot.stale_until and transient?(reason),
      do: {:ok, snapshot},
      else: {:error, reason}
  end

  @doc "Whether `snapshot` may still be used at `now`, fresh or stale."
  @spec usable?(snapshot() | nil, integer()) :: boolean()
  def usable?(nil, _now), do: false
  def usable?(%{stale_until: stale_until}, now), do: now < stale_until

  @doc "Whether `kid` names no key in `snapshot`."
  @spec unknown_kid?(snapshot(), term()) :: boolean()
  def unknown_kid?(%{keys: keys}, kid) when is_binary(kid) and kid != "",
    do: not Enum.any?(keys, &(Map.get(&1, "kid") == kid))

  def unknown_kid?(_snapshot, _kid), do: false

  @doc """
  Decide a refresh request from a reader that observed `observed_generation`.

  A reader that observed an older generation gets the newer snapshot. While a
  fetch is running, the request joins it. A request inside a cooldown gets the
  remembered answer. Otherwise a fetch starts, and an unknown-`kid` request
  opens the unknown-`kid` cooldown.
  """
  @spec admit(t(), pos_integer() | nil, refresh_reason(), integer(), boolean()) ::
          {:reply, {:ok, snapshot()} | {:error, term()}} | :join | {:fetch, t()}
  def admit(%__MODULE__{} = cache, observed_generation, reason, now, fetching?) do
    cond do
      newer_snapshot?(cache, observed_generation) -> {:reply, {:ok, cache.snapshot}}
      fetching? -> :join
      suppressed?(cache, reason, now) -> {:reply, suppressed_reply(cache, reason, now)}
      true -> {:fetch, open_unknown_kid_cooldown(cache, reason, now)}
    end
  end

  @doc "Record a successful fetch of `content` as the next generation."
  @spec put(t(), map(), integer()) :: {snapshot(), t()}
  def put(%__MODULE__{} = cache, content, now) when is_map(content) do
    snapshot =
      Map.merge(content, %{
        fresh_until: now + cache.fresh_ttl,
        stale_until: now + cache.fresh_ttl + cache.stale_ttl,
        generation: cache.generation + 1,
        refresh_error: nil,
        retry_after: nil
      })

    {snapshot, %{cache | snapshot: snapshot, generation: snapshot.generation}}
  end

  @doc """
  Record a failed fetch and start its retry cooldown.

  Before the first snapshot there is nothing to annotate, so the failure is
  kept on the cache; until the cooldown ends, an initial refresh returns the
  remembered error instead of starting another fetch.
  """
  @spec fail(t(), term(), integer()) :: t()
  def fail(%__MODULE__{snapshot: nil} = cache, reason, now),
    do: %{cache | initial_refresh_failure: {reason, now + cache.refresh_retry_interval}}

  def fail(%__MODULE__{snapshot: snapshot} = cache, reason, now) do
    snapshot =
      snapshot
      |> Map.put(:refresh_error, reason)
      |> Map.put(:retry_after, now + cache.refresh_retry_interval)

    %{cache | snapshot: snapshot}
  end

  @doc "Whether a refresh failure is one a stale snapshot may cover."
  @spec transient?(term()) :: boolean()
  def transient?({:transport, _reason}), do: true
  def transient?(:timeout), do: true
  def transient?(:refresh_timeout), do: true
  def transient?({:refresh_task_exit, _reason}), do: true
  def transient?({:http_status, 429}), do: true
  def transient?({:http_status, status}) when status in 500..599, do: true
  def transient?(_reason), do: false

  defp newer_snapshot?(%{snapshot: nil}, _observed), do: false
  # The reader saw an empty cache and a fetch has completed since. That
  # snapshot is newer than what the reader observed, so it is the answer; a
  # second fetch here would break single flight for concurrent first readers.
  defp newer_snapshot?(_cache, nil), do: true
  defp newer_snapshot?(cache, observed), do: cache.snapshot.generation > observed

  defp suppressed?(cache, :expired, now), do: retry_active?(cache.snapshot, now)

  defp suppressed?(%{next_unknown_refresh_at: next_refresh}, :unknown_kid, now)
       when is_integer(next_refresh),
       do: now < next_refresh

  defp suppressed?(
         %{snapshot: nil, initial_refresh_failure: {_reason, retry_after}},
         :initial,
         now
       ),
       do: now < retry_after

  defp suppressed?(_cache, _reason, _now), do: false

  defp suppressed_reply(cache, :expired, now), do: retry_result(cache.snapshot, now)

  defp suppressed_reply(%{initial_refresh_failure: {reason, _retry_after}}, :initial, _now),
    do: {:error, reason}

  defp suppressed_reply(cache, _reason, _now), do: {:ok, cache.snapshot}

  defp open_unknown_kid_cooldown(cache, :unknown_kid, now),
    do: %{cache | next_unknown_refresh_at: now + cache.unknown_kid_refresh_interval}

  defp open_unknown_kid_cooldown(cache, _reason, _now), do: cache

  defp retry_active?(%{retry_after: retry_after}, now) when is_integer(retry_after),
    do: now < retry_after

  defp retry_active?(_snapshot, _now), do: false

  defp retry_result(%{refresh_error: reason} = snapshot, now) do
    if transient?(reason) and now < snapshot.stale_until,
      do: {:ok, snapshot},
      else: {:error, reason}
  end
end
