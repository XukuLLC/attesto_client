defmodule AttestoClient.AuthorizationTransaction.Store do
  @moduledoc """
  Storage contract for replay-safe authorization transactions.

  Both callbacks must be atomic. `put_new/4` must never replace a live entry,
  and `take/2` must delete before returning so the same state cannot be used
  twice, including under concurrent callbacks. `ttl_ms` is a relative lifetime
  in milliseconds.

  A store is represented as `{module, handle}`. The included
  `AttestoClient.AuthorizationTransaction.Store.ETS` implementation uses a
  supervised process as the handle.
  """

  alias AttestoClient.AuthorizationTransaction

  @type handle :: term()
  @type store :: {module(), handle()}

  @callback put_new(handle(), String.t(), AuthorizationTransaction.t(), pos_integer()) ::
              :ok | {:error, :already_exists | term()}
  @callback take(handle(), String.t()) ::
              {:ok, AuthorizationTransaction.t()} | {:error, :not_found | :expired | term()}

  @doc false
  @spec put_new(store(), String.t(), AuthorizationTransaction.t(), pos_integer()) ::
          :ok | {:error, term()}
  def put_new({module, handle}, state, transaction, ttl_ms)
      when is_atom(module) and is_binary(state) and is_integer(ttl_ms) and ttl_ms > 0 do
    module.put_new(handle, state, transaction, ttl_ms)
  end

  def put_new(_store, _state, _transaction, _ttl_ms), do: {:error, :invalid_store}

  @doc false
  @spec take(store(), String.t()) :: {:ok, AuthorizationTransaction.t()} | {:error, term()}
  def take({module, handle}, state) when is_atom(module) and is_binary(state) do
    module.take(handle, state)
  end

  def take(_store, _state), do: {:error, :invalid_store}
end
