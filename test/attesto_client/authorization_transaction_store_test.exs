defmodule AttestoClient.AuthorizationTransactionStoreTest do
  use ExUnit.Case, async: true

  alias AttestoClient.AuthorizationTransaction
  alias AttestoClient.AuthorizationTransaction.Store.ETS

  defp transaction(state) do
    %AuthorizationTransaction{
      state: state,
      nonce: "nonce",
      code_verifier: String.duplicate("v", 43),
      issuer: "https://op.example.com",
      client_id: "client",
      redirect_uri: "https://rp.example.com/callback",
      metadata: %{},
      id_token_alg: "RS256"
    }
  end

  test "take is single-use even under concurrent callbacks" do
    start_supervised!({ETS, name: __MODULE__})
    assert :ok = ETS.put_new(__MODULE__, "state", transaction("state"), 1_000)

    results =
      1..20
      |> Task.async_stream(fn _ -> ETS.take(__MODULE__, "state") end,
        max_concurrency: 20,
        ordered: false
      )
      |> Enum.map(fn {:ok, result} -> result end)

    assert Enum.count(results, &match?({:ok, _}, &1)) == 1
    assert Enum.count(results, &(&1 == {:error, :not_found})) == 19
  end

  test "expires entries and enforces capacity" do
    store = start_supervised!({ETS, max_entries: 1})
    assert :ok = ETS.put_new(store, "live", transaction("live"), 1_000)
    assert {:error, :capacity_exceeded} = ETS.put_new(store, "other", transaction("other"), 100)
    assert {:ok, %AuthorizationTransaction{state: "live"}} = ETS.take(store, "live")

    assert :ok = ETS.put_new(store, "short", transaction("short"), 1)
    Process.sleep(5)
    assert :ok = ETS.put_new(store, "other", transaction("other"), 100)
    assert {:error, :not_found} = ETS.take(store, "short")
    assert {:ok, %AuthorizationTransaction{state: "other"}} = ETS.take(store, "other")
  end

  test "put_new never replaces a live state" do
    store = start_supervised!(ETS)
    assert :ok = ETS.put_new(store, "state", transaction("state"), 1_000)
    assert {:error, :already_exists} = ETS.put_new(store, "state", transaction("state"), 1_000)
  end
end
