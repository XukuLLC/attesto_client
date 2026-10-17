defmodule AttestoClient.AuthorizationTransactionStoreTest do
  use ExUnit.Case, async: true

  alias AttestoClient.AuthorizationTransaction
  alias AttestoClient.AuthorizationTransaction.Store.ETS

  def handle_telemetry(event, measurements, metadata, pid) do
    send(pid, {:telemetry, event, measurements, metadata})
  end

  defp transaction(state) do
    %AuthorizationTransaction{
      state: state,
      nonce: "nonce",
      code_verifier: String.duplicate("v", 43),
      issuer: "https://op.example.com",
      client_id: "client",
      redirect_uri: "https://rp.example.com/callback",
      metadata: %{},
      id_token_alg: "RS256",
      browser_binding: "browser-binding",
      max_age: nil
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

  test "evicts the oldest live entry at capacity and emits telemetry" do
    handler_id = {__MODULE__, self(), make_ref()}

    :ok =
      :telemetry.attach(
        handler_id,
        [:attesto_client, :authorization_transaction, :evicted],
        &__MODULE__.handle_telemetry/4,
        self()
      )

    on_exit(fn -> :telemetry.detach(handler_id) end)

    store = start_supervised!({ETS, max_entries: 2})
    assert :ok = ETS.put_new(store, "oldest", transaction("oldest"), 10_000)
    assert :ok = ETS.put_new(store, "newer", transaction("newer"), 5_000)
    assert :ok = ETS.put_new(store, "newest", transaction("newest"), 10_000)

    assert_receive {:telemetry, [:attesto_client, :authorization_transaction, :evicted],
                    %{count: 1}, %{reason: :capacity}}

    assert {:error, :not_found} = ETS.take(store, "oldest")
    assert {:ok, %AuthorizationTransaction{state: "newer"}} = ETS.take(store, "newer")
    assert {:ok, %AuthorizationTransaction{state: "newest"}} = ETS.take(store, "newest")
  end

  test "expired entries are reclaimed before capacity eviction" do
    store = start_supervised!({ETS, max_entries: 1})
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

  test "redacts transaction secrets from formatted process status" do
    status = %{
      state: %{
        table: :private_table,
        expiry_index: :private_expiry_index,
        age_index: :private_age_index,
        max_entries: 10
      },
      message: {:put_new, "state", transaction("secret-message"), 1_000},
      messages: [{:put_new, "state", transaction("secret-state"), 1_000}]
    }

    formatted = ETS.format_status(status)
    inspected = inspect(formatted)

    assert formatted.state == %{
             table: :redacted,
             expiry_index: :redacted,
             age_index: :redacted,
             max_entries: 10
           }

    assert formatted.message == :redacted
    assert formatted.messages == [:redacted]
    refute inspected =~ "secret-state"
    refute inspected =~ "secret-message"
    refute inspected =~ "browser-binding"
    refute inspected =~ String.duplicate("v", 43)
  end
end
