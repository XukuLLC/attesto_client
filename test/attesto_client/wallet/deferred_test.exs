defmodule AttestoClient.Wallet.DeferredTest do
  use ExUnit.Case, async: true

  alias AttestoClient.Wallet.Deferred

  defp options do
    [
      deferred_credential_endpoint: "https://issuer.example/deferred",
      deferred_clock: fn -> 0 end,
      deferred_sleep: fn _wait -> :ok end
    ]
  end

  defp pending(interval \\ 1), do: %{"transaction_id" => "transaction", "interval" => interval}

  test "waits the current issuer interval and polls the same transaction until issuance" do
    owner = self()

    request = fn id, _opts ->
      send(owner, {:poll, id})

      case Process.get(:attempt, 0) do
        0 ->
          Process.put(:attempt, 1)
          {:ok, pending(2)}

        1 ->
          {:ok, %{"credentials" => [%{"credential" => "issued"}]}}
      end
    end

    opts =
      Keyword.put(options(), :deferred_sleep, fn delay ->
        send(owner, {:wait, delay})
        :ok
      end)

    assert {:ok, %{"credentials" => [_]}} = Deferred.resolve(pending(), opts, request)
    assert_receive {:wait, 1_000}
    assert_receive {:poll, "transaction"}
    assert_receive {:wait, 2_000}
    assert_receive {:poll, "transaction"}
    refute_receive {:poll, _}
  end

  test "a changed transaction ID is rejected before another poll" do
    owner = self()

    request = fn _, _ ->
      send(owner, :poll)
      {:ok, %{"transaction_id" => "other", "interval" => 1}}
    end

    assert {:error, :deferred_transaction_mismatch} =
             Deferred.resolve(pending(), options(), request)

    assert_receive :poll
    refute_receive :poll
  end

  test "missing, nonpositive and excessive intervals cannot trigger a request" do
    request = fn _, _ -> flunk("unexpected deferred request") end

    for interval <- [nil, 0, -1, "1", 0.001, 1.0] do
      assert {:error, :invalid_deferred_interval} =
               Deferred.resolve(pending(interval), options(), request)
    end
  end

  test "bounds total attempts even when the issuer never completes" do
    owner = self()

    request = fn _, _ ->
      send(owner, :poll)
      {:ok, pending()}
    end

    opts = Keyword.put(options(), :deferred_max_attempts, 2)

    assert {:error, :deferred_attempts_exhausted} = Deferred.resolve(pending(), opts, request)
    assert_receive :poll
    assert_receive :poll
    refute_receive :poll
  end

  test "an interval beyond the remaining deadline is never slept or polled" do
    opts = Keyword.put(options(), :deferred_timeout, 500)

    assert {:error, :deferred_timeout} =
             Deferred.resolve(pending(), opts, fn _, _ -> flunk("unexpected poll") end)
  end

  test "a blocking custom sleep is cancelled by the wall deadline" do
    owner = self()

    opts =
      options()
      |> Keyword.put(:deferred_timeout, 1_050)
      |> Keyword.put(:deferred_sleep, fn _ ->
        send(owner, {:sleeping, self()})
        Process.sleep(:infinity)
      end)

    assert {:error, :deferred_timeout} =
             Deferred.resolve(pending(), opts, fn _, _ -> flunk("unexpected poll") end)

    assert_receive {:sleeping, worker}
    refute Process.alive?(worker)
  end

  test "terminal issuer errors are returned once without repeated requests" do
    owner = self()
    error = {:oauth_error, 400, %{"error" => "credential_request_denied"}}

    request = fn _, _ ->
      send(owner, :poll)
      {:error, error}
    end

    assert {:error, ^error} = Deferred.resolve(pending(), options(), request)
    assert_receive :poll
    refute_receive :poll
  end

  test "absent endpoint or explicit opt out preserves the pending response" do
    request = fn _, _ -> flunk("unexpected poll") end
    response = pending()

    assert {:ok, ^response} = Deferred.resolve(response, [], request)

    assert {:ok, ^response} =
             Deferred.resolve(response, options() ++ [deferred_poll: false], request)
  end

  test "a standard long interval is limited by the polling deadline rather than rejected as malformed" do
    assert {:error, :deferred_timeout} =
             Deferred.resolve(pending(86_400), options(), fn _, _ -> flunk("unexpected poll") end)
  end

  test "elapsed waits reduce the next request deadline and prevent later polling" do
    now = start_supervised!({Agent, fn -> 0 end})
    owner = self()

    opts =
      options()
      |> Keyword.put(:deferred_timeout, 1_500)
      |> Keyword.put(:deferred_clock, fn -> Agent.get(now, & &1) end)
      |> Keyword.put(:deferred_sleep, fn wait -> Agent.update(now, &(&1 + wait)) end)

    request = fn _, opts ->
      send(owner, {:request_timeout, opts[:timeout]})
      {:ok, pending()}
    end

    assert {:error, :deferred_timeout} = Deferred.resolve(pending(), opts, request)
    assert_receive {:request_timeout, 500}
    refute_receive {:request_timeout, _}
  end

  test "invalid polling options fail before invoking callbacks" do
    for invalid <- [
          [deferred_timeout: 0],
          [deferred_timeout: 3_600_001],
          [deferred_max_attempts: 101],
          [deferred_max_attempts: 0],
          [deferred_poll: "yes"],
          [deferred_clock: nil],
          [deferred_sleep: nil],
          [timeout: "slow"],
          [deferred_credential_endpoint: ""]
        ] do
      assert {:error, :invalid_deferred_options} =
               Deferred.resolve(pending(), Keyword.merge(options(), invalid), fn _, _ ->
                 flunk("unexpected request")
               end)
    end
  end
end
