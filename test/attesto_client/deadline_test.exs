defmodule AttestoClient.DeadlineTest do
  use ExUnit.Case, async: true

  alias AttestoClient.Deadline

  test "does not leak a late result into the caller mailbox after timeout" do
    assert {:error, :timeout} =
             Deadline.run(
               fn ->
                 receive do
                   :never_sent -> {:ok, %{secret: "must-not-leak"}}
                 end
               end,
               5
             )

    Process.sleep(5)
    assert {:messages, []} = Process.info(self(), :messages)
  end

  test "sanitizes operation failures" do
    assert {:error, :operation_failed} = Deadline.run(fn -> raise "sensitive value" end, 100)
  end

  test "kills the operation when its caller dies" do
    parent = self()

    caller =
      spawn(fn ->
        Deadline.run(
          fn ->
            send(parent, {:operation_started, self()})

            receive do
              :complete -> send(parent, :operation_completed)
            end
          end,
          1_000
        )
      end)

    assert_receive {:operation_started, operation}
    operation_monitor = Process.monitor(operation)
    Process.exit(caller, :kill)

    assert_receive {:DOWN, ^operation_monitor, :process, ^operation, _reason}
    refute_receive :operation_completed
  end
end
