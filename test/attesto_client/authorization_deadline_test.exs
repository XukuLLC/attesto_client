defmodule AttestoClient.AuthorizationDeadlineTest do
  use ExUnit.Case, async: true

  alias AttestoClient.AuthorizationCode

  @issuer "https://issuer.example"
  @expires 1_800_000_000_500

  defp transaction do
    {:ok, %{transaction: transaction}} =
      AuthorizationCode.start(:return,
        protocol: :oauth,
        issuer: @issuer,
        client_id: "client",
        redirect_uri: "https://rp.example/callback",
        browser_binding: "browser",
        metadata: %{
          "issuer" => @issuer,
          "authorization_endpoint" => @issuer <> "/authorize",
          "token_endpoint" => @issuer <> "/token",
          "code_challenge_methods_supported" => ["S256"]
        }
      )

    %{transaction | expires_at: @expires}
  end

  defp callback(transaction, response, opts) do
    AuthorizationCode.callback(
      :return,
      Map.put(response, "state", transaction.state),
      [transaction: transaction, browser_binding: "browser"] ++ opts
    )
  end

  test "authorization errors obey integer and function clocks in either unit" do
    transaction = transaction()
    response = %{"error" => "access_denied", "error_description" => "provider text"}

    for clock <- [
          [now: div(@expires, 1000)],
          [now: fn -> div(@expires, 1000) end],
          [now_ms: @expires],
          [now_ms: fn -> @expires end]
        ] do
      assert {:error, {:invalid_state, :expired}} = callback(transaction, response, clock)
    end

    assert {:error, {:authorization_error, "access_denied", "provider text"}} =
             callback(transaction, response, now_ms: @expires - 1)
  end

  test "seconds are the last millisecond, with equality expired" do
    response = %{"error" => "access_denied"}
    second = div(@expires, 1000)

    for expires <- [second * 1000, second * 1000 + 999] do
      assert {:error, {:invalid_state, :expired}} =
               callback(%{transaction() | expires_at: expires}, response, now: second)
    end

    assert {:error, {:authorization_error, _, _}} =
             callback(%{transaction() | expires_at: second * 1000 + 1000}, response, now: second)
  end

  test "a function clock is read again before the token request" do
    reads = start_supervised!({Agent, fn -> 0 end})
    clock = fn -> Agent.get_and_update(reads, fn n -> {@expires - 1 + n, n + 1} end) end
    plug = fn _conn -> flunk("expired transaction reached the token endpoint") end

    assert {:error, {:invalid_state, :expired}} =
             callback(transaction(), %{"code" => "code"},
               now_ms: clock,
               req_options: [plug: plug]
             )

    assert Agent.get(reads, & &1) == 2
  end

  test "invalid clock results and failures are safe on error callbacks" do
    for clock <- [
          nil,
          "now",
          fn -> :invalid end,
          fn -> raise "private detail" end,
          fn -> throw(:clock_failed) end
        ] do
      assert {:error, :invalid_time} =
               callback(transaction(), %{"error" => "access_denied"}, now_ms: clock)
    end

    assert {:error, :invalid_time} =
             callback(transaction(), %{"error" => "access_denied"}, now: fn -> :invalid end)
  end
end
