defmodule AttestoClient.ConnectRetryTest do
  use ExUnit.Case, async: false

  alias AttestoClient.{Discovery, Token}

  setup do
    id = {__MODULE__, make_ref()}
    :ok = :telemetry.attach(id, [:attesto, :http, :connect_attempt], &__MODULE__.event/4, self())
    on_exit(fn -> :telemetry.detach(id) end)
  end

  def event(_event, _measurements, metadata, parent), do: send(parent, {:attempt, metadata})

  test "token and discovery refusals expose not_sent after three attempts" do
    {socket, port} = listener()
    :gen_tcp.close(socket)
    assert {:error, :not_sent} = exchange(port)
    for n <- 1..3, do: assert_receive({:attempt, %{attempt: ^n, outcome: :error}})
    assert {:error, :not_sent} = Discovery.fetch_jwks("http://localhost:#{port}/jwks", options())
    for n <- 1..3, do: assert_receive({:attempt, %{attempt: ^n, outcome: :error}})
    refute_received {:attempt, _}
  end

  @tag :capture_log
  test "a token deadline ending during TLS connect remains not_sent" do
    {socket, port} = listener()
    parent = self()

    spawn_link(fn ->
      {:ok, peer} = :gen_tcp.accept(socket, 2_000)
      send(parent, :accepted)

      receive do
        :finish -> :ok
      after
        1_000 -> :ok
      end

      :gen_tcp.close(peer)
    end)

    opts =
      options()
      |> Keyword.put(:timeout, 100)
      |> Keyword.put(:req_options, connect_options: [timeout: 5_000])

    assert {:error, :not_sent} =
             Token.exchange_pre_authorized_code(
               "secret-code",
               Keyword.merge(opts,
                 token_endpoint: "https://localhost:#{port}/token",
                 client_auth: :none
               )
             )

    assert_receive :accepted
    assert_receive {:attempt, %{attempt: 1, outcome: :error}}
    refute_received {:attempt, _}
  end

  @tag :capture_log
  test "the refresh coordinator shares the connect deadline and not-sent phase" do
    coordinator = start_supervised!(AttestoClient.RefreshCoordinator)
    {socket, port} = listener()
    parent = self()

    spawn_link(fn ->
      {:ok, peer} = :gen_tcp.accept(socket, 2_000)
      send(parent, :accepted)

      receive do
        :finish -> :ok
      after
        1_000 -> :ok
      end

      :gen_tcp.close(peer)
    end)

    opts =
      Keyword.merge(options(),
        token_endpoint: "https://localhost:#{port}/token",
        client_auth: :none
      )

    assert {:error, :not_sent} =
             AttestoClient.RefreshCoordinator.run(
               coordinator,
               :token_record,
               fn -> Token.exchange_pre_authorized_code("secret-code", opts) end,
               100
             )

    assert_receive :accepted
    assert_receive {:attempt, %{attempt: 1, outcome: :error}}
    refute_received {:attempt, _}
  end

  test "a token POST read and then closed is a transport_error and is not repeated" do
    {socket, port} = listener()
    parent = self()

    spawn_link(fn ->
      {:ok, peer} = :gen_tcp.accept(socket, 2_000)
      send(parent, {:request, read_request(peer, "")})
      :gen_tcp.close(peer)
      send(parent, {:second, :gen_tcp.accept(socket, 150)})
    end)

    assert {:error, :transport_error} = exchange(port)
    assert_receive {:request, request}
    assert request =~ "POST /token HTTP/1.1"
    assert request =~ "pre-authorized_code=secret-code"
    assert_receive {:attempt, %{attempt: 1, outcome: :ok}}
    refute_received {:attempt, _}
    assert_receive {:second, {:error, :timeout}}, 1_000
  end

  test "client credentials are never repeated after a POST is read and closed" do
    {socket, port} = listener()
    parent = self()

    spawn_link(fn ->
      {:ok, peer} = :gen_tcp.accept(socket, 2_000)
      send(parent, {:request, read_credentials_request(peer, "")})
      :gen_tcp.close(peer)
      send(parent, {:second, :gen_tcp.accept(socket, 150)})
    end)

    assert {:error, :transport_error} =
             Token.client_credentials(
               Keyword.merge(options(),
                 token_endpoint: "http://localhost:#{port}/token",
                 client_id: "client",
                 client_auth: {:client_secret_basic, "secret"}
               )
             )

    assert_receive {:request, request}
    assert request =~ "POST /token HTTP/1.1"
    assert request =~ "grant_type=client_credentials"
    assert_receive {:attempt, %{attempt: 1, outcome: :ok}}
    refute_received {:attempt, _}
    assert_receive {:second, {:error, :timeout}}, 1_000
  end

  defp read_credentials_request(socket, acc) do
    if String.contains?(acc, "\r\n\r\n") and
         String.contains?(acc, "grant_type=client_credentials") do
      acc
    else
      {:ok, data} = :gen_tcp.recv(socket, 0, 2_000)
      read_credentials_request(socket, acc <> data)
    end
  end

  test "a token response timeout after writing is timeout and is not repeated" do
    {socket, port} = listener()
    parent = self()

    spawn_link(fn ->
      {:ok, peer} = :gen_tcp.accept(socket, 2_000)
      send(parent, {:request, read_request(peer, "")})

      receive do
        :finish -> :ok
      after
        300 -> :ok
      end

      :gen_tcp.close(peer)
      send(parent, {:second, :gen_tcp.accept(socket, 150)})
    end)

    assert {:error, :timeout} = exchange(port, timeout: 100)
    assert_receive {:request, _}
    assert_receive {:attempt, %{attempt: 1, outcome: :ok}}
    refute_received {:attempt, _}
    assert_receive {:second, {:error, :timeout}}, 1_000
  end

  defp exchange(port, extra \\ []) do
    Token.exchange_pre_authorized_code(
      "secret-code",
      Keyword.merge(
        options(),
        [token_endpoint: "http://localhost:#{port}/token", client_auth: :none] ++ extra
      )
    )
  end

  defp options do
    [
      timeout: 2_000,
      outbound: [allow_loopback_http: true, allowed_cidrs: ["127.0.0.0/8"]],
      resolver: fn _, family ->
        if family == :inet, do: {:ok, [{127, 0, 0, 1}]}, else: {:ok, []}
      end
    ]
  end

  defp listener do
    {:ok, socket} =
      :gen_tcp.listen(0, [:binary, ip: {127, 0, 0, 1}, active: false, reuseaddr: true])

    on_exit(fn -> :gen_tcp.close(socket) end)
    {:ok, port} = :inet.port(socket)
    {socket, port}
  end

  defp read_request(socket, acc) do
    if String.contains?(acc, "\r\n\r\n") and
         String.contains?(acc, "pre-authorized_code=secret-code") do
      acc
    else
      {:ok, data} = :gen_tcp.recv(socket, 0, 2_000)
      read_request(socket, acc <> data)
    end
  end
end
