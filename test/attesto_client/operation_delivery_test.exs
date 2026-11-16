defmodule AttestoClient.OperationDeliveryTest do
  use ExUnit.Case, async: false

  alias AttestoClient.{
    AuthorizationCode,
    Deadline,
    Discovery,
    Issuer,
    RefreshCoordinator,
    Token,
    TokenSet,
    Wallet
  }

  alias AttestoClient.AuthorizationTransaction.Store.ETS
  alias AttestoClient.Wallet.CredentialOffer

  @tls :public_key.pkix_test_data(%{
         root: [key: {:namedCurve, {1, 2, 840, 10_045, 3, 1, 7}}, digest: :sha256],
         intermediates: [],
         peer: [
           key: {:namedCurve, {1, 2, 840, 10_045, 3, 1, 7}},
           digest: :sha256,
           extensions: [{:Extension, {2, 5, 29, 17}, false, [dNSName: ~c"localhost"]}]
         ]
       })

  for operation <- [:exchange, :pre_authorized, :revoke, :start, :callback, :refresh] do
    @operation operation
    test "#{operation}: a refused nonce attempt does not prevent a later not_sent result" do
      key = JOSE.JWK.generate_key({:ec, "P-256"})

      {url, _server} =
        serve([
          fn _url, _request ->
            {400, %{"error" => "use_dpop_nonce"}, [{"dpop-nonce", "fresh"}]}
          end
        ])

      opts = options(url) ++ [dpop: key, client_id: "client", client_auth: :none, issuer: url]
      assert {:error, :not_sent} = invoke(@operation, url, opts)
      assert_receive {:wire, "POST " <> _}
      refute_received {:wire, _}
    end
  end

  for stage <- [:nonce, :credential, :deferred] do
    @stage stage
    test "wallet retains the accepted write when the #{@stage} connection fails" do
      token = fn _, _ -> {200, %{"access_token" => "access", "token_type" => "Bearer"}, []} end
      deferred = fn _, _ -> {202, %{"transaction_id" => "transaction", "interval" => 1}, []} end
      responses = if @stage == :deferred, do: [token, deferred], else: [token]
      {url, _server} = serve(responses)
      opts = wallet_options(url)

      opts =
        if @stage == :nonce, do: Keyword.put(opts, :nonce_endpoint, url <> "/nonce"), else: opts

      opts =
        if @stage == :deferred,
          do:
            Keyword.merge(opts,
              deferred_credential_endpoint: url <> "/deferred",
              deferred_sleep: fn _ -> :ok end
            ),
          else: opts

      assert {:error, :transport_error} = Wallet.request_credential(offer(url), key(), opts)
      assert_receive {:wire, "POST /token " <> _}
      if @stage == :deferred, do: assert_receive({:wire, "POST /credential " <> _})
      refute_received {:wire, _}
      assert {:error, :not_sent} = invoke(:pre_authorized, url, options(url))
    end
  end

  test "a wallet's accepted token write survives a refused credential nonce attempt" do
    {url, _server} =
      serve([
        fn _, _ -> {200, %{"access_token" => "access", "token_type" => "DPoP"}, []} end,
        fn _, _ -> {400, %{"error" => "use_dpop_nonce"}, [{"dpop-nonce", "fresh"}]} end
      ])

    assert {:error, :transport_error} =
             Wallet.request_credential(offer(url), key(), wallet_options(url) ++ [dpop: key()])

    assert_receive {:wire, "POST /token " <> _}
    assert_receive {:wire, "POST /credential " <> _}
    refute_received {:wire, _}
  end

  test "a later connect deadline after an accepted wallet token write is timeout" do
    {url, server} =
      serve(
        [fn _, _ -> {200, %{"access_token" => "access", "token_type" => "Bearer"}, []} end],
        :hold
      )

    opts =
      wallet_options(url)
      |> Keyword.put(:nonce_endpoint, String.replace(url, "http:", "https:") <> "/nonce")
      |> Keyword.put(:timeout, 150)

    assert {:error, :timeout} = Wallet.request_credential(offer(url), key(), opts)
    send(server, :stop)
    assert_receive {:wire, "POST /token " <> _}
  end

  for operation <- [:callback, :refresh] do
    @operation operation
    test "#{operation}: accepted token exchange followed by unavailable rotated keys is invalid_signature" do
      signing = key()
      nonce = start_supervised!({Agent, fn -> nil end})

      {url, _server} =
        serve([
          fn url, _ -> {200, metadata(url), []} end,
          fn _, _ -> {200, %{"keys" => [public_key(signing, "old")]}, []} end,
          fn url, _ ->
            claims = %{
              "iss" => url,
              "sub" => "subject",
              "aud" => "client",
              "iat" => System.system_time(:second),
              "exp" => System.system_time(:second) + 600
            }

            claims =
              if value = Agent.get(nonce, & &1), do: Map.put(claims, "nonce", value), else: claims

            {_, jwt} =
              signing
              |> JOSE.JWT.sign(%{"alg" => "ES256", "kid" => "new"}, claims)
              |> JOSE.JWS.compact()

            {200, %{"access_token" => "access", "token_type" => "Bearer", "id_token" => jwt}, []}
          end
        ])

      issuer = start_supervised!({Issuer, options(url) ++ [issuer: url, fresh_ttl: 60_000]})
      assert :ok = Issuer.warm(issuer)

      opts =
        options(url) ++
          [
            issuer: {Issuer, issuer},
            token_endpoint: url <> "/token",
            client_id: "client",
            client_auth: :none,
            id_token_alg: "ES256",
            subject: "subject"
          ]

      result =
        if @operation == :callback do
          store = {ETS, start_supervised!(ETS)}

          assert {:ok, started} =
                   AuthorizationCode.start(
                     store,
                     opts ++
                       [
                         browser_binding: "browser",
                         redirect_uri: "https://client.example/callback"
                       ]
                   )

          Agent.update(nonce, fn _ ->
            started.url
            |> URI.parse()
            |> Map.fetch!(:query)
            |> URI.decode_query()
            |> Map.fetch!("nonce")
          end)

          AuthorizationCode.callback(
            store,
            %{"state" => started.state, "code" => "code", "iss" => url},
            opts ++ [browser_binding: "browser"]
          )
        else
          coordinator = start_supervised!(RefreshCoordinator)
          Token.refresh(coordinator, :record, tokens(), opts)
        end

      assert {:error, :invalid_signature} = result
      assert_receive {:wire, "GET " <> _}
      assert_receive {:wire, "GET /jwks " <> _}
      assert_receive {:wire, "POST /token " <> _}
      refute_received {:wire, _}
    end
  end

  test "a failed notification connection records ambiguous delivery on the successful result" do
    signing = key()
    holder = key()
    public = holder |> JOSE.JWK.to_public_map() |> elem(1)
    pem = signing |> JOSE.JWK.to_pem() |> elem(1)

    {url, _} =
      serve([
        fn _, _ -> {200, %{"access_token" => "access", "token_type" => "Bearer"}, []} end,
        fn url, _ ->
          credential =
            Attesto.SdJwtVc.issue([iss: url, vct: "degree", pem: pem],
              claims: %{},
              cnf: %{"jwk" => public}
            )

          {200,
           Attesto.CredentialResponse.build(credential)
           |> Map.put("notification_id", "notification"), []}
        end
      ])

    opts =
      wallet_options(url)
      |> Keyword.put(:trusted, signing |> JOSE.JWK.to_public_map() |> elem(1))
      |> Keyword.put(:notification_endpoint, url <> "/notification")

    assert {:ok, %{notification_error: :transport_error, credentials: [_]}} =
             Wallet.request_credential(offer(url), holder, opts)

    assert_receive {:wire, "POST /token " <> _}
    assert_receive {:wire, "POST /credential " <> _}
    refute_received {:wire, _}
  end

  test "a status lookup connect failure cannot erase the earlier credential write" do
    signing = key()
    holder = key()
    public = holder |> JOSE.JWK.to_public_map() |> elem(1)
    trusted = signing |> JOSE.JWK.to_public_map() |> elem(1)
    pem = signing |> JOSE.JWK.to_pem() |> elem(1)

    {url, _} =
      serve([
        fn _, _ -> {200, %{"access_token" => "access", "token_type" => "Bearer"}, []} end,
        fn url, _ ->
          credential =
            Attesto.SdJwtVc.issue([iss: url, vct: "degree", pem: pem],
              claims: %{},
              cnf: %{"jwk" => public},
              status: Attesto.StatusList.reference("https://status.example/list", 0)
            )

          {200, Attesto.CredentialResponse.build(credential), []}
        end
      ])

    parent = self()

    opts =
      wallet_options(url)
      |> Keyword.put(:trusted, trusted)
      |> Keyword.put(:resolve_status, fn _, _ ->
        send(parent, :status_lookup)
        {:error, {:not_sent, {:transport, :econnrefused}}}
      end)

    assert {:error, :transport_error} = Wallet.request_credential(offer(url), holder, opts)
    assert_receive {:wire, "POST /token " <> _}
    assert_receive {:wire, "POST /credential " <> _}
    assert_receive :status_lookup
  end

  test "the coordinator's host callback retains writes across public token calls" do
    {url, _} =
      serve([fn _, _ -> {200, %{"access_token" => "access", "token_type" => "Bearer"}, []} end])

    coordinator = start_supervised!(RefreshCoordinator)

    assert {:error, :transport_error} =
             RefreshCoordinator.run(
               coordinator,
               :record,
               fn ->
                 assert {:ok, _} = invoke(:pre_authorized, url, options(url))
                 invoke(:pre_authorized, url, options(url))
               end,
               2_000
             )
  end

  for method <- [:get, :head] do
    @method method
    test "an earlier #{@method} does not count as a state-changing write" do
      opts = Deadline.options([])
      context = Keyword.fetch!(opts, :attesto_context)
      Deadline.sending(context, @method)
      {url, _} = serve([])
      assert {:error, :not_sent} = Discovery.fetch_jwks(url <> "/jwks", options(url) ++ opts)
    end
  end

  test "the deadline backstop keeps an earlier write after a new connect begins" do
    opts = Deadline.options([])
    context = Keyword.fetch!(opts, :attesto_context)
    Deadline.sending(context, :post)

    assert {:error, :timeout} =
             Deadline.run(
               fn nested ->
                 Deadline.connecting(nested)
                 Process.sleep(500)
               end,
               20,
               opts
             )
  end

  defp invoke(:pre_authorized, url, opts),
    do: Token.exchange_pre_authorized_code("code", opts ++ [token_endpoint: url <> "/token"])

  defp invoke(:revoke, url, opts),
    do: Token.revoke("token", opts ++ [revocation_endpoint: url <> "/revoke"])

  defp invoke(:exchange, url, opts),
    do:
      AuthorizationCode.exchange(
        "code",
        opts ++
          [
            token_endpoint: url <> "/token",
            redirect_uri: "https://client.example/callback",
            code_verifier: String.duplicate("v", 43)
          ]
      )

  defp invoke(:start, url, opts) do
    store = {ETS, start_supervised!(ETS)}

    AuthorizationCode.start(
      store,
      opts ++
        [
          metadata: metadata(url),
          par: true,
          browser_binding: "browser",
          redirect_uri: "https://client.example/callback",
          id_token_alg: "ES256"
        ]
    )
  end

  defp invoke(:callback, url, opts) do
    store = {ETS, start_supervised!(ETS)}

    assert {:ok, started} =
             AuthorizationCode.start(
               store,
               opts ++
                 [
                   metadata: metadata(url),
                   protocol: :oauth,
                   browser_binding: "browser",
                   redirect_uri: "https://client.example/callback"
                 ]
             )

    AuthorizationCode.callback(
      store,
      %{"state" => started.state, "code" => "code", "iss" => url},
      opts ++ [browser_binding: "browser"]
    )
  end

  defp invoke(:refresh, url, opts) do
    coordinator = start_supervised!(RefreshCoordinator)

    {:ok, bound} =
      TokenSet.bind_dpop(
        %{tokens() | token_type: "DPoP"},
        Attesto.DPoP.compute_jkt(Keyword.fetch!(opts, :dpop))
      )

    Token.refresh(
      coordinator,
      :record,
      bound,
      opts ++
        [
          token_endpoint: url <> "/token",
          subject: "subject",
          jwks: %{"keys" => [public_key(key(), "old")]}
        ]
    )
  end

  defp tokens, do: %TokenSet{access_token: "old", token_type: "Bearer", refresh_token: "refresh"}
  defp key, do: JOSE.JWK.generate_key({:ec, "P-256"})

  defp public_key(key, kid),
    do:
      key
      |> JOSE.JWK.to_public_map()
      |> elem(1)
      |> Map.merge(%{"kid" => kid, "alg" => "ES256", "use" => "sig"})

  defp wallet_options(url),
    do:
      options(url) ++
        [
          token_endpoint: url <> "/token",
          credential_endpoint: url <> "/credential",
          format: "dc+sd-jwt",
          trusted: key(),
          client_auth: :none
        ]

  defp offer(url) do
    %CredentialOffer{
      credential_issuer: url,
      credential_configuration_ids: ["degree"],
      grants: %{pre_authorized_code: %{code: "code", tx_code: nil}, authorization_code: nil}
    }
  end

  defp metadata(url),
    do: %{
      "issuer" => url,
      "authorization_endpoint" => url <> "/authorize",
      "token_endpoint" => url <> "/token",
      "jwks_uri" => url <> "/jwks",
      "pushed_authorization_request_endpoint" => url <> "/par",
      "response_types_supported" => ["code"],
      "subject_types_supported" => ["public"],
      "id_token_signing_alg_values_supported" => ["ES256"],
      "code_challenge_methods_supported" => ["S256"]
    }

  defp options(_url),
    do: [
      timeout: 2_000,
      outbound: [allowed_cidrs: ["127.0.0.0/8"]],
      req_options: [connect_options: [transport_opts: [cacerts: @tls[:cacerts]]]],
      resolver: fn _, family ->
        if family == :inet, do: {:ok, [{127, 0, 0, 1}]}, else: {:ok, []}
      end
    ]

  defp serve(responses, finish \\ :close) do
    {:ok, listener} =
      :ssl.listen(0, [
        :binary,
        ip: {127, 0, 0, 1},
        active: false,
        reuseaddr: true,
        cert: @tls[:cert],
        key: @tls[:key]
      ])

    {:ok, {_, port}} = :ssl.sockname(listener)
    url = "https://localhost:#{port}"
    parent = self()

    pid =
      spawn_link(fn ->
        responses
        |> Enum.with_index(1)
        |> Enum.each(&serve_response(&1, length(responses), listener, url, parent, finish))

        if finish == :hold do
          {:ok, socket} = :ssl.transport_accept(listener, 2_000)

          receive do
            :stop -> :ok
          after
            2_000 -> :ok
          end

          :ssl.close(socket)
        end

        :ssl.close(listener)
      end)

    if responses == [], do: :ssl.close(listener)

    on_exit(fn ->
      Process.exit(pid, :kill)
      :ssl.close(listener)
    end)

    {url, pid}
  end

  defp serve_response({response, index}, count, listener, url, parent, finish) do
    {:ok, socket} = :ssl.transport_accept(listener, 5_000)
    {:ok, socket} = :ssl.handshake(socket, 5_000)
    request = read(socket, "")
    send(parent, {:wire, request})
    {status, body, headers} = response.(url, request)
    body = JSON.encode!(body)
    if index == count and finish == :close, do: :ssl.close(listener)
    headers = Enum.map_join(headers, "", &encode_header/1)

    :ok =
      :ssl.send(
        socket,
        "HTTP/1.1 #{status} Result\r\ncontent-type: application/json\r\ncontent-length: #{byte_size(body)}\r\n#{headers}\r\n#{body}"
      )

    :ssl.close(socket)
  end

  defp encode_header({name, value}), do: "#{name}: #{value}\r\n"

  defp read(socket, acc) do
    case :binary.split(acc, "\r\n\r\n") do
      [head, body] ->
        size =
          case Regex.run(~r/content-length: (\d+)/i, head) do
            [_, n] -> String.to_integer(n)
            _ -> 0
          end

        if byte_size(body) >= size, do: acc, else: recv(socket, acc)

      _ ->
        recv(socket, acc)
    end
  end

  defp recv(socket, acc) do
    {:ok, data} = :ssl.recv(socket, 0, 5_000)
    read(socket, acc <> data)
  end
end
