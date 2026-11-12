defmodule AttestoClient.OutboundEntryPointsTest do
  @moduledoc """
  `:outbound` on every public call that connects somewhere and is not covered
  by `AttestoClient.OutboundTest`: it reaches the screen where the operator
  chose the address, and is refused where another party wrote it.
  """

  use ExUnit.Case, async: true

  alias AttestoClient.Issuer
  alias AttestoClient.ResourceServer
  alias AttestoClient.SignedIntrospection
  alias AttestoClient.Token
  alias AttestoClient.UserInfo
  alias AttestoClient.Wallet
  alias AttestoClient.Wallet.CredentialOffer
  alias AttestoClient.Wallet.Presentation
  alias AttestoClient.Wallet.PresentationRequest
  alias AttestoClient.WalletAttestation

  @host "idp.internal.example"
  @issuer "https://idp.internal.example"
  @listed [outbound: [allowed_cidrs: ["127.0.0.1/32"]]]

  # The private network in these tests is this machine's loopback address: the
  # name resolves to 127.0.0.1, which the screen refuses like any other
  # non-public address unless its block is listed. A request that passes the
  # screen then meets a closed port and is refused at once, so no test depends
  # on how an outside network answers.
  setup do
    {:ok, listener} = :gen_tcp.listen(0, ip: {127, 0, 0, 1})
    {:ok, port} = :inet.port(listener)
    :ok = :gen_tcp.close(listener)

    base = [resolver: loopback_resolver(self()), timeout: 2_000, req_options: [retry: false]]
    %{base: base, origin: "https://#{@host}:#{port}"}
  end

  defp loopback_resolver(owner) do
    fn host, family ->
      send(owner, {:resolved, List.to_string(host)})
      if family == :inet, do: {:ok, [{127, 0, 0, 1}]}, else: {:error, :nxdomain}
    end
  end

  defp past_screen(result) do
    assert {:error, reason} = result

    refute reason in [
             :blocked_host,
             :invalid_endpoint,
             :invalid_outbound,
             :outbound_not_supported
           ]
  end

  # Each call is refused at the screen without the option, gets past it with
  # the block listed, and reports a malformed option before connecting.
  defp assert_takes_outbound(call, base) do
    assert {:error, :blocked_host} = call.(base)
    past_screen(call.(base ++ @listed))

    assert {:error, :invalid_outbound} =
             call.(base ++ [outbound: [allowed_cidrs: ["10.0.0.0/0"]]])

    assert {:error, :invalid_outbound} = call.(base ++ [outbound: :any])
  end

  describe "calls to an endpoint the operator chose take the option" do
    test "Token.revoke/2", %{base: base, origin: origin} do
      call = fn opts ->
        Token.revoke(
          "token",
          [revocation_endpoint: origin <> "/revoke", client_id: "client", client_auth: :none] ++
            opts
        )
      end

      assert_takes_outbound(call, base)
    end

    test "Token.exchange_pre_authorized_code/2", %{base: base, origin: origin} do
      call = fn opts ->
        Token.exchange_pre_authorized_code(
          "pre-authorized-code",
          [token_endpoint: origin <> "/token", client_auth: :none] ++ opts
        )
      end

      assert_takes_outbound(call, base)
    end

    test "WalletAttestation.fetch_challenge/2", %{base: base, origin: origin} do
      assert_takes_outbound(&WalletAttestation.fetch_challenge(origin <> "/challenge", &1), base)
    end

    test "UserInfo.verify/2 fetches the issuer's keys under it", %{base: base, origin: origin} do
      call = fn opts ->
        UserInfo.verify(
          "header.payload.signature",
          [issuer: @issuer, client_id: "client", jwks_uri: origin <> "/jwks"] ++ opts
        )
      end

      assert_takes_outbound(call, base)
    end

    test "SignedIntrospection.verify/2 fetches the issuer's keys under it",
         %{base: base, origin: origin} do
      call = fn opts ->
        SignedIntrospection.verify(
          "header.payload.signature",
          [issuer: @issuer, audience: "https://rs.example", jwks_uri: origin <> "/jwks"] ++ opts
        )
      end

      assert_takes_outbound(call, base)
    end

    test "the signed-response verifiers refuse allow_loopback_http for a deployed issuer" do
      loopback = [outbound: [allow_loopback_http: true]]

      assert {:error, :invalid_outbound} =
               UserInfo.verify("a.b.c", [issuer: @issuer, client_id: "client"] ++ loopback)

      assert {:error, :invalid_outbound} =
               SignedIntrospection.verify(
                 "a.b.c",
                 [issuer: @issuer, audience: "https://rs.example"] ++ loopback
               )
    end

    test "Wallet.request_credential/3", %{base: base, origin: origin} do
      {:ok, offer} =
        CredentialOffer.parse(%{
          "credential_issuer" => origin,
          "credential_configuration_ids" => ["UniversityDegree"],
          "grants" => %{
            "urn:ietf:params:oauth:grant-type:pre-authorized_code" => %{
              "pre-authorized_code" => "pre-authorized-code"
            }
          }
        })

      holder = JOSE.JWK.generate_key({:ec, "P-256"})
      {_type, trusted} = JOSE.JWK.to_public_map(JOSE.JWK.generate_key({:ec, "P-256"}))

      call = fn opts ->
        Wallet.request_credential(
          offer,
          holder,
          [
            token_endpoint: origin <> "/token",
            credential_endpoint: origin <> "/credential",
            client_id: "wallet",
            format: "vc+sd-jwt",
            trusted: trusted
          ] ++ opts
        )
      end

      assert_takes_outbound(call, base)
    end
  end

  describe "calls to an address another party wrote refuse the option" do
    defp presentation_request(origin) do
      %PresentationRequest{
        client_id: "x509_hash:verifier",
        nonce: "nonce",
        response_uri: origin <> "/response",
        response_mode: "direct_post",
        dcql_query: %{"credentials" => []},
        client_metadata: %{}
      }
    end

    test "CredentialOffer.fetch/2", %{base: base, origin: origin} do
      uri = origin <> "/offer"

      assert {:error, :blocked_host} = CredentialOffer.fetch(uri, base)
      assert @host in resolutions()

      # Refused before anything is resolved or connected to.
      assert {:error, :outbound_not_supported} = CredentialOffer.fetch(uri, base ++ @listed)
      assert resolutions() == []
    end

    test "PresentationRequest.fetch/3 and from_uri/3", %{base: base, origin: origin} do
      trusted = %{}
      uri = origin <> "/request"

      assert {:error, :blocked_host} = PresentationRequest.fetch(uri, trusted, base)
      assert @host in resolutions()

      assert {:error, :outbound_not_supported} =
               PresentationRequest.fetch(uri, trusted, base ++ @listed)

      deep_link =
        "openid4vp://?" <>
          URI.encode_query(%{"client_id" => "x509_hash:verifier", "request_uri" => uri})

      assert {:error, :outbound_not_supported} =
               PresentationRequest.from_uri(deep_link, trusted, base ++ @listed)

      assert resolutions() == []
    end

    test "Presentation.submit/3 and present/3", %{base: base, origin: origin} do
      request = presentation_request(origin)

      assert {:error, :outbound_not_supported} =
               Presentation.submit(request, %{}, base ++ @listed)

      assert {:error, :outbound_not_supported} =
               Presentation.present(request, [], base ++ @listed)

      assert resolutions() == []
    end

    test "a loopback http exception is refused there too", %{origin: origin} do
      loopback = [outbound: [allow_loopback_http: true]]

      assert {:error, :outbound_not_supported} =
               CredentialOffer.fetch("http://localhost:4000/offer", loopback)

      assert {:error, :outbound_not_supported} =
               Presentation.submit(presentation_request(origin), %{}, loopback)
    end
  end

  describe "AttestoClient.Issuer :resolver" do
    @loopback [outbound: [allow_loopback_http: true]]

    # A plain HTTP server on the loopback interface that answers discovery and
    # JWKS requests until the test ends, so the cache makes real requests and
    # its resolver is consulted for each.
    defp start_issuer_server(jwks) do
      {:ok, listener} =
        :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])

      {:ok, port} = :inet.port(listener)
      issuer = "http://localhost:#{port}"

      metadata = %{
        "issuer" => issuer,
        "jwks_uri" => issuer <> "/jwks",
        "token_endpoint" => issuer <> "/token"
      }

      owner = self()

      server =
        spawn_link(fn -> serve(listener, owner, JSON.encode!(metadata), JSON.encode!(jwks)) end)

      on_exit(fn ->
        Process.exit(server, :kill)
        :gen_tcp.close(listener)
      end)

      issuer
    end

    defp serve(listener, owner, metadata, jwks) do
      {:ok, socket} = :gen_tcp.accept(listener)
      {:ok, request} = :gen_tcp.recv(socket, 0, 5_000)
      [request_line | _headers] = String.split(request, "\r\n")
      send(owner, {:requested, request_line})

      body = if request_line =~ "/jwks", do: jwks, else: metadata

      :ok =
        :gen_tcp.send(
          socket,
          "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n" <>
            "content-length: #{byte_size(body)}\r\nconnection: close\r\n\r\n" <> body
        )

      :gen_tcp.close(socket)
      serve(listener, owner, metadata, jwks)
    end

    defp public_jwk(kid) do
      {_type, public} = JOSE.JWK.to_public_map(JOSE.JWK.generate_key({:ec, "P-256"}))
      Map.merge(public, %{"kid" => kid, "alg" => "ES256", "use" => "sig"})
    end

    defp jwt_with_kid(kid) do
      header = Base.url_encode64(JSON.encode!(%{"alg" => "ES256", "kid" => kid}), padding: false)
      header <> ".e30.c2ln"
    end

    defp resolutions do
      receive do
        {:resolved, host} -> [host | resolutions()]
      after
        0 -> []
      end
    end

    test "the resolver given at start resolves discovery, JWKS and an unknown-kid refresh" do
      issuer = start_issuer_server(%{"keys" => [public_jwk("key-1")]})

      cache =
        start_supervised!(
          {Issuer,
           [
             issuer: issuer,
             well_known: :oauth_authorization_server,
             resolver: loopback_resolver(self()),
             unknown_kid_refresh_interval: 0
           ] ++ @loopback}
        )

      assert {:ok, [%{"kid" => "key-1"}]} = Issuer.keys(cache)
      assert_received {:requested, "GET /.well-known/oauth-authorization-server HTTP/1.1"}
      assert_received {:requested, "GET /jwks HTTP/1.1"}

      # One lookup per address family for each of the two requests.
      first = resolutions()
      assert first != []
      assert Enum.uniq(first) == ["localhost"]

      # A token naming a key the snapshot does not hold asks for one refresh,
      # which goes through the same resolver.
      assert {:error, :invalid_signature} =
               Issuer.verify(cache, jwt_with_kid("key-2"), fn _snapshot ->
                 {:error, :invalid_signature}
               end)

      assert_received {:requested, "GET /jwks HTTP/1.1"}
      refreshed = resolutions()
      assert refreshed != []
      assert Enum.uniq(refreshed) == ["localhost"]
    end

    test "without it the cache uses the system resolver, and a bad value is refused at start" do
      issuer = start_issuer_server(%{"keys" => [public_jwk("key-1")]})

      cache =
        start_supervised!(
          {Issuer, [issuer: issuer, well_known: :oauth_authorization_server] ++ @loopback}
        )

      assert {:ok, [%{"kid" => "key-1"}]} = Issuer.keys(cache)
      assert resolutions() == []

      for invalid <- [:inet, fn _host -> {:ok, []} end, {Kernel, :is_atom}] do
        assert_raise ArgumentError,
                     ~r/Issuer :resolver must be a two-argument function/,
                     fn ->
                       Issuer.start_link(issuer: @issuer, resolver: invalid)
                     end
      end
    end

    test "ResourceServer passes its resolver to the cache it is built on" do
      issuer = start_issuer_server(%{"keys" => [public_jwk("key-1")]})

      server =
        start_supervised!(
          {ResourceServer,
           [
             issuer: issuer,
             audience: "https://rs.example",
             accepted_algs: ["ES256"],
             well_known: :oauth_authorization_server,
             resolver: loopback_resolver(self())
           ] ++ @loopback}
        )

      assert :ok = ResourceServer.warm(server)
      assert Enum.uniq(resolutions()) == ["localhost"]

      assert_raise ArgumentError,
                   ~r/ResourceServer :resolver must be a two-argument function/,
                   fn ->
                     ResourceServer.start_link(
                       issuer: @issuer,
                       audience: "https://rs.example",
                       accepted_algs: ["ES256"],
                       resolver: :inet
                     )
                   end
    end
  end
end
