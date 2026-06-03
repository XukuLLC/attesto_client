defmodule AttestoClient.DiscoveryTest do
  use ExUnit.Case, async: true

  alias AttestoClient.Discovery

  @issuer "https://op.example.com"

  # A Req plug that responds with `status` and `body` as JSON (Req decodes it
  # back to a map), so these tests never touch the network.
  defp json_plug(status, body) do
    fn conn ->
      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.send_resp(status, JSON.encode!(body))
    end
  end

  defp fetch(issuer, plug, opts \\ []) do
    Discovery.fetch(issuer, [req_options: [plug: plug]] ++ opts)
  end

  describe "fetch/2" do
    test "fetches and returns the metadata" do
      meta = %{
        "issuer" => @issuer,
        "jwks_uri" => "#{@issuer}/.well-known/jwks.json",
        "token_endpoint" => "#{@issuer}/oauth/token"
      }

      assert {:ok, m} = fetch(@issuer, json_plug(200, meta))
      assert m["jwks_uri"] == "#{@issuer}/.well-known/jwks.json"
      assert m["token_endpoint"] == "#{@issuer}/oauth/token"
    end

    test "requests the openid-configuration well-known path by default" do
      plug = fn conn ->
        assert conn.request_path == "/.well-known/openid-configuration"
        json_plug(200, %{"issuer" => @issuer}).(conn)
      end

      assert {:ok, _} = fetch(@issuer, plug)
    end

    test "uses the RFC 8414 document (segment before path) for a path-based issuer" do
      issuer = "https://op.example.com/tenant"

      plug = fn conn ->
        # RFC 8414 §3.1: inserted before the issuer path, not appended.
        assert conn.request_path == "/.well-known/oauth-authorization-server/tenant"
        json_plug(200, %{"issuer" => issuer}).(conn)
      end

      assert {:ok, _} = fetch(issuer, plug, well_known: :oauth_authorization_server)
    end

    test "normalises a trailing slash for both the request and the issuer match" do
      plug = fn conn ->
        assert conn.request_path == "/.well-known/openid-configuration"
        # The authorization server's canonical issuer has no trailing slash.
        json_plug(200, %{"issuer" => "https://op.example.com"}).(conn)
      end

      assert {:ok, _} = fetch("https://op.example.com/", plug)
    end

    test "rejects a non-https issuer, or one with a query or fragment (RFC 8414 §2)" do
      assert {:error, :invalid_issuer} = Discovery.fetch("http://op.example.com")
      assert {:error, :invalid_issuer} = Discovery.fetch("not a url")
      assert {:error, :invalid_issuer} = Discovery.fetch("https://op.example.com?x=1")
      assert {:error, :invalid_issuer} = Discovery.fetch("https://op.example.com#frag")
      assert {:error, :invalid_issuer} = Discovery.fetch(:not_a_string)
    end

    test "rejects an issuer mismatch (RFC 8414 §3.3)" do
      assert {:error, :issuer_mismatch} =
               fetch(@issuer, json_plug(200, %{"issuer" => "https://evil.example"}))
    end

    test "surfaces a non-200 status" do
      assert {:error, {:http_status, 404}} = fetch(@issuer, json_plug(404, %{"error" => "nope"}))
    end
  end

  describe "fetch_jwks/2" do
    test "returns a keys document" do
      jwks = %{"keys" => [%{"kty" => "EC", "crv" => "P-256", "kid" => "k1"}]}

      assert {:ok, result} =
               Discovery.fetch_jwks("#{@issuer}/jwks", req_options: [plug: json_plug(200, jwks)])

      assert [%{"kid" => "k1"}] = result["keys"]
    end

    test "rejects a document without a keys list" do
      assert {:error, :invalid_metadata} =
               Discovery.fetch_jwks("#{@issuer}/jwks",
                 req_options: [plug: json_plug(200, %{"x" => 1})]
               )
    end

    test "rejects a non-https (or non-string) JWKS URI - it is the signature trust root" do
      assert {:error, :invalid_jwks_uri} = Discovery.fetch_jwks("http://op.example.com/jwks")
      assert {:error, :invalid_jwks_uri} = Discovery.fetch_jwks("not a url")
      assert {:error, :invalid_jwks_uri} = Discovery.fetch_jwks(:nope)
    end
  end

  describe "interop" do
    defmodule Keystore do
      @moduledoc false
      @behaviour Attesto.Keystore

      @pem JOSE.JWK.generate_key({:ec, "P-256"}) |> JOSE.JWK.to_pem() |> elem(1)

      @impl true
      def signing_pem, do: @pem
      @impl true
      def verification_pems, do: [@pem]
    end

    test "reads the metadata that attesto's OpenIDDiscovery produces" do
      protocol_config =
        Attesto.Config.new(
          issuer: @issuer,
          audience: @issuer,
          keystore: Keystore,
          principal_kinds: [Attesto.PrincipalKind.new("user", "usr_")]
        )

      served = Attesto.OpenIDDiscovery.metadata(protocol_config)

      assert {:ok, m} = fetch(@issuer, json_plug(200, served))
      assert m["issuer"] == @issuer
      assert is_binary(m["token_endpoint"])
      assert is_binary(m["jwks_uri"])
    end
  end
end
