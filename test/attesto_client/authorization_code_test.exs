defmodule AttestoClient.AuthorizationCodeTest do
  use ExUnit.Case, async: true

  alias Attesto.SigningAlg
  alias AttestoClient.AuthorizationCode
  alias AttestoClient.AuthorizationTransaction.Store.ETS
  alias AttestoClient.PKCE

  @issuer "https://op.example.com"
  @client_id "client-123"
  @redirect_uri "https://rp.example.com/callback"
  @now System.system_time(:second)
  @key JOSE.JWK.generate_key({:rsa, 2048})

  defp metadata(overrides \\ %{}) do
    Map.merge(
      %{
        "issuer" => @issuer,
        "authorization_endpoint" => "#{@issuer}/authorize",
        "token_endpoint" => "#{@issuer}/token",
        "jwks_uri" => "#{@issuer}/jwks",
        "response_types_supported" => ["code"],
        "subject_types_supported" => ["public"],
        "id_token_signing_alg_values_supported" => ["RS256"],
        "code_challenge_methods_supported" => ["S256"]
      },
      overrides
    )
  end

  defp start_flow(store, opts \\ []) do
    AuthorizationCode.start(
      {ETS, store},
      Keyword.merge(
        [
          issuer: @issuer,
          client_id: @client_id,
          redirect_uri: @redirect_uri,
          metadata: metadata()
        ],
        opts
      )
    )
  end

  defp public_jwks do
    {_, map} = JOSE.JWK.to_public_map(@key)
    %{"keys" => [Map.merge(map, %{"kid" => "signing", "alg" => "RS256", "use" => "sig"})]}
  end

  defp id_token(nonce, access_token, overrides) do
    claims =
      Map.merge(
        %{
          "iss" => @issuer,
          "sub" => "subject-1",
          "aud" => @client_id,
          "iat" => @now,
          "exp" => @now + 600,
          "nonce" => nonce,
          "at_hash" => hash_claim(access_token)
        },
        overrides
      )

    {_, jwt} =
      @key
      |> JOSE.JWT.sign(%{"alg" => "RS256", "kid" => "signing", "typ" => "JWT"}, claims)
      |> JOSE.JWS.compact()

    jwt
  end

  defp hash_claim(value) do
    :sha256
    |> :crypto.hash(value)
    |> binary_part(0, SigningAlg.hash_half_bytes("RS256"))
    |> Base.url_encode64(padding: false)
  end

  test "starts code flow with unguessable state, nonce, and S256 PKCE" do
    store = start_supervised!(ETS)
    assert {:ok, started} = start_flow(store, scopes: ["openid", "profile"])

    params = started.url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
    assert URI.parse(started.url).path == "/authorize"
    assert params["response_type"] == "code"
    assert params["client_id"] == @client_id
    assert params["redirect_uri"] == @redirect_uri
    assert params["scope"] == "openid profile"
    assert params["code_challenge_method"] == "S256"
    assert byte_size(params["state"]) >= 43
    assert byte_size(params["nonce"]) >= 43
    assert byte_size(params["code_challenge"]) == 43
  end

  test "rejects reserved overrides and malformed discovery" do
    store = start_supervised!(ETS)

    assert {:error, :invalid_authorization_params} =
             start_flow(store, authorization_params: %{"state" => "attacker"})

    assert {:error, :invalid_metadata} =
             start_flow(store, metadata: Map.delete(metadata(), "token_endpoint"))

    assert {:error, :issuer_mismatch} =
             start_flow(store, metadata: %{metadata() | "issuer" => "https://other.example"})

    assert {:error, :invalid_metadata} =
             start_flow(store,
               metadata: %{metadata() | "code_challenge_methods_supported" => ["plain"]}
             )

    Enum.each(
      [
        "http://op.example.com",
        "https://user@op.example.com",
        "https://op.example.com?query=1",
        "https://op.example.com#fragment",
        "not-a-url"
      ],
      fn invalid_issuer ->
        assert {:error, :invalid_issuer} =
                 start_flow(store,
                   issuer: invalid_issuer,
                   metadata: %{metadata() | "issuer" => invalid_issuer}
                 )
      end
    )
  end

  test "exchanges once and binds issuer, nonce, access token, and PKCE verifier" do
    store = start_supervised!(ETS)
    assert {:ok, started} = start_flow(store)
    query = started.url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
    parent = self()

    plug = fn conn ->
      case conn.request_path do
        "/token" ->
          {:ok, body, conn} = Plug.Conn.read_body(conn)
          form = URI.decode_query(body)
          send(parent, {:token_form, form})
          access_token = "access-1"

          conn
          |> Plug.Conn.put_resp_content_type("application/json")
          |> Plug.Conn.send_resp(
            200,
            JSON.encode!(%{
              "access_token" => access_token,
              "token_type" => "Bearer",
              "refresh_token" => "refresh-1",
              "id_token" =>
                id_token(query["nonce"], access_token, %{"c_hash" => hash_claim("code-1")})
            })
          )

        "/jwks" ->
          conn
          |> Plug.Conn.put_resp_content_type("application/json")
          |> Plug.Conn.send_resp(200, JSON.encode!(public_jwks()))
      end
    end

    assert {:ok, result} =
             AuthorizationCode.callback(
               {ETS, store},
               %{"state" => started.state, "code" => "code-1", "iss" => @issuer},
               req_options: [plug: plug],
               timeout: 1_000
             )

    assert result.tokens.refresh_token == "refresh-1"
    assert result.id_token_claims["sub"] == "subject-1"

    assert_receive {:token_form, form}
    assert form["grant_type"] == "authorization_code"
    assert form["code"] == "code-1"
    assert form["redirect_uri"] == @redirect_uri
    assert byte_size(form["code_verifier"]) == 43
    assert {:ok, query["code_challenge"]} == PKCE.code_challenge(form["code_verifier"])

    assert {:error, {:invalid_state, :not_found}} =
             AuthorizationCode.callback(
               {ETS, store},
               %{"state" => started.state, "code" => "code-1"},
               req_options: [plug: plug]
             )
  end

  test "validates c_hash when present and permits omission at the token endpoint" do
    store = start_supervised!(ETS)

    Enum.each([{%{}, :ok}, {%{"c_hash" => hash_claim("different-code")}, :invalid_c_hash}], fn
      {claim_overrides, expectation} ->
        assert {:ok, started} = start_flow(store)
        query = started.url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
        access_token = "access"

        plug = fn conn ->
          case conn.request_path do
            "/jwks" ->
              conn
              |> Plug.Conn.put_resp_content_type("application/json")
              |> Plug.Conn.send_resp(200, JSON.encode!(public_jwks()))

            "/token" ->
              json = %{
                "access_token" => access_token,
                "token_type" => "Bearer",
                "id_token" => id_token(query["nonce"], access_token, claim_overrides)
              }

              conn
              |> Plug.Conn.put_resp_content_type("application/json")
              |> Plug.Conn.send_resp(200, JSON.encode!(json))
          end
        end

        result =
          AuthorizationCode.callback(
            {ETS, store},
            %{"state" => started.state, "code" => "code"},
            req_options: [plug: plug]
          )

        case expectation do
          :ok -> assert {:ok, _completed} = result
          error -> assert {:error, ^error} = result
        end
    end)
  end

  test "consumes state for authorization errors, mixed responses, issuer confusion, and expiry" do
    store = start_supervised!(ETS)

    assert {:ok, first} = start_flow(store)

    assert {:error, {:authorization_error, "access_denied", nil}} =
             AuthorizationCode.callback(
               {ETS, store},
               %{"state" => first.state, "error" => "access_denied"}
             )

    assert {:error, {:invalid_state, :not_found}} =
             AuthorizationCode.callback(
               {ETS, store},
               %{"state" => first.state, "code" => "code"}
             )

    assert {:ok, mixed} = start_flow(store)

    assert {:error, :mixed_authorization_response} =
             AuthorizationCode.callback(
               {ETS, store},
               %{"state" => mixed.state, "code" => "code", "error" => "denied"}
             )

    assert {:ok, wrong_issuer} = start_flow(store)

    assert {:error, :issuer_mismatch} =
             AuthorizationCode.callback(
               {ETS, store},
               %{"state" => wrong_issuer.state, "code" => "code", "iss" => "https://evil.example"}
             )

    assert {:ok, required_issuer} =
             start_flow(store,
               metadata: metadata(%{"authorization_response_iss_parameter_supported" => true})
             )

    assert {:error, :missing_response_issuer} =
             AuthorizationCode.callback(
               {ETS, store},
               %{"state" => required_issuer.state, "code" => "code"}
             )

    assert {:ok, expired} = start_flow(store, transaction_ttl_ms: 1)
    assert expired.expires_in == 1
    Process.sleep(5)

    assert {:error, {:invalid_state, :expired}} =
             AuthorizationCode.callback(
               {ETS, store},
               %{"state" => expired.state, "code" => "code"}
             )
  end

  test "a token-endpoint timeout is bounded, never retried, and consumes state" do
    store = start_supervised!(ETS)
    counter = start_supervised!({Agent, fn -> 0 end})
    assert {:ok, started} = start_flow(store)

    plug = fn conn ->
      case conn.request_path do
        "/jwks" ->
          conn
          |> Plug.Conn.put_resp_content_type("application/json")
          |> Plug.Conn.send_resp(200, JSON.encode!(public_jwks()))

        "/token" ->
          Agent.update(counter, &(&1 + 1))
          Process.sleep(200)
          Plug.Conn.send_resp(conn, 500, "late")
      end
    end

    assert {:error, :timeout} =
             AuthorizationCode.callback(
               {ETS, store},
               %{"state" => started.state, "code" => "code"},
               req_options: [plug: plug],
               timeout: 25
             )

    assert Agent.get(counter, & &1) == 1

    assert {:error, {:invalid_state, :not_found}} =
             AuthorizationCode.callback(
               {ETS, store},
               %{"state" => started.state, "code" => "code"}
             )
  end
end
