defmodule AttestoClient.WalletAttestationChallengeTest do
  use ExUnit.Case, async: true

  alias AttestoClient.OAuthHTTP
  alias AttestoClient.WalletAttestation

  @endpoint "https://as.example.com/challenge"

  test "fetches an empty unauthenticated POST and returns only validated challenge data" do
    plug = fn conn ->
      assert conn.method == "POST"
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      assert body == ""
      assert Plug.Conn.get_req_header(conn, "accept") == ["application/json"]
      assert Plug.Conn.get_req_header(conn, "x-request-id") == ["request"]

      for header <- ~w(authorization dpop oauth-client-attestation oauth-client-attestation-pop) do
        assert Plug.Conn.get_req_header(conn, header) == []
      end

      conn
      |> Plug.Conn.put_resp_header("dpop-nonce", "first-dpop-nonce")
      |> Req.Test.json(%{
        "attestation_challenge" => "first-challenge",
        "expires_in" => 90,
        "extension" => "ignored"
      })
    end

    assert {:ok, %{challenge: "first-challenge", dpop_nonce: "first-dpop-nonce", expires_in: 90}} =
             WalletAttestation.fetch_challenge(@endpoint,
               client_auth: {:client_secret_basic, "unused"},
               req_options: [
                 auth: {:bearer, "unused"},
                 headers: [
                   {"Accept", "text/plain"},
                   {"authorization", "unused"},
                   {"dpop", "unused"},
                   {"oauth-client-attestation", "unused"},
                   {"oauth-client-attestation-pop", "unused"},
                   {"x-request-id", "request"}
                 ],
                 plug: plug
               ]
             )
  end

  test "accepts an omitted lifetime and nonce without inventing an expiration" do
    assert {:ok, %{challenge: "challenge", dpop_nonce: nil, expires_in: nil}} =
             fetch_json(%{"attestation_challenge" => "challenge"})
  end

  test "requires the endpoint's exact success status and JSON media type" do
    for status <- [201, 202, 302, 400] do
      assert {:error, {:http_status, ^status}} =
               fetch_response(status, "application/json", "{\"attestation_challenge\":\"ok\"}")
    end

    for media_type <- ["text/plain", "application/jwt", "application/problem+json"] do
      assert {:error, :invalid_challenge_response} =
               fetch_response(200, media_type, "{\"attestation_challenge\":\"ok\"}")
    end

    assert {:ok, %{challenge: "ok"}} =
             fetch_response(
               200,
               "Application/JSON; charset=utf-8",
               "{\"attestation_challenge\":\"ok\"}"
             )
  end

  test "rejects missing, invalid or oversized challenge and optional lifetime values" do
    assert {:error, :invalid_challenge_response} = fetch_json(%{})

    for challenge <- [nil, "", 42, [], %{}, String.duplicate("x", 4_097)] do
      assert {:error, :invalid_challenge_response} =
               fetch_json(%{"attestation_challenge" => challenge})
    end

    for lifetime <- [nil, 0, -1, 1.5, "90"] do
      assert {:error, :invalid_challenge_response} =
               fetch_json(%{"attestation_challenge" => "ok", "expires_in" => lifetime})
    end
  end

  test "rejects ambiguous JSON, malformed responses and invalid nonce headers" do
    for body <- [
          "{\"attestation_challenge\":\"one\",\"attestation_challenge\":\"two\"}",
          "{\"attestation_challenge\":\"ok\",\"extra\":{\"x\":1,\"x\":2}}",
          "[]",
          "null",
          "not-json"
        ] do
      assert {:error, :invalid_challenge_response} = fetch_response(200, "application/json", body)
    end

    for values <- [[""], [String.duplicate("x", 4_097)], ["one", "two"]] do
      plug = fn conn ->
        conn
        |> Plug.Conn.put_resp_header("dpop-nonce", "unused")
        |> Map.update!(:resp_headers, fn headers ->
          Enum.reject(headers, fn {key, _} -> key == "dpop-nonce" end) ++
            Enum.map(values, &{"dpop-nonce", &1})
        end)
        |> Req.Test.json(%{"attestation_challenge" => "ok"})
      end

      assert {:error, :invalid_challenge_response} =
               WalletAttestation.fetch_challenge(@endpoint, req_options: [plug: plug])
    end
  end

  test "bounds response bytes and rejects unsafe endpoints before HTTP" do
    body =
      JSON.encode!(%{"attestation_challenge" => "ok", "padding" => String.duplicate("x", 16_384)})

    assert {:error, :response_too_large} = fetch_response(200, "application/json", body)

    for endpoint <- [
          "http://as.example.com",
          "https://user:password@as.example.com",
          "https://as.example.com/#fragment"
        ] do
      assert {:error, :invalid_endpoint} =
               WalletAttestation.fetch_challenge(endpoint,
                 req_options: [plug: fn _ -> flunk("unexpected request") end]
               )
    end
  end

  test "uses proactively fetched values in first proofs and replaces a DPoP nonce on one retry" do
    {:ok, challenge} =
      fetch_json(%{"attestation_challenge" => "attestation-challenge"}, "initial-nonce")

    key = JOSE.JWK.generate_key({:ec, "P-256"})
    count = start_supervised!({Agent, fn -> 0 end})
    owner = self()

    plug = fn conn ->
      [pop] = Plug.Conn.get_req_header(conn, "oauth-client-attestation-pop")
      [proof] = Plug.Conn.get_req_header(conn, "dpop")
      attempt = Agent.get_and_update(count, &{&1, &1 + 1})
      send(owner, {:proofs, attempt, claims(pop), claims(proof)})

      if attempt == 0 do
        conn
        |> Plug.Conn.put_resp_header("dpop-nonce", "newest-nonce")
        |> Plug.Conn.put_status(400)
        |> Req.Test.json(%{"error" => "use_dpop_nonce"})
      else
        conn
        |> Plug.Conn.put_status(201)
        |> Req.Test.json(%{"request_uri" => "urn:example:request"})
      end
    end

    assert {:ok, %{"request_uri" => "urn:example:request"}} =
             OAuthHTTP.post_form("https://as.example.com/par", %{},
               client_id: "wallet",
               client_auth:
                 {:client_attestation, "attestation", key,
                  [audience: "https://as.example.com", challenge: challenge.challenge]},
               dpop: key,
               dpop_nonce: challenge.dpop_nonce,
               expected_status: 201,
               req_options: [plug: plug]
             )

    assert_receive {:proofs, 0, first_pop, first_dpop}
    assert_receive {:proofs, 1, second_pop, second_dpop}
    assert first_pop["challenge"] == "attestation-challenge"
    assert second_pop["challenge"] == "attestation-challenge"
    assert first_dpop["nonce"] == "initial-nonce"
    assert second_dpop["nonce"] == "newest-nonce"
    refute first_dpop["jti"] == second_dpop["jti"]
    refute first_pop["jti"] == second_pop["jti"]
    refute_receive {:proofs, 2, _, _}
  end

  test "rejects invalid seeded DPoP nonce before transport" do
    for nonce <- ["", 42, [], String.duplicate("x", 4_097)] do
      assert {:error, :invalid_dpop_nonce} =
               OAuthHTTP.post_form("https://as.example.com/par", %{},
                 client_id: "wallet",
                 dpop_nonce: nonce,
                 req_options: [plug: fn _ -> flunk("unexpected request") end]
               )
    end
  end

  defp fetch_json(body, nonce \\ nil) do
    plug = fn conn ->
      conn = if nonce, do: Plug.Conn.put_resp_header(conn, "dpop-nonce", nonce), else: conn
      Req.Test.json(conn, body)
    end

    WalletAttestation.fetch_challenge(@endpoint, req_options: [plug: plug])
  end

  defp fetch_response(status, media_type, body) do
    plug = fn conn ->
      conn
      |> Plug.Conn.put_resp_header("content-type", media_type)
      |> Plug.Conn.send_resp(status, body)
    end

    WalletAttestation.fetch_challenge(@endpoint, req_options: [plug: plug])
  end

  defp claims(jwt), do: jwt |> JOSE.JWS.peek_payload() |> JSON.decode!()
end
