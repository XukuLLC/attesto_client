defmodule AttestoClient.OAuthHTTPTest do
  use ExUnit.Case, async: true

  alias AttestoClient.OAuthHTTP

  @endpoint "https://op.example.com/token"

  defp call(client_auth, parent) do
    plug = fn conn ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)

      send(
        parent,
        {:request, Plug.Conn.get_req_header(conn, "authorization"), URI.decode_query(body)}
      )

      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.send_resp(200, JSON.encode!(%{"ok" => true}))
    end

    OAuthHTTP.post_form(@endpoint, %{"grant_type" => "authorization_code"},
      client_id: "client id:one",
      client_auth: client_auth,
      req_options: [plug: plug]
    )
  end

  test "supports public and client_secret_post authentication" do
    assert {:ok, %{"ok" => true}} = call(:none, self())
    assert_receive {:request, [], %{"client_id" => "client id:one"}}

    assert {:ok, %{"ok" => true}} = call({:client_secret_post, "s:e c"}, self())

    assert_receive {:request, [], form}
    assert form["client_id"] == "client id:one"
    assert form["client_secret"] == "s:e c"
  end

  test "form-encodes client_secret_basic credentials before base64" do
    assert {:ok, _response} = call({:client_secret_basic, "s:e c"}, self())
    assert_receive {:request, ["Basic " <> encoded], form}
    assert Base.decode64!(encoded) == "client+id%3Aone:s%3Ae+c"
    refute Map.has_key?(form, "client_id")
    refute Map.has_key?(form, "client_secret")
  end

  test "supports private_key_jwt defaults and registered assertion overrides" do
    key = JOSE.JWK.generate_key({:rsa, 2048})

    assert {:ok, _response} =
             call(
               {:private_key_jwt, key,
                [
                  audience: "https://op.example.com/custom-audience",
                  alg: "RS256",
                  kid: "registered-key",
                  now: 1_700_000_000,
                  jti: "assertion-jti"
                ]},
               self()
             )

    assert_receive {:request, [], form}
    assert form["client_id"] == "client id:one"
    assert form["client_assertion_type"] == AttestoClient.ClientAssertion.assertion_type()

    [header, claims, _signature] = String.split(form["client_assertion"], ".")
    assert %{"alg" => "RS256", "kid" => "registered-key"} = decode_segment(header)

    assert %{
             "iss" => "client id:one",
             "sub" => "client id:one",
             "aud" => "https://op.example.com/custom-audience",
             "jti" => "assertion-jti"
           } = decode_segment(claims)

    assert {:error, :invalid_client_assertion_options} =
             call({:private_key_jwt, key, [algg: "RS256"]}, self())

    assert {:error, :invalid_client_assertion_options} =
             call({:private_key_jwt, key, [alg: "RS256", alg: "PS256"]}, self())
  end

  defp decode_segment(segment) do
    {:ok, json} = Base.url_decode64(segment, padding: false)
    JSON.decode!(json)
  end
end
