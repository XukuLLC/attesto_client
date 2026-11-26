defmodule AttestoClient.DynamicClientRegistrationTest do
  use ExUnit.Case, async: true

  alias AttestoClient.DynamicClientRegistration

  @endpoint "https://authorization.example/register"

  test "requires string-keyed client metadata" do
    plug = fn _conn -> flunk("request must not run") end

    for metadata <- [%{}, %{client_name: "Client"}, %{1 => "Client"}] do
      assert {:error, :invalid_client_metadata} =
               DynamicClientRegistration.register(@endpoint, metadata, req_options: [plug: plug])
    end
  end

  test "requires a valid client identifier in the registration response" do
    for response <- [
          %{},
          %{"client_id" => ""},
          %{"client_id" => 1},
          %{"client_id" => "client", "client_secret" => ""},
          %{"client_id" => "client", "client_id_issued_at" => -1}
        ] do
      plug = fn conn -> json(conn, 201, response) end

      assert {:error, :invalid_registration_response} =
               DynamicClientRegistration.register(
                 @endpoint,
                 %{"client_name" => "Client"},
                 req_options: [plug: plug]
               )
    end
  end

  test "returns a validated RFC 7591 response" do
    response = %{
      "client_id" => "client",
      "client_id_issued_at" => 1,
      "client_secret" => "secret",
      "client_secret_expires_at" => 0,
      "token_endpoint_auth_method" => "client_secret_basic"
    }

    plug = fn conn -> json(conn, 201, response) end

    assert {:ok, ^response} =
             DynamicClientRegistration.register(
               @endpoint,
               %{"client_name" => "Client"},
               req_options: [plug: plug]
             )
  end

  test "does not let a deployed issuer authorize a loopback registration request" do
    plug = fn _conn -> flunk("request must not run") end

    assert {:error, :invalid_outbound} =
             DynamicClientRegistration.register(
               "http://127.0.0.1:45123/register",
               %{"client_name" => "Client"},
               issuer: "https://authorization.example",
               outbound: [allow_loopback_http: true],
               req_options: [plug: plug]
             )
  end

  defp json(conn, status, body) do
    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.send_resp(status, JSON.encode!(body))
  end
end
