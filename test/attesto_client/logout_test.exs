defmodule AttestoClient.LogoutTest do
  use ExUnit.Case, async: true

  alias AttestoClient.Logout

  @issuer "https://op.example.com"

  defp metadata(overrides \\ %{}) do
    Map.merge(
      %{
        "issuer" => @issuer,
        "authorization_endpoint" => "#{@issuer}/authorize",
        "token_endpoint" => "#{@issuer}/token",
        "jwks_uri" => "#{@issuer}/jwks",
        "end_session_endpoint" => "#{@issuer}/logout",
        "response_types_supported" => ["code"],
        "subject_types_supported" => ["public"],
        "id_token_signing_alg_values_supported" => ["RS256"]
      },
      overrides
    )
  end

  test "builds an RP-Initiated Logout request without applying session policy" do
    assert {:ok, url} =
             Logout.url(
               issuer: @issuer,
               metadata: metadata(),
               id_token_hint: "id-token",
               client_id: "client",
               post_logout_redirect_uri: "https://rp.example.com/logged-out",
               state: "logout-state"
             )

    uri = URI.parse(url)
    params = URI.decode_query(uri.query)
    assert uri.path == "/logout"
    assert params["id_token_hint"] == "id-token"
    assert params["client_id"] == "client"
    assert params["post_logout_redirect_uri"] == "https://rp.example.com/logged-out"
    assert params["state"] == "logout-state"
  end

  test "requires a logout hint and a discovered end-session endpoint" do
    assert {:error, :missing_logout_hint} = Logout.url(issuer: @issuer, metadata: metadata())

    assert {:error, :missing_end_session_endpoint} =
             Logout.url(
               issuer: @issuer,
               metadata: Map.delete(metadata(), "end_session_endpoint"),
               id_token_hint: "id-token"
             )
  end
end
