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

  test "builds the bare end-session URL when no hint is given" do
    assert {:ok, url} = Logout.url(issuer: @issuer, metadata: metadata())
    assert url == "#{@issuer}/logout"

    assert {:ok, url} =
             Logout.url(
               issuer: @issuer,
               metadata: metadata(),
               client_id: "client",
               post_logout_redirect_uri: "https://rp.example.com/logged-out",
               state: "logout-state"
             )

    uri = URI.parse(url)
    assert uri.path == "/logout"

    assert URI.decode_query(uri.query) == %{
             "client_id" => "client",
             "post_logout_redirect_uri" => "https://rp.example.com/logged-out",
             "state" => "logout-state"
           }
  end

  test "a post-logout redirect needs an ID Token hint or a client_id to name the client" do
    redirect = [post_logout_redirect_uri: "https://rp.example.com/logged-out"]
    base = [issuer: @issuer, metadata: metadata()]

    assert {:error, :missing_client_id} = Logout.url(base ++ redirect)

    assert {:error, :missing_client_id} =
             Logout.url(base ++ redirect ++ [logout_hint: "session-1"])

    assert {:ok, _url} = Logout.url(base ++ redirect ++ [client_id: "client"])
    assert {:ok, _url} = Logout.url(base ++ redirect ++ [id_token_hint: "id-token"])
  end

  test "still validates the provider document without a hint" do
    assert {:error, :invalid_endpoint} =
             Logout.url(
               issuer: @issuer,
               metadata: metadata(%{"end_session_endpoint" => "http://op.example.com/logout"})
             )

    assert {:error, :issuer_mismatch} =
             Logout.url(issuer: "https://other.example.com", metadata: metadata())
  end

  test "requires a discovered end-session endpoint" do
    assert {:error, :missing_end_session_endpoint} =
             Logout.url(
               issuer: @issuer,
               metadata: Map.delete(metadata(), "end_session_endpoint"),
               id_token_hint: "id-token"
             )
  end

  test "builds logout for a provider that advertises only ES256 ID tokens" do
    metadata = metadata(%{"id_token_signing_alg_values_supported" => ["ES256"]})

    assert {:ok, url} =
             Logout.url(
               issuer: @issuer,
               metadata: metadata,
               logout_hint: "session-1"
             )

    assert URI.parse(url).path == "/logout"
  end
end
