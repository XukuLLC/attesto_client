defmodule AttestoClient.TokenUnboundDPoPTest do
  use ExUnit.Case, async: true

  alias AttestoClient.{RefreshCoordinator, Token, TokenSet}

  test "an unsolicited DPoP response requires a locally retained signing key" do
    for type <- ["DPoP", "dpop", "dPoP"] do
      assert {:error, :missing_dpop_key} =
               TokenSet.bind_dpop(%TokenSet{access_token: "access", token_type: type}, nil)

      plug = fn conn ->
        Req.Test.json(conn, %{"access_token" => "access", "token_type" => type})
      end

      assert {:error, :missing_dpop_key} =
               Token.exchange_pre_authorized_code("code",
                 token_endpoint: "https://issuer.example/token",
                 client_id: "client",
                 req_options: [plug: plug]
               )

      coordinator = start_supervised!(RefreshCoordinator, id: make_ref())
      previous = %TokenSet{access_token: "old", token_type: "Bearer", refresh_token: "refresh"}

      assert {:error, :missing_dpop_key} =
               Token.refresh(coordinator, make_ref(), previous,
                 token_endpoint: "https://issuer.example/token",
                 issuer: "https://issuer.example",
                 client_id: "client",
                 subject: "subject",
                 jwks: %{"keys" => []},
                 req_options: [plug: plug]
               )
    end
  end

  test "generic Bearer responses remain available without invented key provenance" do
    tokens = %TokenSet{access_token: "access", token_type: "Bearer"}
    assert {:ok, ^tokens} = TokenSet.bind_dpop(tokens, nil)
  end
end
