defmodule AttestoClient.TokenSetTest do
  use ExUnit.Case, async: true

  alias AttestoClient.TokenSet

  @response %{"access_token" => "access", "token_type" => "Bearer", "refresh_token" => "refresh"}

  test "refresh expiry durations remain literal, including zero and very large values" do
    for timeout <- [0, 60, 10_000_000_000_000] do
      response =
        Map.merge(@response, %{
          "refresh_token_timeout" => timeout,
          "authorization_expires_in" => timeout + 1
        })

      assert {:ok, tokens} = TokenSet.from_response(response, nil)
      assert tokens.refresh_token_timeout == timeout
      assert tokens.authorization_expires_in == timeout + 1
    end
  end

  test "invalid or contradictory refresh expiry information fails response validation" do
    for field <- ["refresh_token_timeout", "authorization_expires_in"],
        invalid <- [-1, 1.5, "60", nil] do
      assert {:error, :invalid_token_response} =
               TokenSet.from_response(Map.put(@response, field, invalid), nil)
    end

    response =
      Map.merge(@response, %{"refresh_token_timeout" => 61, "authorization_expires_in" => 60})

    assert {:error, :invalid_token_response} = TokenSet.from_response(response, nil)
  end

  test "omitted durations stay unknown and unrelated extensions survive" do
    assert {:ok, tokens} = TokenSet.from_response(Map.put(@response, "extension", "value"), nil)
    assert tokens.refresh_token_timeout == nil
    assert tokens.authorization_expires_in == nil
    assert tokens.extra == %{"extension" => "value"}
  end

  test "wire thumbprints cannot supply local DPoP provenance" do
    response = Map.put(@response, "dpop_jkt", "untrusted-thumbprint")
    assert {:ok, tokens} = TokenSet.from_response(response, nil)
    assert tokens.dpop_jkt == nil
    assert tokens.extra["dpop_jkt"] == "untrusted-thumbprint"
  end
end
