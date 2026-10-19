defmodule AttestoClient.WWWAuthenticateTest do
  use ExUnit.Case, async: true

  alias AttestoClient.WWWAuthenticate

  doctest WWWAuthenticate

  describe "parse/1" do
    test "reads a scheme with quoted and bare parameters" do
      assert [%{scheme: "bearer", params: params, token68: nil}] =
               WWWAuthenticate.parse(~s(Bearer realm="api", error=invalid_token, scope="a b"))

      assert params == %{"realm" => "api", "error" => "invalid_token", "scope" => "a b"}
    end

    test "reads several challenges from one field and from a list of fields" do
      header = ~s(Bearer realm="resource", DPoP error="use_dpop_nonce", algs="ES256")

      assert [
               %{scheme: "bearer", params: %{"realm" => "resource"}},
               %{scheme: "dpop", params: %{"error" => "use_dpop_nonce", "algs" => "ES256"}}
             ] = WWWAuthenticate.parse(header)

      assert [%{scheme: "bearer"}, %{scheme: "dpop"}] =
               WWWAuthenticate.parse([
                 ~s(Bearer realm="resource"),
                 ~s(DPoP error="use_dpop_nonce")
               ])
    end

    test "lowercases scheme and parameter names but keeps values" do
      assert [%{scheme: "dpop", params: %{"error" => "Use_DPoP_Nonce"}}] =
               WWWAuthenticate.parse(~s(DPOP Error="Use_DPoP_Nonce"))
    end

    test "unescapes quoted strings and keeps a comma inside them from splitting the member" do
      assert [%{scheme: "bearer", params: %{"realm" => ~s(a "quoted", value\\)}}] =
               WWWAuthenticate.parse(~s(Bearer realm="a \\"quoted\\", value\\\\"))
    end

    test "reads a token68 credential, including trailing padding" do
      assert [%{scheme: "negotiate", params: %{}, token68: "YWJj=="}] =
               WWWAuthenticate.parse("Negotiate YWJj==")

      assert [%{scheme: "negotiate", token68: nil}] = WWWAuthenticate.parse("Negotiate")
    end

    test "keeps the first value of a repeated parameter" do
      assert [%{params: %{"realm" => "first"}}] =
               WWWAuthenticate.parse(~s(Bearer realm="first", realm="second"))
    end

    test "drops a parameter that precedes any scheme and a malformed member" do
      assert [%{scheme: "bearer", params: %{"realm" => "x"}}] =
               WWWAuthenticate.parse(~s(error="orphan", Bearer realm="x", bad"member", , ))
    end

    test "tolerates whitespace around the parameter separator" do
      assert [%{scheme: "dpop", params: %{"error" => "use_dpop_nonce"}}] =
               WWWAuthenticate.parse("DPoP error = use_dpop_nonce")
    end

    test "treats an oversized, invalid, or non-string value as no challenges" do
      assert WWWAuthenticate.parse("Bearer " <> String.duplicate("a", 9_000)) == []
      assert WWWAuthenticate.parse(<<0xFF, 0xFE>>) == []
      assert WWWAuthenticate.parse(nil) == []
      assert WWWAuthenticate.parse(%{}) == []
    end
  end

  describe "resource_metadata/1" do
    @url "https://rs.example/.well-known/oauth-protected-resource/mcp"

    test "returns the first valid pointer from a field, a list, or parsed challenges" do
      header = ~s(Bearer error="invalid_token", resource_metadata="#{@url}")

      assert {:ok, @url} = WWWAuthenticate.resource_metadata(header)
      assert {:ok, @url} = WWWAuthenticate.resource_metadata([~s(Basic realm="x"), header])

      assert {:ok, @url} =
               header |> WWWAuthenticate.parse() |> WWWAuthenticate.resource_metadata()
    end

    test "skips a pointer that is not an https identifier" do
      assert :error =
               WWWAuthenticate.resource_metadata(
                 ~s(Bearer resource_metadata="http://rs.example/prm")
               )

      assert :error =
               WWWAuthenticate.resource_metadata(
                 ~s(Bearer resource_metadata="https://rs.example/prm#frag")
               )

      assert :error =
               WWWAuthenticate.resource_metadata(
                 ~s(Bearer resource_metadata="https://u@rs.example/prm")
               )

      assert {:ok, @url} =
               WWWAuthenticate.resource_metadata([
                 ~s(Bearer resource_metadata="http://rs.example/prm"),
                 ~s(DPoP resource_metadata="#{@url}")
               ])
    end

    test "is :error without a pointer" do
      assert :error = WWWAuthenticate.resource_metadata(~s(Bearer realm="api"))
      assert :error = WWWAuthenticate.resource_metadata([])
    end
  end
end
