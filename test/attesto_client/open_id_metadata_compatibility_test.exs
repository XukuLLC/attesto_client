defmodule AttestoClient.OpenIDMetadataCompatibilityTest do
  use ExUnit.Case, async: true

  alias AttestoClient.OpenIDMetadata
  alias AttestoClient.Verifier
  alias AttestoClient.Wallet.Presentation.DCQL

  @issuer "https://op.example.com"
  @metadata %{
    "issuer" => @issuer,
    "authorization_endpoint" => "https://op.example.com/authorize",
    "token_endpoint" => "https://op.example.com/token",
    "jwks_uri" => "https://op.example.com/jwks",
    "response_types_supported" => ["code"],
    "subject_types_supported" => ["public"],
    "id_token_signing_alg_values_supported" => ["ES256"]
  }

  test "validate/2 remains a public 2.x compatibility entry point" do
    assert Code.ensure_loaded?(OpenIDMetadata)
    assert function_exported?(OpenIDMetadata, :validate, 2)
    assert :ok = OpenIDMetadata.validate(@metadata, @issuer)

    assert {:error, :issuer_mismatch} =
             OpenIDMetadata.validate(@metadata, "https://other.example.com")

    assert {:error, :invalid_metadata} = OpenIDMetadata.validate(%{}, @issuer)
  end

  test "hidden DCQL helpers remain callable throughout 2.x" do
    held = %{format: "dc+sd-jwt", claims: %{"vct" => "urn:example", "age" => 21}}
    query = %{"format" => "dc+sd-jwt", "meta" => %{"vct_values" => ["urn:example"]}}

    assert DCQL.matches?(held, query)
    assert [21] = DCQL.values_at(held.claims, ["age"])
    assert [] = DCQL.values_at(held.claims, ["missing"])
  end

  test "compact_segments/0 remains a public remote type" do
    assert {:ok, types} = Code.Typespec.fetch_types(Verifier)

    assert Enum.any?(types, fn
             {:type, {:compact_segments, _, []}} -> true
             _other -> false
           end)
  end
end
