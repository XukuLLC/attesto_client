defmodule AttestoClient.Wallet.CredentialOfferTest do
  use ExUnit.Case, async: true

  alias AttestoClient.Wallet.CredentialOffer

  @issuer "https://issuer.example.com"

  @pre_authorized_offer %{
    "credential_issuer" => @issuer,
    "credential_configuration_ids" => ["UniversityDegree"],
    "grants" => %{
      "urn:ietf:params:oauth:grant-type:pre-authorized_code" => %{
        "pre-authorized_code" => "pre-auth-code-123",
        "tx_code" => %{"input_mode" => "numeric", "length" => 4, "description" => "Enter the PIN"}
      }
    }
  }

  defp json_plug(status, body) do
    fn conn ->
      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.send_resp(status, JSON.encode!(body))
    end
  end

  describe "parse/1 - by value" do
    test "parses a decoded JSON offer object with a pre-authorized_code grant" do
      assert {:ok, offer} = CredentialOffer.parse(@pre_authorized_offer)
      assert offer.credential_issuer == @issuer
      assert offer.credential_configuration_ids == ["UniversityDegree"]
      assert offer.grants.authorization_code == nil

      assert offer.grants.pre_authorized_code == %{
               code: "pre-auth-code-123",
               authorization_server: nil,
               tx_code: %{input_mode: "numeric", length: 4, description: "Enter the PIN"}
             }
    end

    test "parses a raw JSON string" do
      assert {:ok, offer} = CredentialOffer.parse(JSON.encode!(@pre_authorized_offer))
      assert offer.credential_issuer == @issuer
    end

    test "defaults to an implied authorization_code grant when grants is omitted" do
      offer = Map.delete(@pre_authorized_offer, "grants")
      assert {:ok, parsed} = CredentialOffer.parse(offer)

      assert parsed.grants == %{
               pre_authorized_code: nil,
               authorization_code: %{issuer_state: nil, authorization_server: nil}
             }
    end

    test "parses an authorization_code grant with issuer_state" do
      offer = %{
        "credential_issuer" => @issuer,
        "credential_configuration_ids" => ["UniversityDegree"],
        "grants" => %{"authorization_code" => %{"issuer_state" => "state-abc"}}
      }

      assert {:ok, parsed} = CredentialOffer.parse(offer)

      assert parsed.grants.authorization_code == %{
               issuer_state: "state-abc",
               authorization_server: nil
             }

      assert parsed.grants.pre_authorized_code == nil
    end

    test "an already-parsed offer struct passes through" do
      assert {:ok, offer} = CredentialOffer.parse(@pre_authorized_offer)
      assert {:ok, ^offer} = CredentialOffer.parse(offer)
    end
  end

  describe "parse/1 - openid-credential-offer:// deep link" do
    test "extracts and decodes a by-value credential_offer query parameter" do
      value = @pre_authorized_offer |> JSON.encode!() |> URI.encode_www_form()
      link = "openid-credential-offer://?credential_offer=#{value}"

      assert {:ok, offer} = CredentialOffer.parse(link)
      assert offer.credential_issuer == @issuer
    end

    test "returns {:fetch, uri} for a by-reference credential_offer_uri" do
      uri = "https://issuer.example.com/offers/abc123"
      link = "openid-credential-offer://?credential_offer_uri=#{URI.encode_www_form(uri)}"

      assert {:fetch, ^uri} = CredentialOffer.parse(link)
    end

    test "rejects a link with neither query parameter" do
      assert {:error, :missing_credential_offer} =
               CredentialOffer.parse("openid-credential-offer://?other=1")
    end

    test "rejects a link carrying both query parameters" do
      link =
        "openid-credential-offer://?credential_offer=%7B%7D&credential_offer_uri=https://x.example/o"

      assert {:error, :ambiguous_credential_offer} = CredentialOffer.parse(link)
    end
  end

  describe "fetch/2 - by-reference offer" do
    test "GETs and parses the referenced offer" do
      plug = fn conn ->
        assert conn.request_path == "/offers/abc123"
        assert conn.method == "GET"
        json_plug(200, @pre_authorized_offer).(conn)
      end

      assert {:ok, offer} =
               CredentialOffer.fetch("https://issuer.example.com/offers/abc123",
                 req_options: [plug: plug]
               )

      assert offer.credential_issuer == @issuer
      assert offer.grants.pre_authorized_code.code == "pre-auth-code-123"
    end

    test "surfaces a non-200 status" do
      assert {:error, {:http_status, 404}} =
               CredentialOffer.fetch("https://issuer.example.com/offers/missing",
                 req_options: [plug: json_plug(404, %{"error" => "not_found"})]
               )
    end
  end

  describe "parse/1 rejects invalid input (fail fast)" do
    test "missing/invalid credential_issuer" do
      assert {:error, :invalid_credential_issuer} =
               CredentialOffer.parse(Map.delete(@pre_authorized_offer, "credential_issuer"))

      assert {:error, :invalid_credential_issuer} =
               CredentialOffer.parse(Map.put(@pre_authorized_offer, "credential_issuer", ""))
    end

    test "missing/empty credential_configuration_ids" do
      assert {:error, :invalid_credential_configuration_ids} =
               CredentialOffer.parse(
                 Map.delete(@pre_authorized_offer, "credential_configuration_ids")
               )

      assert {:error, :invalid_credential_configuration_ids} =
               CredentialOffer.parse(
                 Map.put(@pre_authorized_offer, "credential_configuration_ids", [])
               )
    end

    test "an empty grants object (neither grant type present)" do
      assert {:error, :invalid_grants} =
               CredentialOffer.parse(Map.put(@pre_authorized_offer, "grants", %{}))
    end

    test "a pre-authorized_code grant missing its code" do
      offer =
        Map.put(@pre_authorized_offer, "grants", %{
          "urn:ietf:params:oauth:grant-type:pre-authorized_code" => %{}
        })

      assert {:error, :invalid_pre_authorized_code_grant} = CredentialOffer.parse(offer)
    end

    test "malformed JSON" do
      assert {:error, :invalid_json} = CredentialOffer.parse("{not json")
    end

    test "not a map, string, or struct" do
      assert {:error, :invalid_credential_offer} = CredentialOffer.parse(123)
    end
  end
end
