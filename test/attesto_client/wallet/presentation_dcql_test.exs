defmodule AttestoClient.Wallet.PresentationDCQLTest do
  use ExUnit.Case, async: true
  alias AttestoClient.Wallet.Presentation
  alias AttestoClient.Wallet.Presentation.DCQL

  defp held do
    %{
      format: "dc+sd-jwt",
      claims: %{
        "vct" => "identity",
        "name" => "Alice",
        "age" => 25,
        "address" => %{"city" => "Example"},
        "roles" => [%{"name" => "reader"}]
      },
      authority_key_identifiers: ["trusted-aki"]
    }
  end

  defp credential(id \\ "identity"),
    do: %{"id" => id, "format" => "dc+sd-jwt", "meta" => %{"vct_values" => ["identity"]}}

  defp query(credential), do: %{"credentials" => [credential]}

  test "nested, wildcard and exact typed values are matched without ignoring unsupported paths" do
    q =
      credential()
      |> Map.put("claims", [
        %{"path" => ["address", "city"]},
        %{"path" => ["roles", nil, "name"], "values" => ["reader"]}
      ])

    assert {:ok, %{"identity" => _}} = Presentation.select(query(q), [held()])

    for claim <- [
          %{"path" => ["missing", "name"]},
          %{"path" => ["age"], "values" => ["25"]},
          %{"path" => ["roles", 4, "name"]}
        ] do
      assert {:error, {:no_match, "identity"}} =
               Presentation.select(query(Map.put(credential(), "claims", [claim])), [held()])
    end
  end

  test "claim alternatives choose only a matching combination" do
    claims = [
      %{"id" => "name", "path" => ["name"]},
      %{"id" => "absent", "path" => ["missing"]},
      %{"id" => "age", "path" => ["age"]}
    ]

    q =
      credential()
      |> Map.merge(%{"claims" => claims, "claim_sets" => [["absent"], ["name"], ["age"]]})

    assert {:ok, _} = Presentation.select(query(q), [held()])
    assert DCQL.paths(q, held()) == [["name"]]
  end

  test "optional unavailable credential set is omitted while required alternatives are satisfied" do
    missing = Map.put(credential("other"), "meta", %{"vct_values" => ["other"]})

    q = %{
      "credentials" => [credential(), missing],
      "credential_sets" => [
        %{"options" => [["other"], ["identity"]]},
        %{"options" => [["other"]], "required" => false}
      ]
    }

    assert {:ok, %{"identity" => _} = selected} = Presentation.select(q, [held()])
    assert :ok = DCQL.validate_selection(q, selected)
    q = put_in(q["credential_sets"], [%{"options" => [["other"]]}])
    assert {:error, :access_denied} = Presentation.select(q, [held()])
  end

  test "explicit host selection cannot bypass format, claims or issuer provenance" do
    q =
      query(
        credential()
        |> Map.put("trusted_authorities", [%{"type" => "aki", "values" => ["trusted-aki"]}])
      )

    assert :ok = DCQL.validate_selection(q, %{"identity" => held()})

    assert {:error, :invalid_selection} =
             DCQL.validate_selection(q, %{
               "identity" => Map.delete(held(), :authority_key_identifiers)
             })

    assert {:error, :invalid_selection} = DCQL.validate_selection(q, %{"unknown" => held()})

    assert {:error, :invalid_selection} =
             DCQL.validate_selection(q, %{"identity" => %{held() | format: "mso_mdoc"}})

    unsupported =
      query(
        credential()
        |> Map.put("trusted_authorities", [%{"type" => "unsupported", "values" => ["anything"]}])
      )

    assert {:error, {:no_match, "identity"}} = Presentation.select(unsupported, [held()])
  end

  test "malformed DCQL constraints fail before selection or disclosure" do
    for q <- [
          query(Map.put(credential(), "id", "invalid.id")),
          query(Map.put(credential(), "claims", [%{"path" => []}])),
          query(Map.put(credential(), "claims", [%{"path" => ["age"], "values" => [1.5]}])),
          query(
            Map.merge(credential(), %{
              "claims" => [%{"path" => ["name"]}],
              "claim_sets" => [["not-defined"]]
            })
          ),
          %{
            "credentials" => [credential()],
            "credential_sets" => [%{"options" => [["not-defined"]]}]
          },
          query(
            Map.put(credential(), "trusted_authorities", [%{"type" => "aki", "values" => []}])
          )
        ] do
      assert {:error, :invalid_dcql_query} = Presentation.select(q, [held()])
    end
  end

  test "mdoc paths are exactly namespace plus element and claim-set IDs are mandatory" do
    mdoc = %{
      format: "mso_mdoc",
      claims: %{"namespace" => %{"element" => %{-1 => "value"}}},
      doc_type: "document"
    }

    q = %{
      "id" => "doc",
      "format" => "mso_mdoc",
      "claims" => [%{"path" => ["namespace", "element"]}]
    }

    assert {:ok, %{"doc" => ^mdoc}} = Presentation.select(query(q), [mdoc])
    extra_segment = put_in(q["claims"], [%{"path" => ["namespace", "element", -1]}])
    assert {:error, :invalid_dcql_query} = Presentation.select(query(extra_segment), [mdoc])

    missing_id =
      credential()
      |> Map.merge(%{
        "claims" => [%{"id" => "name", "path" => ["name"]}, %{"path" => ["age"]}],
        "claim_sets" => [["name"]]
      })

    assert {:error, :invalid_dcql_query} = Presentation.select(query(missing_id), [held()])
  end

  test "a wildcard aborts on inconsistent JSON element types instead of accepting a partial match" do
    q = credential() |> Map.put("claims", [%{"path" => ["roles", nil, "name"]}])
    invalid = put_in(held().claims["roles"], [%{"name" => "reader"}, 1])
    assert {:error, {:no_match, "identity"}} = Presentation.select(query(q), [invalid])
  end
end
