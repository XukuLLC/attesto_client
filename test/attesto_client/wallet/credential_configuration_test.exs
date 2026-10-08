defmodule AttestoClient.Wallet.CredentialConfigurationTest do
  use ExUnit.Case, async: true

  alias Attesto.{Mdoc, SdJwtVc}
  alias AttestoClient.Wallet
  alias AttestoClient.Wallet.CredentialOffer

  @issuer "https://issuer.example"
  @configuration_id "ExampleCredential"
  @doctype "org.iso.18013.5.1.mDL"

  setup do
    issuer = JOSE.JWK.generate_key({:ec, "P-256"})
    holder = JOSE.JWK.generate_key({:ec, "P-256"})

    %{
      issuer_pem: issuer |> JOSE.JWK.to_pem() |> elem(1),
      issuer_public: issuer |> JOSE.JWK.to_public_map() |> elem(1),
      holder: holder,
      holder_public: holder |> JOSE.JWK.to_public_map() |> elem(1)
    }
  end

  for {format, type} <- [{"dc+sd-jwt", "ExampleCredential"}, {"mso_mdoc", @doctype}] do
    @format format
    @credential_type type

    test "#{@format} accepts the exact advertised type after signature and holder verification",
         context do
      credential = issue(@format, @credential_type, context)
      assert {:ok, %{credentials: [held]}} = request(@format, credential, context)
      assert held.format == @format
      assert held.credential == credential
    end

    test "#{@format} rejects a correctly signed credential of an unrequested type", context do
      credential = issue(@format, "OtherCredential", context)

      assert {:error, :credential_configuration_type_mismatch} =
               request(@format, credential, context)
    end

    test "#{@format} rejects missing or malformed advertised type before HTTP", context do
      type_field = if @format == "mso_mdoc", do: "doctype", else: "vct"
      configuration = configuration(@format)

      for invalid <-
            [Map.delete(configuration, type_field)] ++
              Enum.map([nil, "", 42, []], &Map.put(configuration, type_field, &1)) do
        metadata = metadata(@format, %{@configuration_id => invalid})

        assert {:error, :invalid_credential_configuration_metadata} =
                 request(@format, "unused", context,
                   credential_issuer_metadata: metadata,
                   req_options: [plug: fn _ -> flunk("unexpected HTTP") end]
                 )
      end
    end
  end

  test "an unadvertised selected configuration fails before HTTP", context do
    assert {:error, :credential_configuration_not_advertised} =
             request("dc+sd-jwt", "unused", context,
               credential_configuration_id: "UnknownCredential",
               req_options: [plug: fn _ -> flunk("unexpected HTTP") end]
             )
  end

  test "the supplied format must equal the selected configuration's format before HTTP",
       context do
    assert {:error, :credential_configuration_format_mismatch} =
             request("dc+sd-jwt", "unused", context,
               credential_issuer_metadata: metadata("mso_mdoc"),
               req_options: [plug: fn _ -> flunk("unexpected HTTP") end]
             )
  end

  test "malformed configuration catalogs fail before HTTP", context do
    for catalog <- [
          nil,
          [],
          %{},
          %{"" => configuration("dc+sd-jwt")},
          %{@configuration_id => nil},
          %{@configuration_id => %{}},
          %{@configuration_id => %{"format" => nil}}
        ] do
      assert {:error, :invalid_credential_configuration_metadata} =
               request("dc+sd-jwt", "unused", context,
                 credential_issuer_metadata: metadata("dc+sd-jwt", catalog),
                 req_options: [plug: fn _ -> flunk("unexpected HTTP") end]
               )
    end
  end

  test "legacy callers without an advertised catalog retain their existing trust policy",
       context do
    credential = issue("dc+sd-jwt", "OtherCredential", context)

    assert {:ok, %{credentials: [_]}} =
             request("dc+sd-jwt", credential, context, credential_issuer_metadata: :omit)

    assert {:ok, %{credentials: [_]}} =
             request("dc+sd-jwt", credential, context,
               credential_issuer_metadata:
                 Map.delete(metadata("dc+sd-jwt"), "credential_configurations_supported")
             )
  end

  defp configuration("mso_mdoc"), do: %{"format" => "mso_mdoc", "doctype" => @doctype}
  defp configuration(format), do: %{"format" => format, "vct" => "ExampleCredential"}

  defp metadata(format), do: metadata(format, %{@configuration_id => configuration(format)})

  defp metadata(_format, catalog) do
    %{
      "credential_issuer" => @issuer,
      "credential_endpoint" => @issuer <> "/credential",
      "credential_configurations_supported" => catalog
    }
  end

  defp issue("dc+sd-jwt", type, context) do
    SdJwtVc.issue([iss: @issuer, vct: type, pem: context.issuer_pem],
      claims: %{"given_name" => "Synthetic"},
      cnf: %{"jwk" => context.holder_public}
    )
  end

  defp issue("mso_mdoc", type, context) do
    now = System.system_time(:second)

    {:ok, credential} =
      Mdoc.issue(
        doc_type: type,
        device_key: context.holder_public,
        issuer_pem: context.issuer_pem,
        namespaces: %{"org.iso.18013.5.1" => %{"given_name" => "Synthetic"}},
        validity: %{signed: now - 10, valid_from: now - 5, valid_until: now + 600}
      )

    credential
  end

  defp request(format, credential, context, overrides \\ []) do
    {:ok, offer} =
      CredentialOffer.parse(%{
        "credential_issuer" => @issuer,
        "credential_configuration_ids" => [@configuration_id]
      })

    plug = fn conn ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      assert JSON.decode!(body)["credential_configuration_id"] == @configuration_id
      Req.Test.json(conn, %{"credentials" => [%{"credential" => credential}]})
    end

    opts =
      [
        credential_endpoint: @issuer <> "/credential",
        credential_issuer_metadata: metadata(format),
        format: format,
        trusted: context.issuer_public,
        access_token: "synthetic-access-token",
        req_options: [plug: plug]
      ]
      |> Keyword.merge(overrides)
      |> omit_metadata()

    Wallet.request_credential(offer, context.holder, opts)
  end

  defp omit_metadata(opts) do
    if Keyword.get(opts, :credential_issuer_metadata) == :omit,
      do: Keyword.delete(opts, :credential_issuer_metadata),
      else: opts
  end
end
