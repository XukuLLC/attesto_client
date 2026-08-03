defmodule AttestoClient.Wallet.PresentationTest do
  use ExUnit.Case, async: true

  alias Attesto.{Mdoc, SdJwtVc, VpToken}
  alias AttestoClient.Wallet.Presentation
  alias AttestoClient.Wallet.PresentationRequest

  @doc_type "org.iso.18013.5.1.mDL"
  @mdl_namespace "org.iso.18013.5.1"
  @now 1_700_000_000

  defp ec_keypair do
    jwk = JOSE.JWK.generate_key({:ec, "P-256"})
    {_type, public} = JOSE.JWK.to_public_map(jwk)
    {jwk, public}
  end

  defp request(overrides \\ %{}) do
    struct!(
      PresentationRequest,
      Map.merge(
        %{
          client_id: "https://verifier.example.com",
          nonce: "nonce-1",
          response_uri: "https://verifier.example.com/response",
          response_mode: "direct_post",
          dcql_query: %{
            "credentials" => [
              %{
                "id" => "identity",
                "format" => "dc+sd-jwt",
                "meta" => %{"vct_values" => ["identity"]}
              }
            ]
          },
          state: nil
        },
        overrides
      )
    )
  end

  # Mirrors the held-credential shape `AttestoClient.Wallet.request_credential/3`
  # returns: `:claims` comes from verifying the issued credential, exactly as
  # the wallet does on receipt.
  defp issue_held_sd_jwt(issuer_pem, holder_public) do
    credential =
      SdJwtVc.issue([iss: "https://issuer.example.com", vct: "identity", pem: issuer_pem],
        claims: %{"given_name" => "Alice", "family_name" => "Example"},
        cnf: %{"jwk" => holder_public},
        iat: @now
      )

    {:ok, %{claims: claims}} = SdJwtVc.verify(credential, issuer_jwks_for(issuer_pem), now: @now)

    %{
      format: "dc+sd-jwt",
      credential: credential,
      claims: claims,
      holder_binding: %{"jwk" => holder_public}
    }
  end

  defp issuer_jwks_for(issuer_pem) do
    {_type, public} = issuer_pem |> JOSE.JWK.from_pem() |> JOSE.JWK.to_public_map()
    public
  end

  describe "SD-JWT VC round trip" do
    test "a built presentation verifies with Attesto.VpToken.verify/2 and recovers the disclosed claims" do
      issuer_jwk = JOSE.JWK.generate_key({:ec, "P-256"})
      issuer_pem = issuer_jwk |> JOSE.JWK.to_pem() |> elem(1)
      {holder_jwk, holder_public} = ec_keypair()

      held = issue_held_sd_jwt(issuer_pem, holder_public)
      req = request()

      assert {:ok, vp_token} =
               Presentation.build_vp_token(%{"identity" => held}, req,
                 holder_keys: %{"identity" => holder_jwk},
                 now: @now
               )

      assert %{"identity" => presentation} = vp_token
      assert is_binary(presentation)

      assert {:ok, %{"identity" => result}} =
               VpToken.verify(vp_token,
                 nonce: req.nonce,
                 audience: req.client_id,
                 issuer_jwks: issuer_jwks_for(issuer_pem),
                 now: @now
               )

      assert result.vct == "identity"
      assert result.iss == "https://issuer.example.com"
      assert result.claims["given_name"] == "Alice"
      assert result.claims["family_name"] == "Example"
    end

    test "restricts the presentation to simple top-level requested claims" do
      issuer_jwk = JOSE.JWK.generate_key({:ec, "P-256"})
      issuer_pem = issuer_jwk |> JOSE.JWK.to_pem() |> elem(1)
      {holder_jwk, holder_public} = ec_keypair()

      held = issue_held_sd_jwt(issuer_pem, holder_public)

      req =
        request(%{
          dcql_query: %{
            "credentials" => [
              %{
                "id" => "identity",
                "format" => "dc+sd-jwt",
                "claims" => [%{"path" => ["given_name"]}]
              }
            ]
          }
        })

      assert {:ok, %{"identity" => presentation}} =
               Presentation.build_vp_token(%{"identity" => held}, req,
                 holder_keys: %{"identity" => holder_jwk},
                 now: @now
               )

      assert {:ok, %{"identity" => result}} =
               VpToken.verify(%{"identity" => presentation},
                 nonce: req.nonce,
                 audience: req.client_id,
                 issuer_jwks: issuer_jwks_for(issuer_pem),
                 now: @now
               )

      assert result.claims["given_name"] == "Alice"
      refute Map.has_key?(result.claims, "family_name")
    end

    test "requires a holder key for every selected query id" do
      issuer_jwk = JOSE.JWK.generate_key({:ec, "P-256"})
      issuer_pem = issuer_jwk |> JOSE.JWK.to_pem() |> elem(1)
      {_holder_jwk, holder_public} = ec_keypair()

      held = issue_held_sd_jwt(issuer_pem, holder_public)
      req = request()

      assert {:error, {"identity", :missing_holder_key}} =
               Presentation.build_vp_token(%{"identity" => held}, req,
                 holder_keys: %{},
                 now: @now
               )

      assert {:error, {"identity", :missing_holder_keys}} =
               Presentation.build_vp_token(%{"identity" => held}, req, now: @now)
    end

    test "rejects direct_post.jwt (not yet supported)" do
      issuer_jwk = JOSE.JWK.generate_key({:ec, "P-256"})
      issuer_pem = issuer_jwk |> JOSE.JWK.to_pem() |> elem(1)
      {holder_jwk, holder_public} = ec_keypair()

      held = issue_held_sd_jwt(issuer_pem, holder_public)
      req = request(%{response_mode: "direct_post.jwt"})

      assert {:error, :unsupported_response_mode} =
               Presentation.build_vp_token(%{"identity" => held}, req,
                 holder_keys: %{"identity" => holder_jwk}
               )
    end
  end

  describe "security regressions" do
    defp disclosure(salt, name, value),
      do: [salt, name, value] |> JSON.encode!() |> Base.url_encode64(padding: false)

    defp digest(disclosure),
      do: :sha256 |> :crypto.hash(disclosure) |> Base.url_encode64(padding: false)

    defp b64(map), do: map |> JSON.encode!() |> Base.url_encode64(padding: false)

    test "claim minimisation keeps only TOP-LEVEL disclosures, not a colliding nested one" do
      {holder_jwk, holder_public} = ec_keypair()

      # Two Disclosures with the SAME leaf name "name": one is a top-level claim
      # (its digest is in the issuer payload's `_sd`), the other is nested (its
      # digest is not). A request for the top-level `["name"]` must not leak the
      # nested one.
      top = disclosure("salt-top", "name", "TopValue")
      nested = disclosure("salt-nested", "name", "NestedSecret")

      payload =
        b64(%{
          "iss" => "https://issuer.example.com",
          "vct" => "identity",
          "cnf" => %{"jwk" => holder_public},
          "_sd" => [digest(top)],
          "iat" => @now
        })

      issuer_jwt = b64(%{"alg" => "ES256", "typ" => "dc+sd-jwt"}) <> "." <> payload <> ".sig"
      credential = "#{issuer_jwt}~#{top}~#{nested}~"

      held = %{
        format: "dc+sd-jwt",
        credential: credential,
        claims: %{"vct" => "identity"},
        holder_binding: %{"jwk" => holder_public}
      }

      req =
        request(%{
          dcql_query: %{
            "credentials" => [
              %{"id" => "identity", "format" => "dc+sd-jwt", "claims" => [%{"path" => ["name"]}]}
            ]
          }
        })

      assert {:ok, %{"identity" => presentation}} =
               Presentation.build_vp_token(%{"identity" => held}, req,
                 holder_keys: %{"identity" => holder_jwk},
                 now: @now
               )

      assert String.contains?(presentation, top)
      refute String.contains?(presentation, nested)
    end

    test "submit/3 refuses direct_post.jwt even with a caller-built vp_token" do
      req = request(%{response_mode: "direct_post.jwt"})

      assert {:error, :unsupported_response_mode} =
               Presentation.submit(req, %{"identity" => "eyJ..."}, [])
    end

    test "build refuses to sign with a holder key the credential is not bound to" do
      issuer_jwk = JOSE.JWK.generate_key({:ec, "P-256"})
      issuer_pem = issuer_jwk |> JOSE.JWK.to_pem() |> elem(1)
      {_holder_jwk, holder_public} = ec_keypair()
      {wrong_key, _wrong_public} = ec_keypair()

      held = issue_held_sd_jwt(issuer_pem, holder_public)
      req = request()

      assert {:error, {"identity", :holder_key_mismatch}} =
               Presentation.build_vp_token(%{"identity" => held}, req,
                 holder_keys: %{"identity" => wrong_key},
                 now: @now
               )
    end
  end

  describe "select/2" do
    test "matches by format, vct_values, and requested claim presence" do
      issuer_jwk = JOSE.JWK.generate_key({:ec, "P-256"})
      issuer_pem = issuer_jwk |> JOSE.JWK.to_pem() |> elem(1)
      {_holder_jwk, holder_public} = ec_keypair()

      held = issue_held_sd_jwt(issuer_pem, holder_public)
      req = request()

      assert {:ok, %{"identity" => ^held}} = Presentation.select(req.dcql_query, [held])
    end

    test "returns :no_match when no held credential satisfies a query" do
      req = request()
      assert {:error, {:no_match, "identity"}} = Presentation.select(req.dcql_query, [])
    end

    test "returns :no_match when the vct doesn't match" do
      issuer_jwk = JOSE.JWK.generate_key({:ec, "P-256"})
      issuer_pem = issuer_jwk |> JOSE.JWK.to_pem() |> elem(1)
      {_holder_jwk, holder_public} = ec_keypair()

      credential =
        SdJwtVc.issue([iss: "https://issuer.example.com", vct: "other-type", pem: issuer_pem],
          claims: %{"given_name" => "Alice"},
          cnf: %{"jwk" => holder_public},
          iat: @now
        )

      {:ok, %{claims: claims}} =
        SdJwtVc.verify(credential, issuer_jwks_for(issuer_pem), now: @now)

      held = %{
        format: "dc+sd-jwt",
        credential: credential,
        claims: claims,
        holder_binding: %{"jwk" => holder_public}
      }

      req = request()
      assert {:error, {:no_match, "identity"}} = Presentation.select(req.dcql_query, [held])
    end
  end

  describe "submit/3 and present/3" do
    defp form_plug(parent) do
      fn conn ->
        {:ok, body, conn} = Plug.Conn.read_body(conn)
        send(parent, {:submitted, URI.decode_query(body)})

        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(200, JSON.encode!(%{"ok" => true}))
      end
    end

    test "submit/3 POSTs the JSON-encoded vp_token and state" do
      req = request(%{state: "state-xyz"})
      vp_token = %{"identity" => "presentation-string"}

      assert {:ok, %{"ok" => true}} =
               Presentation.submit(req, vp_token, req_options: [plug: form_plug(self())])

      assert_receive {:submitted, form}
      assert JSON.decode!(form["vp_token"]) == vp_token
      assert form["state"] == "state-xyz"
    end

    test "present/3 selects, builds, and submits in one call" do
      issuer_jwk = JOSE.JWK.generate_key({:ec, "P-256"})
      issuer_pem = issuer_jwk |> JOSE.JWK.to_pem() |> elem(1)
      {holder_jwk, holder_public} = ec_keypair()

      held = issue_held_sd_jwt(issuer_pem, holder_public)
      req = request()

      assert {:ok, %{"ok" => true}} =
               Presentation.present(req, [held],
                 holder_keys: %{"identity" => holder_jwk},
                 now: @now,
                 req_options: [plug: form_plug(self())]
               )

      assert_receive {:submitted, form}
      assert %{"identity" => presentation} = JSON.decode!(form["vp_token"])

      assert {:ok, %{"identity" => result}} =
               VpToken.verify(%{"identity" => presentation},
                 nonce: req.nonce,
                 audience: req.client_id,
                 issuer_jwks: issuer_jwks_for(issuer_pem),
                 now: @now
               )

      assert result.claims["given_name"] == "Alice"
    end
  end

  describe "mso_mdoc presentations" do
    defp mdoc_holder_keypair, do: ec_keypair()

    defp issue_held_mdoc(issuer_pem, holder_public) do
      {:ok, issued} =
        Mdoc.issue(
          device_key: holder_public,
          doc_type: @doc_type,
          issuer_pem: issuer_pem,
          namespaces: %{@mdl_namespace => %{"given_name" => "Jane", "family_name" => "Doe"}},
          validity: %{signed: @now - 10, valid_from: @now - 5, valid_until: @now + 3600}
        )

      {:ok, %{namespaces: namespaces, doc_type: doc_type}} =
        Mdoc.verify(issued, issuer_jwks_for(issuer_pem), now: @now)

      %{
        format: "mso_mdoc",
        credential: issued,
        claims: namespaces,
        holder_binding: holder_public,
        doc_type: doc_type
      }
    end

    test "a built DeviceResponse verifies with Attesto.VpToken.verify/2" do
      issuer_jwk = JOSE.JWK.generate_key({:ec, "P-256"})
      issuer_pem = issuer_jwk |> JOSE.JWK.to_pem() |> elem(1)
      {holder_jwk, holder_public} = mdoc_holder_keypair()

      held = issue_held_mdoc(issuer_pem, holder_public)

      req =
        request(%{
          dcql_query: %{
            "credentials" => [
              %{"id" => "mdl", "format" => "mso_mdoc", "meta" => %{"doctype_value" => @doc_type}}
            ]
          }
        })

      assert {:ok, %{"mdl" => device_response}} =
               Presentation.build_vp_token(%{"mdl" => held}, req,
                 holder_keys: %{"mdl" => holder_jwk},
                 now: @now
               )

      assert {:ok, %{"mdl" => result}} =
               VpToken.verify(%{"mdl" => device_response},
                 nonce: req.nonce,
                 audience: req.client_id,
                 issuer_jwks: issuer_jwks_for(issuer_pem),
                 response_uri: req.response_uri,
                 formats: %{"mdl" => "mso_mdoc"},
                 now: @now
               )

      assert result.doc_type == @doc_type

      assert result.namespaces == %{
               @mdl_namespace => %{"given_name" => "Jane", "family_name" => "Doe"}
             }
    end

    test "select/2 matches by doctype_value" do
      issuer_jwk = JOSE.JWK.generate_key({:ec, "P-256"})
      issuer_pem = issuer_jwk |> JOSE.JWK.to_pem() |> elem(1)
      {_holder_jwk, holder_public} = mdoc_holder_keypair()

      held = issue_held_mdoc(issuer_pem, holder_public)

      dcql_query = %{
        "credentials" => [
          %{"id" => "mdl", "format" => "mso_mdoc", "meta" => %{"doctype_value" => @doc_type}}
        ]
      }

      assert {:ok, %{"mdl" => ^held}} = Presentation.select(dcql_query, [held])

      wrong_type_query = %{
        "credentials" => [
          %{"id" => "mdl", "format" => "mso_mdoc", "meta" => %{"doctype_value" => "other.type"}}
        ]
      }

      assert {:error, {:no_match, "mdl"}} = Presentation.select(wrong_type_query, [held])
    end
  end
end
