defmodule AttestoClient.RequestObjectTest do
  use ExUnit.Case, async: true

  alias Attesto.RequestObject.Policy
  alias AttestoClient.RequestObject

  @client_id "attesto-fapi-dpop-client"
  @audience "https://op.example.com"

  @params %{
    "client_id" => @client_id,
    "response_type" => "code",
    "redirect_uri" => "https://client.example/cb",
    "scope" => "openid",
    "state" => "state-123",
    "code_challenge" => "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    "code_challenge_method" => "S256"
  }

  defp es256_key, do: JOSE.JWK.generate_key({:ec, "P-256"})

  defp public_jwk(jose_jwk, overrides) do
    {_, public} = JOSE.JWK.to_public_map(jose_jwk)
    Map.merge(public, overrides)
  end

  defp claims(jwt), do: jwt |> JOSE.JWS.peek_payload() |> JSON.decode!()
  defp header(jwt), do: jwt |> JOSE.JWS.peek_protected() |> JSON.decode!()

  defp build(opts), do: RequestObject.build(es256_key(), Keyword.merge(base_opts(), opts))
  defp base_opts, do: [client_id: @client_id, audience: @audience, params: @params]

  describe "build/2" do
    test "wraps the params with the RFC 9101 envelope and FAPI typ header" do
      now = 1_700_000_000
      {:ok, jwt} = build(now: now, lifetime: 300)

      c = claims(jwt)
      # Envelope.
      assert c["iss"] == @client_id
      assert c["aud"] == @audience
      assert c["iat"] == now
      assert c["nbf"] == now
      assert c["exp"] == now + 300
      assert is_binary(c["jti"]) and c["jti"] != ""
      # Authorization parameters carried through.
      assert c["response_type"] == "code"
      assert c["redirect_uri"] == "https://client.example/cb"
      assert c["scope"] == "openid"
      assert c["code_challenge_method"] == "S256"

      assert header(jwt)["typ"] == "oauth-authz-req+jwt"
    end

    test "the envelope claims win over colliding params" do
      {:ok, jwt} =
        RequestObject.build(es256_key(),
          client_id: @client_id,
          audience: @audience,
          params: %{"iss" => "spoofed", "exp" => 1, "response_type" => "code"}
        )

      c = claims(jwt)
      assert c["iss"] == @client_id
      refute c["exp"] == 1
      assert c["response_type"] == "code"
    end

    test "the typ header is overridable" do
      {:ok, jwt} = build(typ: "custom+jwt")
      assert header(jwt)["typ"] == "custom+jwt"
    end

    test "defaults params to an empty object" do
      {:ok, jwt} = RequestObject.build(es256_key(), client_id: @client_id, audience: @audience)
      c = claims(jwt)
      assert c["iss"] == @client_id
      refute Map.has_key?(c, "response_type")
    end
  end

  describe "build/2 rejects invalid input (fail fast)" do
    test "bad client_id, audience, params, typ, lifetime, jti, alg, and key type" do
      key = es256_key()

      assert {:error, :invalid_client_id} =
               RequestObject.build(key, client_id: "", audience: @audience)

      assert {:error, :invalid_audience} =
               RequestObject.build(key, client_id: @client_id, audience: "")

      assert {:error, :invalid_params} = build(params: %{:not => "stringkey"})
      assert {:error, :invalid_params} = build(params: "nope")
      assert {:error, :invalid_typ} = build(typ: "")
      assert {:error, :invalid_typ} = build(typ: "   ")
      assert {:error, :invalid_lifetime} = build(lifetime: 0)
      assert {:error, :invalid_jti} = build(jti: "")
      assert {:error, :unsupported_alg} = build(alg: "none")
      assert {:error, {:signing_failed, _}} = build(alg: "RS256")

      assert {:error, :unsupported_key} =
               RequestObject.build(JOSE.JWK.generate_key({:oct, 32}),
                 client_id: @client_id,
                 audience: @audience
               )

      # A malformed JWK map is rejected, not raised (build/2 contract).
      assert {:error, :invalid_key} =
               RequestObject.build(%{"kty" => "bogus"},
                 client_id: @client_id,
                 audience: @audience
               )

      assert {:error, :invalid_key} =
               RequestObject.build(%{}, client_id: @client_id, audience: @audience)
    end

    test "a lifetime beyond the FAPI 60-minute bound is rejected" do
      assert {:ok, _} = build(lifetime: 3600)
      assert {:error, :invalid_lifetime} = build(lifetime: 3601)
    end

    test "a negative now (invalid NumericDate) is rejected" do
      assert {:error, :invalid_time} = build(now: -10)
    end
  end

  describe "interop" do
    test "attesto's FAPI Message Signing verifier accepts the request object" do
      key = es256_key()
      {:ok, jwt} = RequestObject.build(key, base_opts())

      jwks = %{"keys" => [public_jwk(key, %{"alg" => "ES256"})]}

      opts =
        [issuer: @client_id, audience: @audience] ++
          Policy.to_verify_opts(Policy.fapi_message_signing())

      assert {:ok, params} = Attesto.RequestObject.verify(jwt, jwks, opts)
      assert params["response_type"] == "code"
      assert params["scope"] == "openid"
    end

    test "an independent PyJWT verifier accepts the request object (external parity, Leg A)" do
      case python_pyjwt() do
        {:ok, python} ->
          key = es256_key()
          {:ok, jwt} = RequestObject.build(key, base_opts())

          result =
            verify_with_pyjwt(python, %{
              request_object: jwt,
              public_jwk: public_jwk(key, %{"alg" => "ES256"}),
              audience: @audience
            })

          assert {:ok, %{"header" => h, "claims" => c}} = result
          assert h["typ"] == "oauth-authz-req+jwt"
          assert c["iss"] == @client_id
          assert c["aud"] == @audience
          assert c["response_type"] == "code"

        {:skip, reason} ->
          IO.puts("Skipping PyJWT request-object parity: #{reason}")
      end
    end
  end

  # ── python parity harness (mirrors req_dpop) ───────────────────────────────

  defp python_pyjwt do
    python = System.get_env("ATTESTO_CLIENT_PYTHON") || System.find_executable("python3")

    cond do
      is_nil(python) -> {:skip, "python3 not found"}
      not File.exists?(verifier_script()) -> {:skip, "verifier helper not found"}
      true -> ensure_pyjwt(python)
    end
  end

  defp ensure_pyjwt(python) do
    case System.cmd(python, ["-c", "import jwt"], stderr_to_stdout: true) do
      {_out, 0} -> {:ok, python}
      {out, _} -> {:skip, "PyJWT unavailable: #{String.trim(out)}"}
    end
  end

  defp verify_with_pyjwt(python, payload) do
    path =
      Path.join(System.tmp_dir!(), "attesto_client_ro_#{System.unique_integer([:positive])}.json")

    File.write!(path, JSON.encode!(payload))

    try do
      case System.cmd(python, [verifier_script(), path], stderr_to_stdout: true) do
        {out, 0} -> {:ok, out |> last_json_line!() |> JSON.decode!()}
        {out, _} -> {:error, String.trim(out)}
      end
    after
      File.rm(path)
    end
  end

  defp verifier_script do
    Path.expand("../../test_support/python/verify_request_object.py", __DIR__)
  end

  defp last_json_line!(output) do
    output
    |> String.split("\n", trim: true)
    |> Enum.reverse()
    |> Enum.find(&String.starts_with?(&1, "{"))
    |> case do
      nil -> raise "python verifier emitted no JSON: #{output}"
      line -> line
    end
  end
end
