defmodule AttestoClient.ClientAssertionTest do
  use ExUnit.Case, async: true

  alias AttestoClient.ClientAssertion

  @client_id "attesto-fapi-dpop-client"
  @audience "https://op.example.com"

  defp es256_key, do: JOSE.JWK.generate_key({:ec, "P-256"})

  defp es256_map, do: es256_key() |> JOSE.JWK.to_map() |> elem(1)

  defp public_jwk(jose_jwk, overrides) do
    {_, public} = JOSE.JWK.to_public_map(jose_jwk)
    Map.merge(public, overrides)
  end

  defp claims(assertion) do
    assertion |> JOSE.JWS.peek_payload() |> JSON.decode!()
  end

  describe "build/2" do
    test "produces an RFC 7523 assertion with iss=sub=client_id and the given aud" do
      now = 1_700_000_000

      {:ok, assertion} =
        ClientAssertion.build(es256_key(),
          client_id: @client_id,
          audience: @audience,
          now: now,
          lifetime: 60
        )

      c = claims(assertion)
      assert c["iss"] == @client_id
      assert c["sub"] == @client_id
      assert c["aud"] == @audience
      assert c["iat"] == now
      assert c["exp"] == now + 60
      assert is_binary(c["jti"]) and c["jti"] != ""
    end

    test "defaults the lifetime to 60 seconds and generates a fresh jti each call" do
      key = es256_key()
      now = 1_700_000_000
      opts = [client_id: @client_id, audience: @audience, now: now]

      {:ok, a1} = ClientAssertion.build(key, opts)
      {:ok, a2} = ClientAssertion.build(key, opts)

      assert claims(a1)["exp"] == now + 60
      assert claims(a1)["jti"] != claims(a2)["jti"]
    end

    test "infers ES256 for an EC P-256 key and honours an explicit kid" do
      {:ok, assertion} =
        ClientAssertion.build(public_or_private_with_kid(),
          client_id: @client_id,
          audience: @audience,
          kid: "key-1"
        )

      %{"alg" => alg, "kid" => kid} = assertion |> JOSE.JWS.peek_protected() |> JSON.decode!()
      assert alg == "ES256"
      assert kid == "key-1"
    end

    test "carries the kid embedded in a JOSE.JWK struct (no explicit :kid)" do
      # A caller naturally keeps the key as a %JOSE.JWK{}; an embedded kid must
      # still reach the header so the AS can select the verification key.
      struct_key = JOSE.JWK.from_map(Map.put(es256_map(), "kid", "struct-kid"))

      {:ok, assertion} =
        ClientAssertion.build(struct_key, client_id: @client_id, audience: @audience)

      %{"kid" => kid} = assertion |> JOSE.JWS.peek_protected() |> JSON.decode!()
      assert kid == "struct-kid"
    end

    test "the assertion_type/0 is the RFC 7523 jwt-bearer value" do
      assert ClientAssertion.assertion_type() ==
               "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    end
  end

  describe "build/2 rejects invalid input (fail fast)" do
    test "empty or missing client_id / audience" do
      key = es256_key()

      assert {:error, :invalid_client_id} =
               ClientAssertion.build(key, client_id: "", audience: @audience)

      assert {:error, :invalid_client_id} = ClientAssertion.build(key, audience: @audience)

      assert {:error, :invalid_audience} =
               ClientAssertion.build(key, client_id: @client_id, audience: "")

      assert {:error, :invalid_audience} = ClientAssertion.build(key, client_id: @client_id)
    end

    test "a non-positive lifetime or empty jti" do
      key = es256_key()
      base = [client_id: @client_id, audience: @audience]

      assert {:error, :invalid_lifetime} = ClientAssertion.build(key, base ++ [lifetime: -5])
      assert {:error, :invalid_lifetime} = ClientAssertion.build(key, base ++ [lifetime: 0])
      assert {:error, :invalid_jti} = ClientAssertion.build(key, base ++ [jti: ""])
    end

    test "an unsupported algorithm, including none" do
      key = es256_key()
      base = [client_id: @client_id, audience: @audience]

      assert {:error, :unsupported_alg} = ClientAssertion.build(key, base ++ [alg: "none"])
      assert {:error, :unsupported_alg} = ClientAssertion.build(key, base ++ [alg: "bogus"])
    end

    test "a key/algorithm mismatch fails as signing_failed rather than raising" do
      key = es256_key()

      assert {:error, {:signing_failed, _msg}} =
               ClientAssertion.build(key,
                 client_id: @client_id,
                 audience: @audience,
                 alg: "RS256"
               )
    end

    test "an unsupported key type (symmetric oct) fails as unsupported_key, not a raise" do
      key = JOSE.JWK.generate_key({:oct, 32})

      assert {:error, :unsupported_key} =
               ClientAssertion.build(key, client_id: @client_id, audience: @audience)
    end

    test "a malformed JWK map fails as invalid_key, not a raise" do
      assert {:error, :invalid_key} =
               ClientAssertion.build(%{"kty" => "bogus"},
                 client_id: @client_id,
                 audience: @audience
               )

      assert {:error, :invalid_key} =
               ClientAssertion.build(%{}, client_id: @client_id, audience: @audience)
    end
  end

  describe "interop" do
    test "attesto's server-side verifier accepts the assertion (in-family interop)" do
      key = es256_key()

      {:ok, assertion} =
        ClientAssertion.build(key, client_id: @client_id, audience: @audience)

      jwks = %{"keys" => [public_jwk(key, %{"alg" => "ES256"})]}

      assert {:ok, verified} =
               Attesto.ClientAssertion.verify(assertion, @client_id, @audience, jwks)

      assert verified["iss"] == @client_id
    end

    test "an independent PyJWT verifier accepts the assertion (external parity, Leg A)" do
      case python_pyjwt() do
        {:ok, python} ->
          key = es256_key()

          {:ok, assertion} =
            ClientAssertion.build(key, client_id: @client_id, audience: @audience)

          result =
            verify_with_pyjwt(python, %{
              assertion: assertion,
              public_jwk: public_jwk(key, %{"alg" => "ES256"}),
              audience: @audience
            })

          assert {:ok, c} = result
          assert c["iss"] == @client_id
          assert c["sub"] == @client_id
          assert c["aud"] == @audience

        {:skip, reason} ->
          IO.puts("Skipping PyJWT client-assertion parity: #{reason}")
      end
    end
  end

  # ── helpers ──────────────────────────────────────────────────────────────

  defp public_or_private_with_kid do
    # A private JWK map carrying a `kid`, to exercise the kid default path.
    {_, map} = es256_key() |> JOSE.JWK.to_map()
    Map.put(map, "kid", "key-1")
  end

  # Mirror req_dpop's external-reference harness: shell to python3, require the
  # reference library, and skip gracefully when either is absent.
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
      Path.join(System.tmp_dir!(), "attesto_client_#{System.unique_integer([:positive])}.json")

    File.write!(path, JSON.encode!(payload))

    try do
      case System.cmd(python, [verifier_script(), path], stderr_to_stdout: true) do
        {out, 0} -> {:ok, out |> last_json_line!() |> JSON.decode!() |> Map.fetch!("claims")}
        {out, _} -> {:error, String.trim(out)}
      end
    after
      File.rm(path)
    end
  end

  defp verifier_script do
    Path.expand("../../test_support/python/verify_client_assertion.py", __DIR__)
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
