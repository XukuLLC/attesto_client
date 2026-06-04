defmodule AttestoClient.JARMTest do
  use ExUnit.Case, async: true

  alias AttestoClient.JARM

  @issuer "https://op.example.com"
  @client_id "attesto-fapi-dpop-client"
  @now 1_700_000_000

  # An EC (ES256) authorization-server signing key, shared by the in-family and
  # negative tests. Generated once per test run.
  defp as_key, do: JOSE.JWK.generate_key({:ec, "P-256"})

  defp public_jwk(jose_jwk, overrides) do
    {_, public} = JOSE.JWK.to_public_map(jose_jwk)
    Map.merge(public, overrides)
  end

  defp jwks(jose_jwk, overrides \\ %{}), do: %{"keys" => [public_jwk(jose_jwk, overrides)]}

  # Sign a JARM response directly (lets the negative tests control the claims).
  defp sign(jose_jwk, claims, header \\ %{"alg" => "ES256"}) do
    {_, jwt} = jose_jwk |> JOSE.JWT.sign(header, claims) |> JOSE.JWS.compact()
    jwt
  end

  defp success_claims(overrides \\ %{}) do
    Map.merge(
      %{
        "iss" => @issuer,
        "aud" => @client_id,
        "iat" => @now,
        "exp" => @now + 600,
        "code" => "auth-code-123",
        "state" => "state-xyz"
      },
      overrides
    )
  end

  defp verify(jwt, jwks, overrides \\ []) do
    JARM.verify(
      jwt,
      jwks,
      Keyword.merge([issuer: @issuer, client_id: @client_id, now: @now], overrides)
    )
  end

  describe "verify/3 success" do
    test "verifies a valid response and returns the response parameters" do
      key = as_key()
      jwt = sign(key, success_claims())

      assert {:ok, claims} = verify(jwt, jwks(key))
      assert claims["code"] == "auth-code-123"
      assert claims["state"] == "state-xyz"
      assert claims["iss"] == @issuer
      assert claims["aud"] == @client_id
    end

    test "accepts an aud array containing the client_id" do
      key = as_key()
      jwt = sign(key, success_claims(%{"aud" => ["other", @client_id]}))

      assert {:ok, _} = verify(jwt, jwks(key))
    end

    test "returns an error response's parameters" do
      key = as_key()
      jwt = sign(key, success_claims(%{"error" => "access_denied"}) |> Map.drop(["code"]))

      assert {:ok, claims} = verify(jwt, jwks(key))
      assert claims["error"] == "access_denied"
    end

    test "selects the key by kid when the header carries one" do
      key = as_key()
      other = as_key()
      jwt = sign(key, success_claims(), %{"alg" => "ES256", "kid" => "as-key-1"})

      keyset = %{
        "keys" => [
          public_jwk(other, %{"kid" => "other"}),
          public_jwk(key, %{"kid" => "as-key-1"})
        ]
      }

      assert {:ok, _} = verify(jwt, keyset)
    end
  end

  describe "verify/3 rejects" do
    test "a wrong issuer, wrong audience, expired, and missing exp" do
      key = as_key()

      assert {:error, :invalid_issuer} =
               verify(sign(key, success_claims(%{"iss" => "https://evil.example"})), jwks(key))

      assert {:error, :invalid_audience} =
               verify(sign(key, success_claims(%{"aud" => "someone-else"})), jwks(key))

      assert {:error, :expired} =
               verify(sign(key, success_claims(%{"exp" => @now - 1})), jwks(key))

      assert {:error, :missing_exp} =
               verify(sign(key, success_claims() |> Map.drop(["exp"])), jwks(key))
    end

    test "a signature from a key not in the JWKS" do
      signer = as_key()
      other = as_key()
      jwt = sign(signer, success_claims())

      assert {:error, :invalid_signature} = verify(jwt, jwks(other))
    end

    test "a tampered token" do
      key = as_key()
      jwt = sign(key, success_claims())
      # Flip the first character of the signature segment - fully significant
      # bits, so the signature bytes always change (unlike the last char, whose
      # trailing bits are not all significant under base64url).
      [header, payload, signature] = String.split(jwt, ".")

      flipped =
        if(String.first(signature) == "A", do: "B", else: "A") <>
          String.slice(signature, 1..-1//1)

      tampered = Enum.join([header, payload, flipped], ".")

      assert {:error, :invalid_signature} = verify(tampered, jwks(key))
    end

    test "an unsecured (alg=none) token" do
      key = as_key()
      header = Base.url_encode64(JSON.encode!(%{"alg" => "none"}), padding: false)
      payload = Base.url_encode64(JSON.encode!(success_claims()), padding: false)
      none_jwt = header <> "." <> payload <> "."

      assert {:error, :invalid_signature} = verify(none_jwt, jwks(key))
    end

    test "missing :issuer or :client_id options, and an invalid JWKS" do
      key = as_key()
      jwt = sign(key, success_claims())

      assert {:error, :missing_issuer} = JARM.verify(jwt, jwks(key), client_id: @client_id)
      assert {:error, :missing_client_id} = JARM.verify(jwt, jwks(key), issuer: @issuer)
      assert {:error, :invalid_jwks} = verify(jwt, "not-a-jwks")
    end

    test "a mixed-type aud array is malformed even if the client_id is present" do
      key = as_key()
      jwt = sign(key, success_claims(%{"aud" => [@client_id, 42]}))

      assert {:error, :invalid_audience} = verify(jwt, jwks(key))
    end

    test "a malformed or future iat" do
      key = as_key()

      assert {:error, :invalid_iat} =
               verify(sign(key, success_claims(%{"iat" => -1})), jwks(key))

      assert {:error, :invalid_iat} =
               verify(sign(key, success_claims(%{"iat" => "soon"})), jwks(key))

      assert {:error, :not_yet_valid} =
               verify(sign(key, success_claims(%{"iat" => @now + 3600})), jwks(key))

      # Within the clock-skew tolerance is accepted.
      assert {:ok, _} = verify(sign(key, success_claims(%{"iat" => @now + 30})), jwks(key))
    end

    test "an invalid :accepted_algs option" do
      key = as_key()
      jwt = sign(key, success_claims())

      assert {:error, :unsupported_alg} = verify(jwt, jwks(key), accepted_algs: ["none"])
      assert {:error, :unsupported_alg} = verify(jwt, jwks(key), accepted_algs: ["bogus"])
      assert {:error, :unsupported_alg} = verify(jwt, jwks(key), accepted_algs: "ES256")
      # A valid restricted list still works.
      assert {:ok, _} = verify(jwt, jwks(key), accepted_algs: ["ES256"])
    end
  end

  describe "interop" do
    defmodule Keystore do
      @moduledoc false
      @behaviour Attesto.Keystore

      @pem JOSE.JWK.generate_key({:ec, "P-256"}) |> JOSE.JWK.to_pem() |> elem(1)

      @impl true
      def signing_pem, do: @pem
      @impl true
      def verification_pems, do: [@pem]
    end

    test "verifies a response signed by attesto's server-side Attesto.JARM" do
      config =
        Attesto.Config.new(
          issuer: @issuer,
          audience: @issuer,
          keystore: Keystore,
          principal_kinds: [Attesto.PrincipalKind.new("user", "usr_")]
        )

      {:ok, jwt} =
        Attesto.JARM.response_jwt(config, @client_id, %{"code" => "c", "state" => "s"}, now: @now)

      pem = Keystore.signing_pem()
      {_, pub} = pem |> Attesto.Key.jwk() |> JOSE.JWK.to_public_map()
      as_jwks = %{"keys" => [Map.merge(pub, %{"alg" => "ES256", "kid" => Attesto.Key.kid(pem)})]}

      assert {:ok, claims} = verify(jwt, as_jwks)
      assert claims["code"] == "c"
      assert claims["aud"] == @client_id
    end

    test "verifies a JARM response signed by an independent PyJWT signer (external parity, Leg A)" do
      case python_pyjwt() do
        {:ok, python} ->
          key = as_key()
          {_, priv} = JOSE.JWK.to_map(key)
          priv = Map.put(priv, "kid", "py-as-key")

          {:ok, %{"jwt" => jwt}} =
            sign_with_pyjwt(python, %{private_jwk: priv, alg: "ES256", claims: success_claims()})

          assert {:ok, claims} = verify(jwt, jwks(key, %{"kid" => "py-as-key"}))
          assert claims["code"] == "auth-code-123"
          assert claims["aud"] == @client_id

        {:skip, reason} ->
          IO.puts("Skipping PyJWT JARM parity: #{reason}")
      end
    end
  end

  # ── python parity harness (mirrors req_dpop) ───────────────────────────────

  defp python_pyjwt do
    python = System.get_env("ATTESTO_CLIENT_PYTHON") || System.find_executable("python3")

    cond do
      is_nil(python) -> {:skip, "python3 not found"}
      not File.exists?(signer_script()) -> {:skip, "signer helper not found"}
      true -> ensure_pyjwt(python)
    end
  end

  defp ensure_pyjwt(python) do
    case System.cmd(python, ["-c", "import jwt"], stderr_to_stdout: true) do
      {_out, 0} -> {:ok, python}
      {out, _} -> {:skip, "PyJWT unavailable: #{String.trim(out)}"}
    end
  end

  defp sign_with_pyjwt(python, payload) do
    path =
      Path.join(
        System.tmp_dir!(),
        "attesto_client_jarm_#{System.unique_integer([:positive])}.json"
      )

    File.write!(path, JSON.encode!(payload))

    try do
      case System.cmd(python, [signer_script(), path], stderr_to_stdout: true) do
        {out, 0} -> {:ok, out |> last_json_line!() |> JSON.decode!()}
        {out, _} -> {:error, String.trim(out)}
      end
    after
      File.rm(path)
    end
  end

  defp signer_script do
    Path.expand("../../test_support/python/sign_jarm.py", __DIR__)
  end

  defp last_json_line!(output) do
    output
    |> String.split("\n", trim: true)
    |> Enum.reverse()
    |> Enum.find(&String.starts_with?(&1, "{"))
    |> case do
      nil -> raise "python signer emitted no JSON: #{output}"
      line -> line
    end
  end
end
