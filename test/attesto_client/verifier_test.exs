defmodule AttestoClient.VerifierTest do
  use ExUnit.Case, async: true

  alias AttestoClient.Verifier

  test "PS256 verification enforces the RFC 7518 salt length" do
    private = JOSE.JWK.generate_key({:rsa, 2048})
    public = private |> JOSE.JWK.to_public_map() |> elem(1)
    claims = %{"sub" => "subject"}

    valid = signed_ps256(private, claims, 32)
    invalid = signed_ps256(private, claims, 31)

    assert {:ok, ^claims, %{"alg" => "PS256"}, %JOSE.JWK{}} =
             Verifier.verify_signature(valid, [public], ["PS256"])

    # JOSE accepts an automatically detected PSS salt length. The shared
    # Attesto verifier rechecks the RFC 7518 requirement explicitly.
    assert {true, %JOSE.JWT{}, %JOSE.JWS{}} =
             JOSE.JWT.verify_strict(JOSE.JWK.to_public(private), ["PS256"], invalid)

    assert {:error, :invalid_signature} =
             Verifier.verify_signature(invalid, [public], ["PS256"])
  end

  defp signed_ps256(private, claims, salt_length) do
    protected = encode64(JSON.encode!(%{"alg" => "PS256"}))
    payload = encode64(JSON.encode!(claims))
    signing_input = protected <> "." <> payload
    private_key = private |> JOSE.JWK.to_key() |> elem(1)

    signature =
      :public_key.sign(signing_input, :sha256, private_key,
        rsa_padding: :rsa_pkcs1_pss_padding,
        rsa_pss_saltlen: salt_length,
        rsa_mgf1_md: :sha256
      )

    signing_input <> "." <> encode64(signature)
  end

  defp encode64(value), do: Base.url_encode64(value, padding: false)
end
