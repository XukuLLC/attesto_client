defmodule AttestoClient.JOSECompatibilityTest do
  use ExUnit.Case, async: true

  test "JOSE encodes an Elixir nil claim as JSON null" do
    key = JOSE.JWK.generate_key({:oct, 32})

    {_jws, compact} =
      key
      |> JOSE.JWT.sign(%{"alg" => "HS256"}, %{"nullable" => nil})
      |> JOSE.JWS.compact()

    [_header, payload, _signature] = String.split(compact, ".")
    json = Base.url_decode64!(payload, padding: false)

    assert JSON.decode!(json) == %{"nullable" => nil}
    refute json =~ ~s("nullable":"nil")
  end
end
