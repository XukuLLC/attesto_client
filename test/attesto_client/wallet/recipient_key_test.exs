defmodule AttestoClient.Wallet.RecipientKeyTest do
  use ExUnit.Case, async: true
  alias AttestoClient.Wallet.RecipientKey

  test "omitted use and key_ops place no restriction, a present null is malformed" do
    assert RecipientKey.ecdh_usage?(%{})
    assert RecipientKey.ecdh_usage?(%{"use" => "enc", "key_ops" => ["deriveBits"]})

    refute RecipientKey.ecdh_usage?(%{"use" => nil})
    refute RecipientKey.ecdh_usage?(%{"key_ops" => nil})
    refute RecipientKey.ecdh_usage?(%{"use" => "sig"})
  end
end
