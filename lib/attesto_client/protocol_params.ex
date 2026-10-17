defmodule AttestoClient.ProtocolParams do
  @moduledoc false

  @protected ~w(
    client_id redirect_uri response_type response_mode scope state nonce
    code_challenge code_challenge_method dpop_jkt request_uri request request_uri_method
    client_secret client_assertion client_assertion_type grant_type code code_verifier
    refresh_token pre-authorized_code tx_code token token_type_hint
  )

  @spec protected() :: [String.t()]
  def protected, do: @protected

  @spec root(String.t()) :: String.t()
  def root(key) when is_binary(key) do
    case :binary.match(key, "[") do
      {position, _length} -> binary_part(key, 0, position)
      :nomatch -> key
    end
  end
end
