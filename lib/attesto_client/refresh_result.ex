defmodule AttestoClient.RefreshResult do
  @moduledoc """
  Result shared by one refresh-token rotation flight.

  `id_token_claims` is populated when the refresh response contains an ID Token
  and that token has passed full verification.
  """

  @enforce_keys [:tokens]
  defstruct [:tokens, :id_token_claims]

  @type t :: %__MODULE__{
          tokens: AttestoClient.TokenSet.t(),
          id_token_claims: map() | nil
        }
end
