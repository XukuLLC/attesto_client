defmodule AttestoClient.MCPAuthorization.Registration do
  @moduledoc """
  Client registration selected for one MCP authorization server.

  Pre-registered and user-entered credentials are bound to the exact issuer
  that issued them. A Client ID Metadata Document registration is portable,
  but is used at another issuer only when that authorization server advertises
  CIMD support.

  The struct may contain a client secret or private signing key in
  `:client_auth`. Its `Inspect` implementation omits that field. Applications
  that persist it must protect it as a credential.
  """

  @enforce_keys [:issuer, :client_id, :client_auth, :source]
  @derive {Inspect, only: [:issuer, :client_id, :source]}
  defstruct @enforce_keys ++ [metadata: nil]

  @type source :: :pre_registered | :client_id_metadata | :user | :dynamic

  @type t :: %__MODULE__{
          issuer: String.t(),
          client_id: String.t(),
          client_auth: term(),
          source: source(),
          metadata: map() | nil
        }
end
