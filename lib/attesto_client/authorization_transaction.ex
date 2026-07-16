defmodule AttestoClient.AuthorizationTransaction do
  @moduledoc """
  One-time state for an OpenID Connect authorization transaction.

  Transactions bind the callback to the issuer, client, redirect URI, nonce,
  PKCE verifier, and opaque initiating browser-session value that created it.
  They are deliberately stored behind the
  `AttestoClient.AuthorizationTransaction.Store` behaviour so applications can
  choose storage appropriate to their topology. The included ETS store is
  suitable for a single node; clustered deployments should provide a store
  with equivalent atomic `put_new` and `take` semantics.

  A transaction contains protocol secrets, especially the PKCE verifier and
  browser binding. Never send it to the browser or log it.
  """

  @enforce_keys [
    :state,
    :nonce,
    :code_verifier,
    :issuer,
    :client_id,
    :redirect_uri,
    :metadata,
    :id_token_alg,
    :browser_binding,
    :max_age
  ]
  defstruct @enforce_keys

  @type t :: %__MODULE__{
          state: String.t(),
          nonce: String.t(),
          code_verifier: String.t(),
          issuer: String.t(),
          client_id: String.t(),
          redirect_uri: String.t(),
          metadata: map(),
          id_token_alg: String.t(),
          browser_binding: String.t(),
          max_age: non_neg_integer() | nil
        }
end
