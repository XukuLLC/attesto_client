defmodule AttestoClient.AuthorizationTransaction do
  @moduledoc """
  One-time state for an OAuth or OpenID Connect authorization transaction.

  Transactions bind the callback to the issuer, client, redirect URI, nonce,
  PKCE verifier, and opaque initiating browser-session value that created it.
  They are deliberately stored behind the
  `AttestoClient.AuthorizationTransaction.Store` behaviour so applications can
  choose storage appropriate to their topology. The included ETS store is
  suitable for a single node; clustered deployments should provide a store
  with equivalent atomic `put_new` and `take` semantics.

  Optional DPoP provenance pins the initiating public-key thumbprint; callback
  must use the same signing key. The explicit generic, HAIP, or FAPI profile
  and its authentication identity are pinned at start; callback options cannot
  weaken them. HAIP/FAPI require authenticated PAR and a DPoP private key.
  Authentication bindings retain public key identity or a secret digest rather
  than private keys or attestation JWTs.

  `:expires_at` is the transaction's deadline as Unix milliseconds.
  `AttestoClient.AuthorizationCode.callback/3` refuses a transaction past it,
  whichever way the transaction was kept.

  A transaction contains protocol secrets, especially the PKCE verifier and
  browser binding. Never log it, and never send it to the browser in a form
  the browser can read. An application that keeps the transaction itself
  (`AttestoClient.AuthorizationCode.start/2` with `:return`) must encrypt it
  before it leaves the server; signing alone exposes the verifier.
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
  defstruct @enforce_keys ++
              [
                protocol: :oidc,
                dpop_jkt: nil,
                require_response_issuer: false,
                profile: :generic,
                client_auth_binding: nil,
                resources: [],
                issuer_aliases: [],
                expires_at: nil
              ]

  @type t :: %__MODULE__{
          state: String.t(),
          nonce: String.t(),
          code_verifier: String.t(),
          issuer: String.t(),
          client_id: String.t(),
          redirect_uri: String.t(),
          metadata: map(),
          id_token_alg: String.t() | nil,
          browser_binding: String.t(),
          max_age: non_neg_integer() | nil,
          protocol: :oidc | :oauth,
          dpop_jkt: String.t() | nil,
          require_response_issuer: boolean(),
          profile: :generic | :haip | :fapi,
          client_auth_binding: map() | nil,
          resources: [String.t()],
          issuer_aliases: [String.t()],
          expires_at: integer() | nil
        }
end
