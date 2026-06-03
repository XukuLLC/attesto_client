defmodule AttestoClient do
  @moduledoc """
  Client-side OAuth 2.0 / OpenID Connect / FAPI 2.0 artifacts and verification.

  `AttestoClient` is the relying-party (client) counterpart to
  [`attesto`](https://hex.pm/packages/attesto) (the authorization server). Where
  attesto *verifies* client artifacts and *issues* server artifacts with the
  authorization server's keystore, this library *builds* client artifacts signed
  with the **client's own** key, and *verifies* the server artifacts a client
  receives:

    * `AttestoClient.ClientAssertion` - build a `private_key_jwt` client
      authentication assertion (RFC 7523 / OpenID Connect Core §9).
    * `AttestoClient.RequestObject` - build a signed authorization request object
      (JAR, RFC 9101 / FAPI 2.0 Message Signing §5.3.1).
    * `AttestoClient.JARM` - verify a signed authorization response (JARM,
      FAPI 2.0 Message Signing §5.4).
    * (planned) a thin discovery-metadata lookup.

  It is deliberately **not** a full OAuth client framework: it has no flow
  orchestrator, token store, or session handling. It produces and checks the
  cryptographic, wire-format artifacts an OAuth/OIDC/FAPI client needs, leaving
  HTTP orchestration to the host (DPoP-bound requests are
  [`req_dpop`](https://hex.pm/packages/req_dpop)'s job).

  ## Assurance

  Each artifact carries a cross-language parity test: the artifact this library
  builds is checked against an independent, non-Elixir reference implementation,
  so correctness does not rest on agreement between this library and attesto
  alone.
  """
end
