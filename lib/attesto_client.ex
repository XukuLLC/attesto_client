defmodule AttestoClient do
  @moduledoc """
  Client-side OAuth 2.0 / OpenID Connect / FAPI 2.0 artifacts and verification.

  `AttestoClient` is the relying-party (client) counterpart to
  [`attesto`](https://hex.pm/packages/attesto) (the authorization server). Where
  attesto *verifies* client artifacts and *issues* server artifacts with the
  authorization server's keystore, this library *builds* client-side wire
  artifacts and *verifies* the server artifacts a client receives:

    * `AttestoClient.ClientAssertion` - build a `private_key_jwt` client
      authentication assertion (RFC 7523 / OpenID Connect Core §9).
    * `AttestoClient.RequestObject` - build a signed authorization request object
      (JAR, RFC 9101 / FAPI 2.0 Message Signing §5.3.1).
    * `AttestoClient.IDToken` - verify OpenID Connect ID Tokens, including
      nonce, `max_age`, and `at_hash` / `c_hash` / `s_hash`.
    * `AttestoClient.JARM` - verify a signed authorization response (JARM,
      FAPI 2.0 Message Signing §5.4).
    * `AttestoClient.IdentityAssertion` - build Identity Assertion JWT
      Authorization Grant assertions (ID-JAG / EMA).
    * `AttestoClient.PKCE` - generate S256 PKCE verifier/challenge pairs.
    * `AttestoClient.SignedIntrospection` - verify RFC 9701 signed
      introspection responses.
    * `AttestoClient.UserInfo` - verify signed OpenID Connect UserInfo
      responses.
    * `AttestoClient.Discovery` - fetch and read authorization-server metadata
      and JWKS (RFC 8414 / OpenID Connect Discovery 1.0).
    * `AttestoClient.ResourceServer` - verify RFC 9068 JWT access tokens from a
      remote issuer with coordinated JWKS rotation, bounded stale-key use, and
      optional DPoP/mTLS request binding.
    * `AttestoClient.ResourceServer.Plug` - authenticate Bearer, DPoP, and mTLS
      protected-resource requests and enforce route scopes.
    * `AttestoClient.AuthorizationCode` - run the Authorization Code flow with
      S256 PKCE and atomically consumed transaction state.
    * `AttestoClient.RefreshCoordinator` and `AttestoClient.Token` - refresh
      rotation single-flight and RFC 7009 revocation with bounded deadlines.
    * `AttestoClient.Logout` - build an RP-Initiated Logout request.

  The lifecycle helpers retain only short-lived protocol transactions and
  in-flight refresh calls. They do not make authorization decisions, create
  sessions, or choose token/session retention policy; those remain with the
  host application. DPoP-bound requests are
  [`req_dpop`](https://hex.pm/packages/req_dpop)'s job.

  ## Assurance

  The build-side artifacts carry cross-language parity tests where practical,
  and the mirror modules are covered by in-family interop tests against the
  corresponding attesto server-side issuer or verifier.
  """
end
