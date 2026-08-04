# AttestoClient

[![Hex.pm](https://img.shields.io/hexpm/v/attesto_client)](https://hex.pm/packages/attesto_client)
[![Hexdocs.pm](https://img.shields.io/badge/docs-hexdocs.pm-blue)](https://hexdocs.pm/attesto_client)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![OpenID Certified](https://img.shields.io/badge/OpenID-Certified-F78C40)](https://openid.net/certification/certified-openid-relying-parties-profiles/)

<a href="https://openid.net/certification/certified-openid-relying-parties-profiles/"><img src="https://openid.net/wordpress-content/uploads/2016/04/oid-l-certification-mark-l-rgb-150dpi-90mm.png" alt="OpenID Certified" width="180" align="right"></a>

AttestoClient is
[OpenID Certified](https://openid.net/certification/certified-openid-relying-parties-profiles/)
as a Relying Party library to the **Basic**, **Config**, and **Dynamic** OP
profiles, run against the OpenID Foundation's conformance suite.

Run a secure OpenID Connect Authorization Code + PKCE exchange, refresh and
revoke tokens, build RP-Initiated Logout requests, and build or verify the OAuth
and OpenID Connect wire artifacts an Elixir client needs: `private_key_jwt`,
signed authorization request objects (JAR), strict ID Token verification, JARM,
ID-JAG/EMA assertions, signed introspection and UserInfo, and discovery/JWKS.

Use it when you are writing a relying party or OAuth client that needs secure
protocol mechanics without delegating application policy:

- Authenticate to token, PAR, or introspection endpoints with
  `private_key_jwt`.
- Send signed authorization requests for JAR/FAPI deployments.
- Verify ID Tokens, signed authorization responses returned through JARM, signed
  introspection responses, and signed UserInfo responses.
- Build ID-JAG/EMA identity assertions for the JWT-bearer grant.
- Generate S256 PKCE verifier/challenge pairs.
- Fetch authorization-server metadata and JWKS with issuer validation.
- Verify RFC 9068 JWT access tokens from a remote issuer with coordinated JWKS
  rotation, bounded caching and stale-key use, DPoP/mTLS binding, and Plug
  integration.
- Correlate state/nonce/PKCE and an opaque browser-session binding in an atomic,
  expiring transaction store.
- Single-flight concurrent refresh-token rotation with bounded deadlines.
- Revoke tokens and create RP-Initiated Logout requests.
- Run the OID4VCI/OID4VP **wallet-holder** flow: receive a credential offer,
  request and verify credentials, and build presentations (EU wallet / HAIP).

`AttestoClient` is the client-side counterpart to
[`attesto`](https://hex.pm/packages/attesto). `attesto` verifies client artifacts
and issues server artifacts with the authorization server's keystore;
`AttestoClient` builds artifacts signed with the client's own key and verifies
the server artifacts a client receives.

On the server side of the same family,
[`attesto_phoenix`](https://github.com/XukuLLC/attesto_phoenix) is the
batteries-included Phoenix/Ecto authorization server built on `attesto`, and
[`attesto_mcp`](https://github.com/XukuLLC/attesto_mcp) protects a Model Context
Protocol server as an OAuth resource server.

It does **not** make authorization decisions or own application sessions. Its
included ETS store retains only short-lived protocol correlation data, and its
refresh coordinator retains no token set after a flight completes. The host
chooses its durable/distributed store, atomically persists rotation results,
maps verified identities to authorization, and applies session-retention
policy. `AttestoClient.DPoP` generates the RFC 9449 proofs for its own token
and credential requests; [`req_dpop`](https://hex.pm/packages/req_dpop) remains
the tool for DPoP-binding arbitrary outgoing requests.

## What it provides

- `AttestoClient.ClientAssertion` — `private_key_jwt` client authentication
  assertions (RFC 7523 / OpenID Connect Core §9).
- `AttestoClient.RequestObject` — signed authorization request objects (JAR,
  RFC 9101 / FAPI 2.0 Message Signing §5.3.1).
- `AttestoClient.JARM` — verify signed authorization responses (JARM, FAPI 2.0
  Message Signing §5.4) with unique-key selection and key-aware FAPI policy.
- `AttestoClient.IDToken` — verify OpenID Connect ID Tokens, including nonce,
  `max_age`, and key-aware `at_hash`, `c_hash`, and `s_hash` for RSA, EC,
  Ed25519, and Ed448 signatures.
- `AttestoClient.IdentityAssertion` — build Identity Assertion JWT
  Authorization Grant assertions (ID-JAG / EMA).
- `AttestoClient.PKCE` — generate S256 PKCE verifier/challenge pairs.
- `AttestoClient.SignedIntrospection` — verify RFC 9701 signed token
  introspection responses.
- `AttestoClient.UserInfo` — verify signed OpenID Connect UserInfo responses
  and bind them to a verified ID Token subject when supplied.
- `AttestoClient.Discovery` — fetch and read authorization-server metadata and
  JWKS (RFC 8414 / OpenID Connect Discovery 1.0).
- `AttestoClient.ResourceServer` — verify remote-issuer RFC 9068 JWT access
  tokens, coordinate JWKS refresh, and enforce exact OAuth scopes.
- `AttestoClient.ResourceServer.Plug` — authenticate Bearer, DPoP, and mTLS
  requests, fail closed on missing sender-constraint evidence, and assign
  verified claims.
- `AttestoClient.AuthorizationCode` — complete OIDC Authorization Code flow
  with S256 PKCE, nonce, issuer and browser-session binding, and one-time state.
- `AttestoClient.AuthorizationTransaction.Store.ETS` — bounded, expiring,
  single-node transaction store with atomic consumption.
- `AttestoClient.RefreshCoordinator` and `AttestoClient.Token` — deadline-bound,
  single-flight refresh rotation and RFC 7009 revocation.
- `AttestoClient.Logout` — RP-Initiated Logout request construction.

### Wallet-holder (OID4VCI / OID4VP)

The client-side of the EU-wallet stack — the holder role that receives and
presents verifiable credentials, mirroring `attesto`'s issuer/verifier core.

- `AttestoClient.Wallet` — the OID4VCI issuance flow end to end: exchange a
  credential offer's pre-authorized code, prove the holder key, request the
  credential, and verify each returned SD-JWT VC, `jwt_vc_json`, or mdoc. Supports
  batch issuance and the OID4VCI §10 Notification Endpoint.
- `AttestoClient.DPoP` — RFC 9449 DPoP proofs, sender-constraining the token and
  credential requests (with a `use_dpop_nonce` retry).
- `AttestoClient.WalletAttestation` / `AttestoClient.KeyAttestation` — OAuth
  attestation-based client authentication (Client Attestation + PoP) and OID4VCI
  key attestation, the HAIP-recommended wallet credentials.
- `AttestoClient.Wallet.Proof` / `AttestoClient.Wallet.CredentialOffer` — the
  holder key proof and credential-offer parsing.
- `AttestoClient.Wallet.Presentation` / `AttestoClient.Wallet.PresentationRequest`
  — OID4VP: verify a signed Authorization Request and build a `direct_post`
  `vp_token` (SD-JWT VC with a holder Key Binding JWT, or an ISO 18013-5 mdoc
  DeviceResponse), with claim minimisation.

## Example

```elixir
key = JOSE.JWK.generate_key({:ec, "P-256"})

{:ok, assertion} =
  AttestoClient.ClientAssertion.build(key,
    client_id: "my-client",
    audience: "https://op.example.com"
  )

# Submit it at the token / PAR / introspection endpoint:
#   client_assertion_type = AttestoClient.ClientAssertion.assertion_type()
#   client_assertion      = assertion
```

For a full authorization flow, store setup, callback handling, refresh,
revocation, and logout, see the
[Authorization Code guide](guides/authorization-code.md).

For inbound JWT access-token verification backed by a remote issuer, including
key rotation, stale-key behavior, scope checks, and Plug wiring, see the
[Remote issuer resource-server guide](guides/resource-server.md).

## Assurance

Build-side artifacts carry **cross-language parity tests** where practical: they
are checked against an independent, non-Elixir reference implementation (e.g.
PyJWT or Node's native crypto implementation), so correctness does not rest only
on this library and `attesto` agreeing with each other. This includes exact and
legacy Ed25519/Ed448 signatures plus the curve-dependent OIDC hash construction.
The mirror modules also carry in-family interop tests against the corresponding
attesto server-side issuer or verifier. External-reference tests skip cleanly
when their toolchain is absent, so they never block a plain `mix test`.

For release confidence, run them explicitly against a Python with the reference
libraries installed (the system Python is usually PEP-668 externally managed, so
use a venv):

```sh
python3 -m venv .venv
.venv/bin/pip install "pyjwt[crypto]"
ATTESTO_CLIENT_PYTHON=.venv/bin/python ATTESTO_PATH=1 mix test
```

When `ATTESTO_CLIENT_PYTHON` is unset the harness falls back to `python3` on the
`PATH`.

## Status

A stable `2.x` release: the public API follows [semantic versioning](https://semver.org/) —
minor and patch releases are backward-compatible, and breaking changes wait for
a new major version. Pin to `~> 2.3`.

## Requirements

AttestoClient requires Elixir 1.18 or later, Attesto 1.8 or later, and JOSE
1.11.12 or later within the JOSE 1.x line. The JOSE range keeps the patched
security floor while allowing native OTP SHA-3 and Ed448 improvements in later
compatible releases. Both this package and `attesto` use Elixir's built-in
`JSON` module, so lowering only this package's declared floor would not create a
working older-Elixir installation.

Ed448 verification and OIDC hash claims additionally require JOSE to have a
working Curve448 and SHAKE256 backend. That may come from supported native OTP
crypto in a later JOSE 1.x release, an installed backend, or JOSE's cryptographic
fallback. Operations fail closed when the required capability is unavailable.
