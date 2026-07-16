# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.1.0] - 2026-07-16

### Added

- Add `AttestoClient.ResourceServer`, a supervised remote-issuer RFC 9068 JWT
  access-token verifier. It performs exact issuer and audience checks, strict
  algorithm/key selection, required claim and time validation, exact scope
  enforcement, optional subject/client and token-age/lifetime policy, explicit
  warming/readiness, and fail-closed DPoP/mTLS confirmation binding.
- Add coordinated discovery/JWKS caching with bounded key count, configurable
  fresh and stale intervals, transient-error-only stale-key use, single-flight
  refresh, unknown-`kid` rotation refresh, response-size limits, and refresh-
  storm throttling/backoff.
- Add `AttestoClient.ResourceServer.Plug` for Bearer, DPoP, and mTLS protected
  resources, including fail-closed DPoP replay wiring and RFC 6750 error and
  insufficient-scope responses. Upstream key availability failures produce a
  detail-free `503` rather than an `invalid_token` challenge.
- Add bidirectional PyJWT parity coverage for RFC 9068 signing and verification,
  including an independently signed unknown-`kid` key-rotation flow.

### Security

- Remote discovery and JWKS refreshes retain HTTPS, exact-issuer, SSRF, and
  redirect protections; disable Req retries and bound each coordinated refresh
  with an application-configured deadline.

## [2.0.0] - 2026-07-16

### Security

- Add a complete OpenID Connect Authorization Code flow that always uses S256
  PKCE, binds callbacks to high-entropy state, nonce, and a mandatory opaque
  application browser-session value, validates the response issuer when
  supplied, atomically consumes expiring transaction state, pins the registered
  ID Token algorithm, and gives the code exchange a bounded deadline with
  retries disabled.
- ID Token verification now rejects ambiguous eligible JWKS keys and RSA keys
  below 2048 bits, honors JWK `use` / `key_ops`, validates optional `nbf`, and
  uses constant-time nonce/subject comparisons. A missing `kid` remains valid
  only when exactly one eligible verification key exists.
- Add bounded single-flight refresh-token rotation. Concurrent callers for one
  application key share one request and one result; timeout and worker failure
  wake all waiters and clear the flight.
- Require HTTPS redirect URIs except for native-client loopback HTTP redirects.
- Raise the Req dependency floor to 0.6.1, the first release patched for
  EEF-CVE-2026-49755 decompression-bomb denial of service.

### Added

- `AttestoClient.AuthorizationTransaction.Store` and a bounded, single-node ETS
  implementation with atomic insert/consume and monotonic expiry.
- `AttestoClient.Token` refresh and RFC 7009 revocation operations,
  `AttestoClient.RefreshCoordinator`, `AttestoClient.TokenSet`, and verified
  refresh ID Token results.
- `AttestoClient.Logout.url/1` for OpenID Connect RP-Initiated Logout.
- Structural discovery validation for required OIDC endpoints and capability
  fields before an authorization flow uses them.
- Adversarial coverage for replay and concurrent state consumption, expiry,
  issuer/audience/nonce confusion, ambiguous or ineligible keys, weak RSA,
  malformed discovery, refresh races, independent refreshes, and deadlines.
- Authorization-request `max_age` is retained in the transaction and enforced
  against the callback ID Token's `auth_time`.

### Changed

- Supplying `:access_token` to `AttestoClient.IDToken.verify/2` validates
  `at_hash` when present but no longer requires the claim for a token-endpoint
  ID Token, where OIDC Core permits omission. Pass `require_at_hash: true` for
  front-channel or profile rules that require it.
- Authorization decisions, durable token persistence, refresh-result
  compare-and-swap, and session-retention/termination remain application-owned.
- The Elixir floor remains 1.18: this package and its required `attesto`
  dependency both depend on Elixir's built-in `JSON` module.

### Migration

- `AttestoClient.AuthorizationCode.start/2` and `callback/3` now require the
  same opaque `:browser_binding`. Generate or retain it in the initiating user
  agent's secure application session; callbacks with a missing or different
  binding consume state and fail before token exchange.
- The key-selection and minimum-RSA checks intentionally reject tokens that 1.x
  could accept. Applications with duplicate `kid` values, multiple eligible
  kid-less keys, encryption-only verification keys, or RSA keys below 2048 bits
  must correct their JWKS before upgrading.
- Because those security checks tighten existing public verification APIs,
  this release is a **2.0.0** major release.

## [1.1.0] - 2026-07-07

### Changed

- `AttestoClient.Discovery.fetch/2` now compares the document's `issuer`
  **exactly** against the supplied issuer (RFC 8414 §3.3 / OpenID Connect
  Discovery 1.0 §4.3) instead of normalising a trailing slash away. A
  slash-terminated path issuer (e.g. a multi-tenant issuer, or the OpenID
  conformance suite's `https://.../test/a/<alias>/`) was previously rejected
  with `:issuer_mismatch`; conversely, two identifiers that differ only by a
  trailing slash no longer match. The trailing slash is still removed when
  constructing the well-known request URL, as both specs require.

### Added

- `AttestoClient.IDToken.verify/2` accepts `allow_unsigned: true`, an explicit
  opt-in for the OIDC Core §3.1.3.7 case: a client that registered
  `id_token_signed_response_alg` `none` and received the ID Token directly from
  the token endpoint over TLS may accept an unsigned (`alg: "none"`) token. All
  claim checks still run; the signature part must be empty; signed tokens are
  unaffected; the default remains to reject unsigned tokens.

## [1.0.0] - 2026-07-04

First stable release; the public API is now under semantic versioning. No
functional change from 0.6.0. Requires `attesto ~> 1.0`.

## [0.6.0] - 2026-06-21

### Security

- `AttestoClient.Discovery` hardens its discovery/JWKS fetches against SSRF:
  redirects are no longer followed (a 3xx surfaces as `{:http_status, _}` rather
  than being chased to its `Location`), and a URL whose host resolves to a
  loopback, private, link-local, or unique-local address is rejected with
  `:blocked_host` — so an attacker-influenced `issuer`/`jwks_uri` cannot point a
  server-side fetch at an internal service or the cloud metadata endpoint. An
  unresolvable host is left to the transport.

### Added

- `AttestoClient.IDToken` - verify OpenID Connect ID Tokens against authorization
  server JWKS/discovery, including issuer, audience, `azp`, expiration,
  issued-at, nonce, `max_age`/`auth_time`, and detached `at_hash` / `c_hash` /
  `s_hash` validation. Interop-tested against `Attesto.IDToken.mint/4`.
- `AttestoClient.IdentityAssertion` - build Identity Assertion JWT
  Authorization Grant assertions (ID-JAG / EMA) with the `oauth-id-jag+jwt`
  header and the required `iss`/`sub`/`aud`/`client_id`/`jti`/`iat`/`exp`
  claims. Interop-tested against `Attesto.IdentityAssertion.verify/3`.
- `AttestoClient.PKCE` - generate S256 PKCE verifier/challenge pairs, delegating
  challenge computation to `Attesto.PKCE.challenge/1` so generated pairs verify
  under `Attesto.PKCE.verify/3`.
- `AttestoClient.SignedIntrospection` - verify RFC 9701 signed token
  introspection responses against authorization-server JWKS/discovery.
  Interop-tested against `Attesto.SignedIntrospection.response_jwt/4`.
- `AttestoClient.UserInfo` - verify signed OpenID Connect UserInfo JWT
  responses, including issuer/audience/subject checks and optional binding to a
  previously verified ID Token subject.
- Internal AttestoClient.Verifier shared by the AS-signed JWT verifiers (not
  public API; hidden from docs).
- `AttestoClient.ClientAssertion` - build `private_key_jwt` client
  authentication assertions (RFC 7523 / OpenID Connect Core §9), signed with the
  client's own key. Carries a cross-language parity test against an independent
  PyJWT reference verifier, plus in-family interop against
  `Attesto.ClientAssertion.verify/5`.
- `AttestoClient.RequestObject` - build signed authorization request objects
  (JAR, RFC 9101 / FAPI 2.0 Message Signing §5.3.1): the caller's authorization
  parameters wrapped with the iss/aud/iat/nbf/exp/jti envelope and the
  `oauth-authz-req+jwt` typ, signed with the client's key. The lifetime is
  bounded to the FAPI 60-minute window. Parity-tested against an independent
  PyJWT reference and in-family against `Attesto.RequestObject.verify/3` under
  the FAPI Message Signing policy.
- Internal AttestoClient.Builder shared by the builders (not public API; hidden from docs).
- `AttestoClient.JARM` - verify a signed authorization response (JARM, FAPI 2.0
  Message Signing §5.4): JWS signature against the authorization server's JWKS
  (FAPI algorithm allow-list, `none` rejected, kid selection), plus `iss`/`aud`/
  `iat`/`exp`, returning the response parameters. Parity-tested by verifying a
  JARM token signed by an independent PyJWT signer (the flipped external
  direction) and one signed by `Attesto.JARM.response_jwt/4` (in-family).
- `AttestoClient.Discovery` - fetch and read OAuth 2.0 / OpenID Connect
  authorization-server metadata and JWKS (RFC 8414 / OpenID Connect Discovery
  1.0) over `Req`, with `https` and RFC 8414 §3.3 issuer-match validation.
  Verified in-family against `Attesto.OpenIDDiscovery.metadata/2` output.

### Changed

- Require `attesto ~> 0.9` so the client mirror can use the current ID Token,
  ID-JAG, PKCE, signed introspection, signing-algorithm, and hash primitives.
