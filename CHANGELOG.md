# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
