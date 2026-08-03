# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.3.0] - 2026-08-03

### Added

- Add the OID4VCI/OID4VP **wallet-holder** role. `AttestoClient.Wallet` drives
  pre-authorized_code issuance end to end — credential offer, token exchange,
  `c_nonce`, holder key proof, Credential Request, and verification of each
  returned credential (SD-JWT VC, `jwt_vc_json`, or mdoc) — with support for
  OID4VCI 1.0 final's plural `proofs`, batch issuance (a list of holder keys →
  one credential per key), and the §10 Notification Endpoint.
- Add `AttestoClient.DPoP` (RFC 9449 proof generation), threaded through the
  token and credential requests via a `:dpop` option with a `use_dpop_nonce`
  single retry; a DPoP-bound access token is presented with the `DPoP`
  authentication scheme.
- Add `AttestoClient.WalletAttestation` (OAuth Attestation-Based Client
  Authentication — Client Attestation JWT + per-request PoP) and a
  `{:client_attestation, ...}` client-auth method, and `AttestoClient.KeyAttestation`
  (OID4VCI Key Attestation) carried in the holder proof's `key_attestation`
  header. These are the client-side mirrors of the matching attesto verifiers.
- Add OID4VP presentation (`AttestoClient.Wallet.Presentation` /
  `PresentationRequest`): verify a signed Authorization Request, select held
  credentials by DCQL, and build a `direct_post` `vp_token` (SD-JWT VC with a
  holder Key Binding JWT, or an ISO 18013-5 mdoc DeviceResponse).

### Security

- Bind each issued credential to the holder key whose proof requested it
  (thumbprint membership, one credential per proof), and fail closed with
  `:missing_trusted` before any network call when no issuer trust anchor is
  supplied.
- Scope SD-JWT claim minimisation to top-level Disclosures (digest present in
  the issuer payload's `_sd`), so a nested claim sharing a requested top-level
  name is never disclosed; refuse `direct_post.jwt` in `submit/3`; check the
  signing key against the credential's holder binding before disclosing any
  contents; and validate the DCQL query shape so a signed-but-malformed request
  cannot crash selection.
- Refresh client-auth `jti`s on a DPoP-nonce retry (no replay), send a single
  Authorization header, require an explicit audience for the client-attestation
  PoP, and bound by-reference fetch bodies (with decompression disabled).

## [2.2.0] - 2026-07-25

### Added

- Support RFC 9864 `Ed25519` and `Ed448` identifiers across issuer-signed JWT
  verification and client artifact builders while retaining legacy `EdDSA`.
- Add independent Node crypto parity for Ed25519 and Ed448 signatures and OIDC
  detached hash claims.

### Security

- Bind ID Token `at_hash`, `c_hash`, and `s_hash` calculation to the verified
  issuer JWK. Legacy `EdDSA` now selects SHA-512 with a 32-byte left half for
  Ed25519 and SHAKE256 with 114 bytes of output and a 57-byte left half for
  Ed448.
- Move JARM onto the shared hardened verifier: require a unique eligible key,
  honor JWK `alg`, `use`, and `key_ops`, reject RSA keys below 2048 bits, bind
  every algorithm to its key type and curve, and apply FAPI's Ed25519-only
  Edwards policy by default. An explicit `accepted_algs` list remains a
  deliberate non-FAPI override unless `enforce_fapi_alg_policy: true` is set.
- Validate every explicit outbound signing algorithm against its private key
  before signing, including exact Edwards curve binding.

### Changed

- Require Attesto 1.3 or later for key-aware OIDC hashing and trusted-key
  algorithm validation.
- Keep the JOSE security floor at 1.11.12 while widening the upper-compatible
  range to all 1.x releases, so a future 1.x release with native OTP SHA-3 and
  Ed448 detection is reachable without another AttestoClient release.

## [2.1.1] - 2026-07-17

### Security

- Restrict the optional Plug integration to the security-patched releases on
  every supported minor line: Plug 1.16.6, 1.17.4, 1.18.5, 1.19.5, and 1.20.3
  and later 1.x releases.
- Raise the JOSE floor to 1.11.12, excluding releases affected by
  GHSA-9mg4-v392-8j68 / CVE-2023-50966, the 1.11.7-1.11.8 packages that
  included development-only tooling as runtime dependencies, and the
  1.11.9-1.11.10 releases with broken EC key conversion on OTP 28. JOSE
  1.11.11 fixed that conversion but could encode Elixir `nil` as the JSON
  string `"nil"` with OTP's built-in JSON module; 1.11.12 fixes that too.
- Refresh the development lock to Mint 1.9.3, resolving
  EEF-CVE-2026-59249 / CVE-2026-59249.
- Extend discovery and JWKS SSRF checks across non-global IPv4, translated
  IPv6, deprecated site-local, and local-use NAT64 destinations while retaining
  globally reachable anycast and public NAT64 targets.
- Require a replay callback for every DPoP request; the former test-only
  acknowledgement flag can no longer disable replay protection.
- Keep internal token, DPoP, certificate, and nonce rejection reasons out of
  OAuth error responses.

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
