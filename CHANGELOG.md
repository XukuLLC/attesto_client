# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
- Internal `AttestoClient.Builder` shared by the builders (not public API).
