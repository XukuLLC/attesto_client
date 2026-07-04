# AttestoClient

[![Hex.pm](https://img.shields.io/hexpm/v/attesto_client)](https://hex.pm/packages/attesto_client)
[![Hexdocs.pm](https://img.shields.io/badge/docs-hexdocs.pm-blue)](https://hexdocs.pm/attesto_client)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Build and verify the OAuth and OpenID Connect wire artifacts an Elixir client
needs when your app already owns the HTTP flow: `private_key_jwt`, signed
authorization request objects (JAR), ID Token verification, JARM verification,
ID-JAG/EMA assertions, PKCE generation, signed introspection and UserInfo
verification, and discovery/JWKS fetching.

Use it when you are writing a relying party or OAuth client that needs the
cryptographic pieces without adopting a full redirect/session/token framework:

- Authenticate to token, PAR, or introspection endpoints with
  `private_key_jwt`.
- Send signed authorization requests for JAR/FAPI deployments.
- Verify ID Tokens, signed authorization responses returned through JARM, signed
  introspection responses, and signed UserInfo responses.
- Build ID-JAG/EMA identity assertions for the JWT-bearer grant.
- Generate S256 PKCE verifier/challenge pairs.
- Fetch authorization-server metadata and JWKS with issuer validation.

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

It is **not** a full OAuth client framework: no flow orchestrator, token store,
or session handling. It produces and checks the cryptographic wire-format
artifacts a FAPI client needs and leaves HTTP orchestration to the host. DPoP
proof generation for outgoing requests is
[`req_dpop`](https://hex.pm/packages/req_dpop)'s job.

## What it provides

- `AttestoClient.ClientAssertion` — `private_key_jwt` client authentication
  assertions (RFC 7523 / OpenID Connect Core §9).
- `AttestoClient.RequestObject` — signed authorization request objects (JAR,
  RFC 9101 / FAPI 2.0 Message Signing §5.3.1).
- `AttestoClient.JARM` — verify signed authorization responses (JARM, FAPI 2.0
  Message Signing §5.4).
- `AttestoClient.IDToken` — verify OpenID Connect ID Tokens, including nonce,
  `max_age`, `at_hash`, `c_hash`, and `s_hash`.
- `AttestoClient.IdentityAssertion` — build Identity Assertion JWT
  Authorization Grant assertions (ID-JAG / EMA).
- `AttestoClient.PKCE` — generate S256 PKCE verifier/challenge pairs.
- `AttestoClient.SignedIntrospection` — verify RFC 9701 signed token
  introspection responses.
- `AttestoClient.UserInfo` — verify signed OpenID Connect UserInfo responses
  and bind them to a verified ID Token subject when supplied.
- `AttestoClient.Discovery` — fetch and read authorization-server metadata and
  JWKS (RFC 8414 / OpenID Connect Discovery 1.0).

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

## Assurance

Build-side artifacts carry **cross-language parity tests** where practical: they
are checked against an independent, non-Elixir reference implementation (e.g.
PyJWT), so correctness does not rest only on this library and `attesto` agreeing
with each other. The mirror modules also carry in-family interop tests against
the corresponding attesto server-side issuer or verifier. The Python parity
tests skip cleanly when the reference toolchain is absent, so they never block a
plain `mix test`.

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

A `0.x` release: pre-1.0, API may change between minor versions. Pin to
`~> 0.6`.
