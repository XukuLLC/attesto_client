# AttestoClient

[![Hex.pm](https://img.shields.io/hexpm/v/attesto_client)](https://hex.pm/packages/attesto_client)
[![Hexdocs.pm](https://img.shields.io/badge/docs-hexdocs.pm-blue)](https://hexdocs.pm/attesto_client)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Client-side OAuth 2.0 / OpenID Connect / FAPI 2.0 **artifacts and verification**
for Elixir relying parties. The client counterpart to
[`attesto`](https://hex.pm/packages/attesto) (the authorization server): where
attesto verifies client artifacts and issues server artifacts with the AS
keystore, `AttestoClient` *builds* the artifacts a client signs with its **own**
key, and *verifies* the artifacts a client receives.

It is **not** a full OAuth client framework — no flow orchestrator, token store,
or session handling. It produces and checks the cryptographic wire-format
artifacts a FAPI client needs and leaves HTTP orchestration to the host. DPoP
proof generation for outgoing requests is
[`req_dpop`](https://hex.pm/packages/req_dpop)'s job.

## Surface

- `AttestoClient.ClientAssertion` — `private_key_jwt` client authentication
  assertions (RFC 7523 / OpenID Connect Core §9).
- _planned:_ signed request objects (JAR, RFC 9101) and JARM response
  verification (FAPI 2.0 Message Signing §5.4).

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

Each artifact this library builds carries a **cross-language parity test**: it is
checked against an independent, non-Elixir reference implementation (e.g. PyJWT),
so correctness does not rest on this library and `attesto` agreeing with each
other. The parity tests skip cleanly when the reference toolchain is absent, so
they never block a plain `mix test`.

## Status

A `0.x` release: pre-1.0, API may change between minor versions. Pin to
`~> 0.1`.
