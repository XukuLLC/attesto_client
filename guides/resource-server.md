# Remote issuer resource server

`AttestoClient.ResourceServer` verifies RFC 9068 JWT access tokens issued by a
remote OAuth authorization server. It is the lightweight inbound-verification
layer for an application that does not run the issuer itself: it depends on the
existing client-side discovery, JWKS, and JOSE machinery and does not bring in
Phoenix, Ecto, token issuance, or authorization-server endpoints.

The verifier authenticates tokens and can require scopes. Your application
still decides what a subject may do, maps claims to local identities, owns
revocation/introspection policy, and chooses session retention.

## Supervision

Start one process per trusted issuer. The accepted algorithm list is explicit;
do not derive it from discovery or a token header.

```elixir
children = [
  {AttestoClient.ResourceServer,
   name: MyApp.RemoteIssuer,
   issuer: "https://issuer.example",
   audience: "https://api.example",
   accepted_algs: ["PS256", "ES256"],
   fresh_ttl: :timer.minutes(5),
   stale_ttl: :timer.hours(1),
   unknown_kid_refresh_interval: :timer.seconds(30),
   refresh_retry_interval: :timer.seconds(5),
   refresh_timeout: :timer.seconds(10),
   max_jwks_keys: 32,
   max_response_bytes: 512 * 1024}
]

Supervisor.start_link(children, strategy: :one_for_one)

:ok = AttestoClient.ResourceServer.warm(MyApp.RemoteIssuer)
true = AttestoClient.ResourceServer.ready?(MyApp.RemoteIssuer)
```

The issuer must be HTTPS. By default the OpenID Connect discovery document is
used; set `well_known: :oauth_authorization_server` for RFC 8414 metadata. A
trusted, already-validated metadata map or JWKS URI can be supplied with
`:metadata` or `:jwks_uri`, but the JWKS request remains HTTPS-only.
`accepted_algs` is mandatory and must be chosen from the algorithms the
deployment permits; it is never derived from discovery or a token header.

`warm/1` completes metadata and JWKS retrieval and refuses a key set that has
no usable key for the configured algorithms. `ready?/1` reports whether a
successfully validated key snapshot remains within its permitted lifetime.
Verification also warms lazily, which is useful outside an application
supervision tree, but production readiness should call `warm/1` explicitly.

## Pure verification API

```elixir
{:ok, claims} =
  AttestoClient.ResourceServer.verify(MyApp.RemoteIssuer, access_token,
    required_scopes: ["documents.read"],
    allowed_subjects: ["service-account-1"],
    allowed_client_ids: ["client-1"],
    max_token_age_seconds: 300,
    max_token_lifetime_seconds: 900
  )
```

The verifier requires the RFC 9068 `at+jwt` JOSE type and validates:

- signature, algorithm allowlist, unique eligible key selection, and minimum
  RSA strength;
- exact issuer and a configured audience;
- `exp`, `iat`, optional `nbf`, `sub`, `client_id`, and `jti`;
- the optional space-delimited OAuth `scope` claim and every requested scope;
- the complete `cnf` confirmation object and its binding to current-request
  DPoP or mTLS evidence.

Scope strings are exact OAuth tokens. This layer does not define an application
scope catalog or grant a business capability merely because a claim exists.
Subject/client allowlists and age/lifetime limits are optional token-acceptance
policy; object-level authorization and business decisions remain application
owned.

## Key rotation and outage behavior

Verification uses cached keys while they are fresh. When the fresh interval
ends, callers coordinate one discovery/JWKS refresh. A token naming an unknown
`kid` also requests one coordinated refresh so normal signing-key rotation does
not require waiting for cache expiry.

Unknown `kid` refreshes are throttled across all key IDs. This prevents random
attacker-selected values from turning one request into one upstream fetch.
`max_jwks_keys` bounds retained keys.

When refresh fails because of a transport error, HTTP 429, or HTTP 5xx, a known
cached key may remain usable only until the configured stale interval ends. A
metadata issuer mismatch, invalid JWKS, blocked host, non-HTTPS URI, redirect,
or other validation failure never activates stale fallback. An unknown key
cannot be authenticated by stale data.

After a transient failure, `refresh_retry_interval` prevents every request from
starting another refresh while the stale snapshot remains usable. Req retries
are disabled, `max_response_bytes` bounds metadata and JWKS response bodies
before JSON decoding, and `refresh_timeout` bounds the single coordinated
operation. Applications should monitor refresh errors and choose stale and
retry intervals according to issuer rotation and incident-response
requirements.

## Plug integration

With Plug available, wire the verifier directly into a protected route:

```elixir
plug AttestoClient.ResourceServer.Plug,
  server: MyApp.RemoteIssuer,
  required_scopes: ["documents.read"],
  claims_key: :attesto_claims,
  resource_metadata: "https://api.example/.well-known/oauth-protected-resource"
```

Successful verification assigns string-keyed claims. Missing or invalid tokens
produce RFC 6750 `invalid_token` responses; an authenticated token lacking a
route scope produces `403 insufficient_scope`. If initial key retrieval fails
or no permitted stale snapshot exists, the plug returns a detail-free `503`
with no authentication challenge, preventing an upstream availability failure
from being misreported as an invalid client credential.

### DPoP

DPoP presentation uses `Authorization: DPoP <token>` plus the `DPoP` proof
header. Replay protection is mandatory:

```elixir
plug AttestoClient.ResourceServer.Plug,
  server: MyApp.RemoteIssuer,
  required_scopes: ["documents.write"],
  replay_check: &MyApp.DPoPReplay.check_and_record/2,
  nonce_check: &MyApp.DPoPNonce.check/1,
  nonce_issue: &MyApp.DPoPNonce.issue/0,
  dpop_max_age_seconds: 60
```

The proof is bound to the request method, externally visible HTTPS URI, and
access-token hash. Its JWK thumbprint must match `cnf.jkt`. A deployment behind
a trusted proxy must rewrite the connection to the external scheme and host, or
provide an `:htu` callback. The plug rejects DPoP when replay storage is absent.

### Mutual TLS

For RFC 8705 certificate-bound tokens, provide the DER certificate already
authenticated by the TLS layer:

```elixir
plug AttestoClient.ResourceServer.Plug,
  server: MyApp.RemoteIssuer,
  cert_der: &MyApp.TLS.authenticated_client_certificate/1
```

The callback is not a trust decision. The listener or trusted TLS terminator
must validate the certificate chain, validity, and revocation status before
exposing its DER bytes. The plug computes the SHA-256 thumbprint and requires it
to match `cnf["x5t#S256"]`.

An ambient authenticated client certificate does not turn an otherwise
unbound token into an mTLS-bound token and does not cause rejection. Only a
token carrying `cnf["x5t#S256"]` requires and validates that evidence.

Bound tokens never degrade to bearer tokens: missing, malformed, cross-scheme,
or mismatched confirmation evidence is rejected.

## Result compatibility

`verify/3` returns `{:ok, claims}` or a typed `{:error, reason}` and does not
raise for an untrusted token. Signature, issuer, audience, time, confirmation,
and token-policy failures are authentication errors. `:insufficient_scope` is
separate so an HTTP layer can return `403`. A
`{:jwks_refresh_failed, reason}` result means the verifier could not establish
a usable validated key snapshot and no permitted stale snapshot was available;
the Plug maps that class to a detail-free `503`.

Startup configuration is trusted application input and is validated eagerly;
invalid issuer, audience, algorithm, cache-bound, or timeout options raise
`ArgumentError`. This distinction keeps deployment mistakes out of the
untrusted-token error surface.
