# Authorization Code + PKCE

AttestoClient owns protocol mechanics: discovery validation, S256 PKCE, state
and nonce correlation, code exchange, ID Token verification, refresh
single-flight, revocation, and logout request construction. Your application
still owns authorization, durable token persistence, and session policy.

For a browser frontend, use this server-side client as the backend for frontend
described in [RFC 10017](https://www.rfc-editor.org/rfc/rfc10017.html). Keep
OAuth tokens on the backend; protect the browser session with secure, HttpOnly
cookies and CSRF defenses, and authenticate the backend as a confidential
client. A browser session should end when its usable grant expires.

## Supervision

The included transaction store and each refresh coordinator process are
node-local. Start them under your supervisor:

```elixir
children = [
  {AttestoClient.AuthorizationTransaction.Store.ETS,
   name: MyApp.OIDCTransactions, max_entries: 10_000},
  {AttestoClient.RefreshCoordinator, name: MyApp.OIDCRefreshes}
]
```

If callbacks can land on different nodes, implement
`AttestoClient.AuthorizationTransaction.Store` over a shared database or cache.
Its `put_new/4` and `take/2` operations must be atomic, and `take/2` must delete
before returning.

Login starts can allocate store capacity before authentication. Rate-limit the
start endpoint per client and network/user signal, and monitor
`:capacity_exceeded` rather than treating the configured bound as abuse
protection by itself.

Single-flight refresh protection covers callers sharing one coordinator
process. In a cluster, route each token-record key to one coordinator or place a
distributed lock/serialization layer around refresh; independent coordinators
cannot prevent cross-node reuse of the same refresh token.

## Start authorization

```elixir
store = {AttestoClient.AuthorizationTransaction.Store.ETS, MyApp.OIDCTransactions}

# Generate this once per initiating browser session and retain it only in the
# application's secure, HttpOnly session. Do not put it in the redirect URL.
browser_binding = application_browser_session_binding

{:ok, request} =
  AttestoClient.AuthorizationCode.start(store,
    issuer: "https://accounts.example.com",
    client_id: "my-client",
    browser_binding: browser_binding,
    redirect_uri: "https://app.example.com/oidc/callback",
    scopes: ["openid", "profile", "email"],
    id_token_alg: "RS256"
  )

# Redirect the user agent to request.url.
```

`id_token_alg` must be the exact algorithm registered for the client. It is
checked against provider metadata and then used as the sole accepted ID Token
algorithm. RFC 9864 `Ed25519` and `Ed448` identifiers are supported only with
their matching issuer JWK curve; legacy `EdDSA` remains compatible with both.
Detached `at_hash` and `c_hash` validation uses the verified key to distinguish
Ed25519's SHA-512 profile from Ed448's SHAKE256 profile.

The browser binding is mandatory protocol correlation: a callback created in
one browser session cannot establish a login in another. AttestoClient treats
it as an opaque value and does not create, retain, or authorize the application
session. A fresh random value with at least 256 bits of entropy retained in the
server-side session (or protected by the framework's secure session mechanism)
is a suitable binding.

HTTPS redirect URIs are required for web clients. HTTP is accepted only for
loopback redirects (`127.0.0.0/8`, `[::1]`, or `localhost`) used by native
clients.

## Plain OAuth, PAR and DPoP

Use `protocol: :oauth` for an authorization server that does not provide an
OIDC login, including OID4VCI issuance. Discovery uses RFC 8414 metadata;
`openid`, a nonce and an ID Token are not required. The callback returns
`id_token_claims: nil`. State, browser binding, S256 PKCE and issuer checks
still apply, and the selected protocol is pinned in the stored transaction.

Pass `par: true` to push the bound request to the advertised PAR endpoint
before redirecting. `:client_auth` and `:dpop` apply to that request. The
default `par: :auto` uses PAR when metadata requires it. `haip: true` and
`fapi?: true` require PAR regardless of the metadata flag: an absent PAR
endpoint fails locally, and `par: false` cannot override the profile. A failed
PAR or a transaction that expires during PAR is removed. Successful PAR requires
HTTP 201, and the returned
`expires_in` reflects both the remaining transaction and PAR lifetimes.

When supplying `dpop:` at start, retain the same private key for the callback.
Its thumbprint is sent as `dpop_jkt`; a different or missing key fails before
code exchange, and a Bearer token response is rejected. Client authentication
supports the existing secret and private-key methods and
`{:client_attestation, attestation, instance_key, options}`.

Select exactly one of `haip: true` or `fapi?: true`; selecting both is an
error. The selected profile is stored with the transaction and cannot be
downgraded by callback flags. Both require an authenticated PAR request and
token exchange, a retained DPoP private key, and the authorization response's
`iss`. These requirements are checked even when metadata omits their flags.
Missing authentication or signing material fails before discovery; a changed
method, client identifier, authentication key, or DPoP key fails before token
HTTP.

FAPI uses the supported `private_key_jwt` method with a FAPI-compatible
algorithm and key. Set `alg: "PS256"` explicitly for RSA client authentication;
its generic inferred default is RS256. The DPoP key's inferred algorithm must
also satisfy the profile, so an EC P-256 or Ed25519 key is suitable. This API
does not establish an mTLS client/certificate binding; TLS request options or
a flag cannot substitute for the required DPoP key.

HAIP supports authenticated methods according to the issuer's ecosystem
policy, including client attestation. Retain the client subject and
instance key through callback and refresh, with `sub` matching `client_id`, `cnf`
matching that key, and the PoP audience matching the authorization server
issuer. A refreshed challenge may be supplied without changing that identity.
Renewed attestations may change their timestamps, JWT identifier, signature,
provider certificate or optional `iss` claim while retaining the client subject,
instance key and PoP algorithm. HAIP's Appendix E format requires an `x5c`
header. This client accepts 1–8 base64 DER certificates, each at most 64 KiB decoded.
The client checks complete DER certificate structure before HTTP. The
authorization server still verifies attester signatures, certificate trust and
attestation validity; local consistency checks do not authenticate the provider.
Generic OAuth and OIDC transactions retain their existing authentication
choices.

HAIP authorization requests require a nonempty credential-type scope. The
application must choose a scope mapped by the issuer to the requested
credential configuration. For FAPI OIDC, an omitted `id_token_alg` selects an
advertised compliant algorithm in the order ES256, PS256, Ed25519, EdDSA;
an explicitly incompatible algorithm fails locally. Verification also checks
the selected issuer key's FAPI algorithm and strength rules.

Issued token sets retain local `profile`, `client_auth_binding`, `client_id`,
`issuer` and `id_token_alg` provenance alongside `dpop_jkt`. These values are
derived from the trusted transaction rather than token-endpoint JSON. Retain the full token
set for later profile-aware operations.

When upgrading a shared transaction store, pending generic transactions that
lack the new profile fields remain supported. Pending protected transactions
with the old issuer-protection flag but no explicit profile must be restarted;
the client rejects them locally rather than inferring an authentication policy.

Extra authorization parameters cannot override bound protocol fields or client
authentication. This includes bracket aliases such as `state[value]` and
`client_assertion[]`, which web frameworks decode under the protected root.
The original query strings of discovered authorization, PAR and token
endpoints are checked too: protected exact names, bracket aliases, and
duplicate decoded roots are rejected before merging or making a request.
Benign fixed endpoint parameters remain supported.

See the [Credential wallet guide](credential-wallet.md#3-use-authorization-code-issuance-with-par-and-dpop)
for a complete plain OAuth/PAR integration example.

## Handle the callback

Pass the original callback URI or raw URL-encoded query whenever it is
available. The client rejects repeated names before building a map, including
equivalent percent-encoded names such as `code` and `co%64e`:

```elixir
{:ok, completed} =
  AttestoClient.AuthorizationCode.callback(store, conn.query_string,
    browser_binding: browser_binding_from_secure_session,
    client_auth: {:private_key_jwt, client_private_jwk},
    timeout: 10_000
  )

claims = completed.id_token_claims
tokens = completed.tokens
```

A string-keyed parameter map remains accepted for framework integrations. A map
cannot reveal duplicate names that the framework already collapsed, so the host
must reject duplicates before parsing when the original URI or body is not
passed to `callback/3`.

State is consumed before the token request, including for provider errors and
invalid responses. An ambiguous encoded response is rejected before state is
consumed.

A timeout means the token endpoint outcome is unknown. The code and transaction
have already been consumed and must not be retried.

Successful verification establishes protocol facts such as issuer, audience,
nonce, signature, and time validity. It does not decide that the subject may
access your application. Apply authorization before creating a session.

When several providers share a client, prefer a distinct registered redirect
URI for each provider. This prevents provider mix-up when an older provider
does not return the authorization-response `iss` parameter.

## Refresh rotation

Use a stable, non-secret key for the token record. Concurrent calls using the
same key share one request and result:

```elixir
{:ok, result} =
  AttestoClient.Token.refresh(MyApp.OIDCRefreshes, token_record_key, tokens,
    token_endpoint: metadata["token_endpoint"],
    issuer: metadata["issuer"],
    metadata: metadata,
    client_id: "my-client",
    client_auth: {:private_key_jwt, client_private_jwk},
    subject: verified_subject,
    id_token_alg: "RS256",
    timeout: 10_000
  )
```

Compare-and-swap the stored token set with `result.tokens` against the prior
record version or refresh token, rejecting stale results. The coordinator does
not retain it after returning. If the response contains an ID Token,
`result.id_token_claims` contains its verified claims; issuer, audience,
subject, algorithm, time, and any `at_hash` are checked.

Refresh uses the selected algorithm retained in `tokens.id_token_alg`, so FAPI
ES256 flows do not need to repeat `id_token_alg` on refresh. Persist this field
with the token set. A conflicting explicit option returns
`{:error, :id_token_alg_mismatch}` before discovery or token HTTP. Successful
refreshes retain it even when no ID Token is returned, and shared results must
match each caller's algorithm. Legacy token sets without a retained algorithm
use the explicit option or the previous default (PS256 for FAPI, RS256
otherwise), then retain that selection for later refreshes.

For DPoP tokens, also pass `dpop: original_private_key`. A missing signing key,
public-only key, or a key that differs from the locally recorded
`tokens.dpop_jkt` fails before discovery or token HTTP. A requested or previous
DPoP token cannot accept a Bearer response; token-type comparison is case
insensitive. Successful refresh carries the local thumbprint across rotation,
including nonce retries. Persist it with the token set, rather than deriving it
from untrusted token-endpoint JSON. A coalesced result is checked against each
caller's key; another caller's key cannot be adopted under the same record key.

Legacy or manually assembled DPoP token sets without `dpop_jkt` still require a
signing key. Their historical key continuity cannot be checked; after a
successful DPoP refresh the supplied key is recorded for subsequent refreshes.

When the provider implements
[refresh-expiration draft03](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-refresh-token-expiration-03),
`result.tokens.refresh_token_timeout` and `authorization_expires_in` carry
validated, literal durations in seconds. Record the response time when deriving
deadlines; a retry must not restart a previously recorded grant deadline.
Absent fields stay `nil`, and credentials may expire earlier through revocation.

## Revocation and logout

```elixir
:ok =
  AttestoClient.Token.revoke(tokens.refresh_token,
    revocation_endpoint: metadata["revocation_endpoint"],
    issuer: metadata["issuer"],
    client_id: "my-client",
    client_auth: {:private_key_jwt, client_private_jwk},
    token_type_hint: "refresh_token"
  )

{:ok, logout_url} =
  AttestoClient.Logout.url(
    issuer: metadata["issuer"],
    metadata: metadata,
    id_token_hint: tokens.id_token,
    client_id: "my-client",
    post_logout_redirect_uri: "https://app.example.com/logged-out",
    state: application_generated_logout_state
  )
```

The application correlates logout state and decides when to terminate its local
session. Revocation and provider logout do not substitute for local policy.
