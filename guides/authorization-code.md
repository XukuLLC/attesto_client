# Authorization Code + PKCE

AttestoClient owns protocol mechanics: discovery validation, S256 PKCE, state
and nonce correlation, code exchange, ID Token verification, refresh
single-flight, revocation, and logout request construction. Your application
still owns authorization, durable token persistence, and session policy.

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

Single-flight refresh protection covers callers sharing one coordinator
process. In a cluster, route each token-record key to one coordinator or place a
distributed lock/serialization layer around refresh; independent coordinators
cannot prevent cross-node reuse of the same refresh token.

## Start authorization

```elixir
store = {AttestoClient.AuthorizationTransaction.Store.ETS, MyApp.OIDCTransactions}

{:ok, request} =
  AttestoClient.AuthorizationCode.start(store,
    issuer: "https://accounts.example.com",
    client_id: "my-client",
    redirect_uri: "https://app.example.com/oidc/callback",
    scopes: ["openid", "profile", "email"],
    id_token_alg: "RS256"
  )

# Redirect the user agent to request.url.
```

`id_token_alg` must be the exact algorithm registered for the client. It is
checked against provider metadata and then used as the sole accepted ID Token
algorithm.

## Handle the callback

Pass the callback's string-keyed parameter map. State is consumed before the
token request, including for provider errors and invalid responses:

```elixir
{:ok, completed} =
  AttestoClient.AuthorizationCode.callback(store, callback_params,
    client_auth: {:private_key_jwt, client_private_jwk},
    timeout: 10_000
  )

claims = completed.id_token_claims
tokens = completed.tokens
```

A timeout means the token endpoint outcome is unknown. The code and transaction
have already been consumed and must not be retried.

Successful verification establishes protocol facts such as issuer, audience,
nonce, signature, and time validity. It does not decide that the subject may
access your application. Apply authorization before creating a session.

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

## Revocation and logout

```elixir
:ok =
  AttestoClient.Token.revoke(tokens.refresh_token,
    revocation_endpoint: metadata["revocation_endpoint"],
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
