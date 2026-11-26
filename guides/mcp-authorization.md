# MCP authorization

`AttestoClient.MCPAuthorization` coordinates the OAuth authorization policy in
MCP 2025-11-25 and 2026-07-28. It deliberately does not implement MCP JSON-RPC
or HTTP session handling. Your MCP client owns that transport and calls this
module when a request receives an authorization challenge.

The coordinator provides:

- RFC 9728 protected-resource discovery, including a challenge's
  `resource_metadata` pointer and the path-to-root compatibility fallback;
- RFC 8414 and OpenID Connect authorization-server discovery, with exact
  issuer checking and explicit S256 PKCE support;
- issuer-bound pre-registration, Client ID Metadata Document, opt-in Dynamic
  Client Registration, or a host prompt;
- authorization code + PKCE, refresh, exact RFC 8707 resource binding, and
  Bearer-only presentation;
- bounded `insufficient_scope` retries and safe authorization-server
  migration.

The application persists registrations and token sets, protects client
secrets, opens the browser, associates callbacks with the initiating user, and
decides whether the user may connect to a server.

## Supervision

Use the same transaction store and refresh coordinator as a generic OAuth
authorization-code client:

```elixir
children = [
  {AttestoClient.AuthorizationTransaction.Store.ETS,
   name: MyApp.MCPTransactions, max_entries: 10_000},
  {AttestoClient.RefreshCoordinator, name: MyApp.MCPRefreshes}
]

store = {AttestoClient.AuthorizationTransaction.Store.ETS, MyApp.MCPTransactions}
```

The included processes are node-local. Use a shared transaction store and
distributed refresh serialization when callbacks and refreshes may run on
different nodes.

## 1. Discover from the challenge

After an unauthenticated MCP request returns 401, pass the requested server URL
and every `WWW-Authenticate` field value:

```elixir
{:ok, authorization} =
  AttestoClient.MCPAuthorization.discover("https://mcp.example.com/mcp",
    www_authenticate: response_headers["www-authenticate"],
    offline_access: true
  )
```

The challenge's Bearer scope takes priority over
`scopes_supported` in protected-resource metadata. `offline_access: true` adds
that scope only when the authorization server advertises it. No scope is
invented when neither source supplies one.

Without a valid challenge pointer, discovery tries the path-specific protected
resource document first. It tries the origin-root document only after a 404.
For an MCP URL below the origin, the root document may identify either the
requested URL or the exact origin. The document's identifier becomes the
resource sent on every authorization and token request. Pass an explicit
`resource_well_known: :path` or `:root` to select only that location.

Authorization-server metadata is tried in this order:

1. RFC 8414 path insertion;
2. OpenID Connect path insertion;
3. OpenID Connect path appending.

Only a 404 advances to the next URL. A malformed document, issuer mismatch,
transport error, or another HTTP status stops discovery.

## 2. Select and persist a registration

Registration selection is deterministic:

1. an existing registration bound to this exact issuer;
2. a configured pre-registration for this exact issuer;
3. a validated Client ID Metadata Document when the server advertises support;
4. Dynamic Client Registration when explicitly enabled and advertised;
5. a host prompt callback.

For a pre-registered public client:

```elixir
{:ok, registration} =
  AttestoClient.MCPAuthorization.select_registration(authorization,
    registration: load_registration_for_server(),
    pre_registered: %{
      "https://accounts.example.com" => %{
        client_id: "mcp-desktop-client",
        client_auth: :none
      }
    }
  )

persist_registration(registration)
```

For a Client ID Metadata Document, the host fetches or otherwise obtains the
document and supplies its decoded value:

```elixir
client_id_metadata: %{
  client_id: "https://client.example.com/oauth/client.json",
  document: decoded_document,
  client_auth: :none
}
```

Dynamic registration must be opted into because it creates state at the
authorization server:

```elixir
dynamic_registration: [
  client_name: "Example MCP Client",
  redirect_uris: ["http://127.0.0.1:45123/callback"],
  application_type: :native,
  token_endpoint_auth_method: "none"
]
```

If `token_endpoint_auth_method` is omitted, the client chooses the first
advertised method it supports: `client_secret_basic`, `client_secret_post`, or
`none`. Web clients must use HTTPS redirect URIs. Native clients may also use
loopback HTTP redirect URIs; arbitrary custom schemes are refused. Persist the
returned registration as a credential; its `Inspect`
implementation omits `client_auth`, but storage must still protect it.

## 3. Start and complete authorization

```elixir
browser_binding = application_browser_session_binding

{:ok, request} =
  AttestoClient.MCPAuthorization.start(authorization, registration, store,
    redirect_uri: "https://client.example.com/oauth/callback",
    browser_binding: browser_binding
  )

# Redirect the user agent to request.url.
```

At the callback, pass the raw query string when available so duplicate
parameters can be rejected:

```elixir
{:ok, completed} =
  AttestoClient.MCPAuthorization.callback(
    authorization,
    registration,
    store,
    conn.query_string,
    browser_binding: browser_binding
  )

tokens = completed.tokens
persist_token_set(tokens)
```

The stored transaction pins the issuer, metadata, client identity, resource,
and requested scopes. The callback also checks that those pins match the
supplied MCP context and registration before token HTTP. It validates an RFC
9207 response issuer when
advertised, repeats the resource at the token endpoint, retains requested
scope when the response omits it, and refuses a non-Bearer access token.
DPoP options are refused before creating or consuming authorization state;
core MCP authorization here uses Bearer tokens only.

## 4. Present, step up, and refresh

Before an MCP request, build the header from the same authorization context and
token set:

```elixir
{:ok, {"authorization", value}} =
  AttestoClient.MCPAuthorization.authorization_header(authorization, tokens)
```

This refuses a token set bound to another issuer or resource and always emits
the registered `Bearer` spelling.

When the resource returns a Bearer `insufficient_scope` challenge, union its
scope with every scope previously requested and run authorization again:

```elixir
{:ok, authorization} =
  AttestoClient.MCPAuthorization.step_up(
    authorization,
    response_headers["www-authenticate"]
  )
```

The default limit is two step-up attempts. A challenge without both
`error="insufficient_scope"` and a valid non-empty scope is not retried.

Refresh uses plain OAuth mode, repeats the protected resource, and verifies
the token set and registration bindings before sending anything:

```elixir
{:ok, result} =
  AttestoClient.MCPAuthorization.refresh(
    authorization,
    registration,
    MyApp.MCPRefreshes,
    {:mcp_grant, account_id, authorization.resource},
    tokens,
    []
  )

persist_token_set(result.tokens)
```

## Authorization-server migration

Rediscover after a new challenge. If protected-resource metadata selects a
different issuer, pass the old registration to `select_registration/2`.
Issuer-bound credentials are never reused. A CIMD client is revalidated and
used only if the new server advertises CIMD support; a dynamic client is
registered again when dynamic registration remains enabled. With no valid
choice, the result is `:authorization_server_changed` rather than a credential
being sent to the new issuer.

Persist registrations under the exact issuer and token sets under both exact
issuer and protected resource. Replace them atomically only after the new
authorization succeeds.

## Loopback development

Production resources and issuers require HTTPS. For a native development
server on loopback only, pass:

```elixir
outbound: [allow_loopback_http: true]
```

The resource, challenge-selected metadata pointer, and issuer must each be
loopback. This exception does not permit a challenge to select an arbitrary
private network address.
