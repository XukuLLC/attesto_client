# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.19.0] - 2026-11-13

Requires Attesto >= 2.19.0 (was >= 2.15.0).

- Update the published dependency lock, CI checks, and installation examples;
  remove older-core capability fallbacks and run all wallet tests against the
  supported core.

## [2.18.0] - 2026-11-12

### Changed

- **Breaking:** ID Token, signed UserInfo, and signed introspection verification
  read the clock after key retrieval and signature verification. Tokens that
  expire during a slow key fetch are now refused, including an ID Token that
  triggers an issuer-cache refresh (RFC 7519 §4.1.4). JARM and resource-server
  verification also read the clock immediately before their time checks.
- **Breaking for `require_auth_time: true` only:** zero or negative integer
  `auth_time` returns `:auth_time_required`, including when `:max_age` is set.
  Other invalid values and future times remain refused. This is a local
  requirement for the option, not a restriction imposed by OIDC Core §2.
- ID Token `typ` accepts `application/jwt` as well as `JWT`, case-insensitively,
  using Attesto's media-type comparison (RFC 7515 §4.1.9). Other JWT types
  remain refused.
- **Breaking:** a malformed explicit `:now` on ID Token verification returns
  `:invalid_time` instead of silently using the system clock. Its existing
  `DateTime` form remains supported. A non-boolean `:require_auth_time` is also
  refused when `:max_age` is supplied, as it already was without `:max_age`.
- Resolve the development dependency lock to published Attesto 2.17.0.
- **Breaking:** concurrent refresh callers with different ID Token verification
  options re-verify the shared token under their own options instead of
  inheriting the first caller's checks. The refresh request still runs once
  (OIDC Core §3.1.3.7; RFC 7519 §4.1.4).

### Added

- `AuthorizationCode.callback/3` and `Token.refresh/4` accept `:now` as integer
  Unix seconds or a zero-arity function returning them. ID Token verification
  accepts the function too and reads it after signature verification. Callback
  transaction deadlines and DPoP proof times use the supplied clock; store TTLs
  and network deadlines still measure elapsed time. Invalid options and clock
  results are refused. These are clock-injection APIs, not new protocol rules.
- `AuthorizationCode.start/2` accepts `require_response_issuer: true`. It
  requires metadata to advertise `authorization_response_iss_parameter_supported:
  true` before storing a transaction or sending authorization, otherwise
  returning `:response_issuer_not_supported`. The retained requirement refuses
  callbacks without `iss` as `:missing_response_issuer` (RFC 9207 §2.4, §3).
  The default is `false`; advertised support already requires `iss` without
  this option. A malformed option is `:invalid_require_response_issuer`.
- `IDToken.verify/2`, `AuthorizationCode.callback/3`, and `Token.refresh/4`
  accept `require_typ: true` to refuse an absent JOSE `typ` as `:unexpected_typ`.
  The option defaults to `false`; a malformed value is `:invalid_require_typ`.
  RFC 7519 §5.1 makes `typ` optional. Requiring generic JWT typing does not
  distinguish every JWT purpose (RFC 8725 §3.11).

## [2.17.0] - 2026-11-12

### Changed

- Require Attesto `>= 2.15.0 and < 3.0.0` and update the published dependency
  and CI core reference to 2.15.0.
- Delegate X.509 certificate path validation to `Attesto.X509`, retaining
  `AttestoClient.Wallet.Presentation.CertificateTrust.verify/2` and
  `decode_x5c/1` as documented compatibility functions. Validation behavior
  and the existing contract tests are unchanged (RFC 5280 §6).
- Decode wallet CBOR through `Attesto.StrictCBOR`. Repeated map keys are
  refused in credential envelopes, COSE headers, presentation responses,
  and embedded issuer-signed items, including nested maps (RFC 9052 §3;
  RFC 8949 §5.6). Existing byte limits and error atoms are retained; core's
  default nesting limit of 32 also applies. Invalid embedded items return
  `:invalid_credential` even when claim selection would omit them.

## [2.16.0] - 2026-11-12

Requires Attesto `>= 2.14.0 and < 3.0.0`. Attesto 2.14.0 has the CIDR
allowance in its outbound screen, the loopback-only `http` form of the
identifier check, and the stricter host rule used below.

### Changed

- An issuer or endpoint URL whose host contains a percent-encoded character
  (`https://auth.test%20evil/`) or an empty label (`https://auth.test../`) is
  refused everywhere this package checks one: `:invalid_issuer`,
  `:invalid_endpoint`, `:invalid_jwks_uri` or `:blocked_host`, by call. No
  valid issuer metadata contains such a host (RFC 3986 §3.2.2). The rule is
  Attesto's `Attesto.URI.valid_host?/1`. An upper-case scheme (`HTTPS://`) is
  still accepted, since schemes are case-insensitive (RFC 3986 §3.1), and one
  trailing dot (`https://auth.test./`) is still the fully qualified form of
  the name.

- `AttestoClient.IDToken.verify/2` rejects an ID Token whose `aud` names any
  audience other than this client, with `{:error, :untrusted_audience}`. OIDC
  Core §3.1.3.7 item 3 says the ID Token MUST be rejected if it "contains
  additional audiences not trusted by the Client". Until now an `aud` array was
  accepted as long as it contained the client and `azp` named it, whatever
  else it listed. The new `:trusted_audiences` option lists the additional
  audiences the client trusts and is empty by default.
  `AttestoClient.AuthorizationCode.callback/3` and
  `AttestoClient.Token.refresh/4` take the same option and apply it to the ID
  Token they verify. The `azp` rules are unchanged.

  Behaviour change: a provider that puts another party in the ID Token's `aud`
  next to the client (an API identifier, for example) now fails sign-in and
  refresh until that value is listed in `:trusted_audiences`. A malformed
  option is `{:error, :invalid_trusted_audiences}`.
- `AttestoClient.Logout.url/1` no longer requires `:id_token_hint` or
  `:logout_hint`, and no longer returns `{:error, :missing_logout_hint}`.
  RP-Initiated Logout 1.0 §2 makes every request parameter optional. With no
  hint the result is the validated `end_session_endpoint` with whatever
  parameters were given, so a relying party that no longer holds the ID Token
  gets the checked URL without rebuilding it.
- `AttestoClient.Logout.url/1` returns `{:error, :missing_client_id}` for a
  `:post_logout_redirect_uri` sent with neither `:id_token_hint` nor
  `:client_id`. Without one of them the provider has no client to validate
  the redirect against (§2, §3). This combination with only `:logout_hint`
  used to produce a URL.
- `AttestoClient.Logout.url/1` refuses provider metadata whose authorization,
  pushed-authorization or token endpoint carries a protocol parameter in its
  own query, as `AttestoClient.AuthorizationCode.start/2` already did. The two
  now share one document check.

### Added

- `:outbound` names deliberate exceptions to the rules applied to every
  address this package connects to. `AttestoClient.AuthorizationCode.start/2`,
  `callback/3` and `exchange/2`, `AttestoClient.IDToken.verify/2`,
  `AttestoClient.Token.refresh/4`, `AttestoClient.Logout.url/1`, the
  `AttestoClient.Discovery` functions, `AttestoClient.Issuer` and
  `AttestoClient.ResourceServer` take it; `AttestoClient.Outbound` documents
  it. A malformed value is `{:error, :invalid_outbound}` (an `ArgumentError`
  when starting a cache).
  - `outbound: [allowed_cidrs: ["10.20.0.0/16"]]` lets the issuer's hosts
    resolve into the listed non-public networks, for an identity provider
    reachable only at a private address. Until now such an issuer failed with
    `:blocked_host`. Every resolved address must be public or inside a listed
    block, `https` is still required, and there is no host-name form. The rule
    is `Attesto.OutboundTarget`'s. This is an SSRF exception the operator
    takes on deliberately: the issuer's metadata can then direct this
    package's requests, including the token request, at any host in those
    networks.
  - `outbound: [allow_loopback_http: true]` accepts `http` for an issuer, and
    for the endpoints in its metadata, whose host is `localhost` or a literal
    loopback address, for development against a local identity provider. Every
    other host still needs `https`. The option is refused when the issuer is
    not a loopback host.

  The option is not stored in an authorization transaction or a token set.
  `callback/3` and `refresh/4` apply only what they are passed, so nothing a
  transaction carries can widen what a later call connects to.

  The other calls that connect to an issuer, or to an endpoint the caller
  chose from its metadata, take it too and check it before connecting:
  `AttestoClient.UserInfo.verify/2`,
  `AttestoClient.SignedIntrospection.verify/2`,
  `AttestoClient.Token.exchange_pre_authorized_code/2` and `revoke/2`,
  `AttestoClient.WalletAttestation.fetch_challenge/2` and
  `AttestoClient.Wallet.request_credential/3`.

  Calls whose address is written by another party refuse it with
  `{:error, :outbound_not_supported}`:
  `AttestoClient.Wallet.CredentialOffer.fetch/2`,
  `AttestoClient.Wallet.PresentationRequest.fetch/3` and `from_uri/3`, and
  `AttestoClient.Wallet.Presentation.submit/3` and `present/3`. A credential
  offer link or a verifier's request names those addresses, so an allowance
  there would let whoever wrote the link direct a request into the listed
  networks.
- `AttestoClient.Issuer` and `AttestoClient.ResourceServer` take `:resolver`,
  the two-argument host resolver `AttestoClient.Discovery` already takes. It
  is used for every metadata and JWKS fetch the cache makes, including a
  refresh on an unknown `kid`. Until now a cache always used the system
  resolver. A value that is not a two-argument function raises
  `ArgumentError` at start.
- `AttestoClient.Discovery.validate_metadata/3` checks an authorization-server
  metadata document for an issuer and returns `{:ok, document}` or the error
  `AttestoClient.AuthorizationCode.start/2` would give for its content.
  `protocol: :oidc` (the default) validates OpenID Provider metadata;
  `protocol: :oauth` validates RFC 8414 metadata. It is the function `start/2`
  calls, so a document accepted here is not refused there for its content.
- `AttestoClient.Issuer` takes `:protocol` (`:oidc` or `:oauth`). With it,
  every refresh runs that check, and a document `start/2` would refuse is a
  refresh failure that never becomes a snapshot; a previously cached document
  stays in place. Without it the cache checks only the issuer and `jwks_uri`,
  as before, which is what a resource server's cache needs.

## [2.15.0] - 2026-11-11

### Added

- `AttestoClient.Issuer`, a supervised cache of one issuer's discovery
  metadata and JWKS. Until now only `AttestoClient.ResourceServer` cached
  them, so `AttestoClient.IDToken.verify/2` fetched the discovery document
  and the key set on every call that was not handed a `:jwks`. The cache has
  the fresh and stale intervals, the retry cooldown, and the single
  coordinated refresh on an unknown `kid` (RFC 7517 key rotation) that
  `ResourceServer` already had. `issuer/1`, `metadata/1`, `keys/1`, `warm/1`,
  `ready?/1`, and `refresh/1` read and drive it.
- `issuer: {AttestoClient.Issuer, name}` on `AttestoClient.IDToken.verify/2`,
  `AttestoClient.AuthorizationCode.start/2` and `callback/3`, and
  `AttestoClient.Token.refresh/4`. The issuer identifier compared with the ID
  Token's `iss` and the RFC 9207 response `iss` is the one the cache was
  started with. `start/2` takes the discovery metadata from the cache;
  `callback/3` and `refresh/4` take the ID Token's keys from it, and a
  caller-supplied `:jwks` still takes precedence. `callback/3` returns
  `{:error, :issuer_mismatch}` for a cache whose issuer is not the
  transaction's. A cache that is not running returns
  `{:error, {:jwks_refresh_failed, :server_not_running}}`. A plain issuer
  string behaves as before.

- `AttestoClient.IDToken.verify/2` accepts `:max_token_age_seconds`, which
  rejects an ID Token whose `iat` is older than that many seconds plus
  `:clock_skew_seconds` with `{:error, :token_too_old}` (OIDC Core §3.1.3.7
  item 10). It is the option `AttestoClient.ResourceServer` already takes, and
  both now run the same rule. A value that is not a non-negative integer is
  `{:error, :invalid_max_token_age_seconds}`.
- `AttestoClient.IDToken.verify/2` accepts `require_auth_time: true`, which
  requires the `auth_time` claim even when no `:max_age` is given (§3.1.3.7
  item 13) and returns `{:error, :auth_time_required}` without it.
  `AttestoClient.AuthorizationCode.callback/3` and
  `AttestoClient.Token.refresh/4` accept both options and apply them to the
  ID Token they verify.
- `AttestoClient.AuthorizationCode.start/2` accepts `:return` in place of a
  store. Nothing is stored; the result carries the transaction under
  `:transaction` for the application to keep, and `callback/3` takes it back
  as `transaction:`. The response's `state` must equal the transaction's, and
  every other callback check runs as it does for a stored transaction. The
  application then owns two things a store provided. It must encrypt the
  transaction before it leaves the server, because it holds the PKCE
  verifier. It must also make the transaction single use, because
  `callback/3` accepts a returned transaction again until it expires.
- `AttestoClient.AuthorizationTransaction` has an `:expires_at` field, the
  transaction's deadline in Unix milliseconds. `callback/3` refuses a
  transaction past it with `{:error, {:invalid_state, :expired}}`, whether it
  came from a store or from the caller. A transaction stored by an earlier
  version has no deadline of its own and relies on its store's lifetime, as
  before.
- `AttestoClient.AuthorizationCode.exchange/2` performs the authorization-code
  token request on its own (RFC 6749 §4.1.3, RFC 7636 §4.5): code,
  `redirect_uri`, `code_verifier`, client authentication, and DPoP when a key
  is given. It returns the validated token response as an
  `AttestoClient.TokenSet`. It is the request `callback/3` makes, for an
  application that ran the authorization request itself; such an application
  still has to check `state` and verify a returned ID Token.

### Fixed

- Work run under the package's request deadline now carries `$callers` and
  `$ancestors` leading back to the calling process, as `Task` does. The work
  runs in a separate process so it can be stopped at the deadline, and until
  now that process named no caller. `Req.Test` stubs, Ecto sandbox allowances
  and other ownership that follows `$callers` did not reach token, PAR,
  discovery or JWKS requests made through it.

### Changed

- `AttestoClient.ResourceServer` is built on `AttestoClient.Issuer`, so there
  is one cache and one refresh logic. Its options, defaults, results, and
  error values are unchanged. The process it starts is an
  `AttestoClient.Issuer` process: its name can be passed as
  `issuer: {AttestoClient.Issuer, name}` to verify ID Tokens from the same
  issuer against the same keys. A `ResourceServer` process started by an
  earlier version does not survive a hot code upgrade to this one, because
  its callback module changed; its supervisor restarts it with an empty cache.

- `:issuer_aliases` on `AttestoClient.IDToken.verify/2`,
  `AttestoClient.AuthorizationCode.start/2`, and `AttestoClient.Token.refresh`:
  a list of extra exact strings accepted as the ID Token's `iss`. It is an
  opt-in interop workaround that deviates from OIDC Core §3.1.3.7 item 2,
  which says the issuer identifier "MUST exactly match" the `iss` claim. Some
  providers break that rule. Google issues ID Tokens with both
  `https://accounts.google.com` and `accounts.google.com`, and the second is
  not a valid issuer identifier because it has no `https` scheme. The list is
  empty by default, so `iss` is still compared exactly unless a caller opts
  in. Discovery, the JWKS, and the RFC 9207 authorization-response `iss` check
  stay pinned to `:issuer`. `start/2` pins the aliases in the transaction; a
  token set does not retain them, so pass them again to `Token.refresh`.
- `:expiry_leeway_seconds` on `AttestoClient.IDToken.verify/2`,
  `AttestoClient.AuthorizationCode.callback/3`, `AttestoClient.Token.refresh`,
  and `AttestoClient.ResourceServer`: how long past `exp` a token is still
  accepted (RFC 7519 §4.1.4). An integer from 0 to 300. It defaults to 0, so
  an expired token is still rejected at `exp` unless a caller sets it.
- `:clock_skew_seconds` on `AttestoClient.IDToken.verify/2`,
  `AttestoClient.AuthorizationCode.callback/3`, and
  `AttestoClient.Token.refresh`: how far in the future an ID Token's `iat`,
  `nbf`, and `auth_time` may lie. An integer from 0 to 300, default 60, the
  value that was fixed before. It has the meaning the option of the same name
  already has on `AttestoClient.ResourceServer`: it bounds future-dated
  claims and does not extend `exp`.

## [2.14.0] - 2026-11-09

### Security

- Require Attesto `>= 2.12.0 and < 3.0.0`. Attesto 2.12.0 refuses a JWK Set
  where one JWK is expected. Earlier releases accepted such a value as a key
  in DPoP proofs, credentials and trusted key material, and computing the
  thumbprint of a set did not return.
- `AttestoClient.Wallet.PresentationRequest.from_uri/3` replaced a
  caller-supplied `:client_id` with the unauthenticated `client_id` from the
  deep link. A verifier whose keys the caller passed as trusted could sign a
  request naming another verifier's `client_id`; the request verified as that
  other verifier, so the presentation's audience and nonce were bound to it and
  the response went to the signer's `response_uri`. A caller `:client_id` that
  differs from the deep link's now returns `{:error, :invalid_client_id}` before
  any `request_uri` is fetched. Without a caller `:client_id`, the deep link's
  value is still bound to the signed request.
- An SD-JWT presentation numbered array positions over the issuer's raw array,
  counting decoy digests and other placeholders the credential holds no
  Disclosure for, while DCQL matching and the held claims shown for consent
  number the reconstructed array, where those placeholders are absent. A
  claims path with an array index then disclosed a different element from the
  one selected. Array indexes are now counted over the reconstructed array.
- Outbound requests to DNS-screened addresses started one Finch instance under
  Req per distinct hostname, because the TLS hostname was part of the
  connection options Req keys its pools on, and Req never stops those
  instances. Each hostname left about 8 processes, 9 atoms and 0.45 MB behind
  for the life of the VM. Hostnames come from untrusted inputs such as
  `request_uri`, `credential_offer_uri`, `WWW-Authenticate` `resource_metadata`
  and `jwks_uri`, so a wildcard DNS zone could exhaust memory and then the atom
  table. Screened requests now open one Mint connection to the checked address
  and close it when the response completes. Connections are no longer reused
  across requests, and Finch pool options such as `:pool_timeout` have no
  effect on them.
- `AttestoClient.ResourceServer` applied `refresh_retry_interval` only after
  its first successful key refresh. While the issuer failed before then, every
  `verify/3` call started its own discovery and JWKS fetch and waited for it,
  so each unauthenticated request cost an outbound request. A failure before
  the first snapshot now starts the same cooldown: `verify/3` returns the
  remembered `{:error, {:jwks_refresh_failed, reason}}` until it ends.
  `warm/1` and `refresh/1` still fetch.

### Fixed

- An SD-JWT presentation for a DCQL claims path with a `null` (all elements)
  component, such as `["degrees", null, "type"]`, left out the Disclosures of
  the selectively disclosable array elements the selected claims sit in.
  `select/2` reported a match, but the verifier rejected the presentation with
  `:unused_disclosure`, or saw an empty array when the elements were disclosed
  whole. Those element Disclosures are now kept.
- `AttestoClient.Wallet.request_credential/3` returned
  `{:error, {:notification, reason}}` when the OID4VCI Notification POST failed
  after the credentials had been issued and verified, discarding them. A
  pre-authorized code is single-use, so the wallet could not request them
  again. The result now carries the credentials, and the failure reason in a
  new `:notification_error` field, which is `nil` when the Notification
  succeeded or was not sent. `{:error, {:notification, reason}}` is no longer
  returned.

## [2.13.1] - 2026-11-05

### Security

- Refuse a present JSON `null` where an omitted member places no restriction:
  - DCQL `trusted_authorities`, `meta.doctype_value`, and `meta.vct_values` in
    `AttestoClient.Wallet.Presentation.select/2`, which now return
    `:invalid_dcql_query` instead of treating the null as unrestricted and
    widening which held credentials match. `doctype_value` must be a non-empty
    string and `vct_values` a non-empty list of non-empty strings when present.
  - A recipient encryption key's `use` and `key_ops`, which now make the key
    unusable instead of reading as omitted.

- Require Attesto `>= 2.11.0 and < 3.0.0`. `AttestoClient.ResourceServer`
  checks sender constraints through `Attesto.Token.check_confirmation/2`, which
  in earlier Attesto releases accepted a `"cnf": null` access token as an
  unbound bearer token under the Jason or Poison JOSE backend.

### Changed

- Verified claims carry JSON `null` as `nil` whichever JSON backend JOSE uses,
  following Attesto 2.11.0. Under JOSE's builtin OTP backend they previously
  carried `:null`.

## [2.13.0] - 2026-10-31

### Changed

- `AttestoClient.Wallet` builds the `mso_mdoc` session transcript and
  `DeviceAuthentication` bytes with `Attesto.Mdoc`, decodes SD-JWT
  Disclosures with `Attesto.SdJwt.decode_disclosures/2`, and checks DCQL claim
  paths with `Attesto.PresentationRequest.claim_path?/2`, so the Wallet applies
  the same rules as the Verifier. A held SD-JWT whose Disclosures name a
  reserved claim, repeat a digest, or carry a non-string salt or name is now
  refused before presentation, and a DCQL path element may be any string.
- An `mso_mdoc` presentation given an unusable `:response_encryption_jwk`
  returns `{:error, :invalid_key}`; it leaked `:malformed_jwk` before.
- Credential request encryption chooses a key only if it is a P-256 point on
  the curve with 32-byte coordinates and no private members, the rule OID4VP
  response encryption already applied. Such a key was selected before and
  failed later at encryption.
- Require Attesto `>= 2.9.0 and < 3.0.0` for those functions.

## [2.12.0] - 2026-10-31

### Changed

- `AttestoClient.ResourceServer.Plug` now delegates bearer, DPoP, and mTLS
  request authentication, challenge formatting, and scope enforcement to
  `Attesto.Plug.Authenticate`, and `AttestoClient.ResourceServer` delegates
  `cnf` sender-constraint checks to `Attesto.Token.check_confirmation/2` while
  preserving the client's documented challenges, status codes, and error atoms.
- `AttestoClient.Discovery` delegates outbound endpoint URL validation, DNS
  resolution, and public-IP screening to `Attesto.OutboundTarget.screen/2`, and
  the client's internal strict JSON decoder delegates duplicate-key and
  depth-bounded decoding to `Attesto.StrictJSON.decode/1`.
- Require Attesto `>= 2.8.0 and < 3.0.0` in the 2.x line for the shared
  `Attesto.OutboundTarget`, `Attesto.StrictJSON`, `Attesto.Plug.Authenticate`,
  and `Attesto.Token.check_confirmation/2` APIs.

## [2.11.1] - 2026-10-27

### Security

- Require JOSE 1.11.13 or later, which fixes CVE-2026-65625 through
  CVE-2026-65632. With earlier JOSE releases, ID token and request-object
  verification accepted ECDSA signatures padded with leading zero bytes.
  AttestoClient decrypts no JWEs, and wallet response encryption already
  accepted only a public P-256 verifier key.

## [2.11.0] - 2026-10-19

### Added

- `AttestoClient.Discovery.fetch_resource/2` reads a protected resource's
  RFC 9728 metadata, from the well-known location derived from its identifier
  or from the URL a `WWW-Authenticate` challenge advertised, and refuses a
  document whose `resource` differs from the identifier it was requested for.
  Advertised authorization servers must be valid issuer identifiers and
  `jwks_uri` must be `https`.
- `AttestoClient.Discovery.authorization_server/2` follows that document to
  the issuer's own metadata: it selects the single advertised authorization
  server or the `:issuer` chosen among several, tries the RFC 8414 document
  before the OpenID Connect one, and returns both documents with the issuer.
- `AttestoClient.WWWAuthenticate` parses `WWW-Authenticate` challenges
  (RFC 9110 §11.6.1), several per field, and reads the RFC 9728
  `resource_metadata` pointer. The DPoP nonce retry now reads challenges
  through it.
- `AttestoClient.AuthorizationCode.start/2` takes `:resource`, one or more
  RFC 8707 resource indicators. Each is sent as a `resource` parameter on the
  authorization request or the pushed request, pinned in the transaction, and
  repeated on the token request; `callback/3` takes `:resource` to narrow the
  token request to a subset of the pinned indicators. A malformed indicator,
  or one outside the pinned set, is `{:error, :invalid_resource}`.

### Changed

- A `"resource"` entry in `:authorization_params` is read as the `:resource`
  option: it is validated as an RFC 8707 indicator, pinned, and repeated on the
  token request, which previously never carried it. Supplying both is
  `{:error, :invalid_authorization_params}`.
- Form bodies are encoded from parameter pairs, so a repeated parameter such
  as `resource` is sent once per value.

## [2.10.0] - 2026-10-18

### Security

- Bind every returned SD-JWT VC and JWT VC issuer claim to the Credential
  Issuer Identifier from the accepted offer. Certificate-backed credentials
  may still omit `iss` where the profiled credential format permits it.
- Evict the oldest live authorization transaction when the bounded ETS store
  reaches capacity, with telemetry for operators, so unauthenticated login
  starts cannot leave the store refusing every new login until expiry.
- Apply the JWKS refresh retry cooldown to hard validation and HTTP failures as
  well as transient outages. Hard failures remain fail-closed and no longer
  make every token verification repeat the same upstream fetch.
- Route all client JWT verification through Attesto's strict protected-header,
  candidate-selection, and signature-verification boundaries while preserving
  ambiguous-key rejection and the 2048-bit RSA minimum.
- Use Attesto's strict URI validator at every client endpoint boundary. This
  closes weaker userinfo, fragment, malformed-percent, and hostless cases in
  key-attestation and wallet presentation paths.
- Reject duplicate JSON object members in discovery metadata, JWKS documents,
  credential offers, and credential responses before protocol validation.

- Bound OpenID4VP request objects to 64 KiB before reading their unverified
  claims, matching Attesto core's Request Object limit.

### Changed

- Require Attesto 2.6.0 or later in the 2.x line for the shared JWS candidate,
  NumericDate, claim, URI, JWE, and secret-generation boundaries.
- Consolidate registered-claim validation without changing each protocol's
  established missing, malformed, expiry, and future-time error results.
- Split OAuth client authentication and challenge parsing from the HTTP
  transport, centralize bounded response collection and option validation,
  and remove nested request deadlines and repeat DPoP signing probes.
- Call `Attesto.JWE` directly internally now that every supported core version
  provides the bounded implementation. The deprecated
  `AttestoClient.CryptoJWE` compatibility wrapper remains available
  throughout the 2.x line.
- Retain the public `AttestoClient.OpenIDMetadata.validate/2`
  validation entry point, the hidden DCQL matching/path helpers, and the
  `AttestoClient.Verifier.compact_segments/0` remote type throughout
  the 2.x line.

## [2.9.0] - 2026-10-17

### Security

- Defer DPoP replay-cache claims in the resource-server Plug until after the
  access-token signature and `cnf.jkt` binding verify. An unauthenticated proof
  can no longer reserve replay identifiers or grow the replay store before its
  token establishes the caller's identity.
- Route local JWT verification through Attesto's shared strict verifier so
  client-side verification applies the same canonical parsing, candidate
  filtering, malformed-result handling, and exact RSA-PSS salt and MGF1 checks
  as core protocol verifiers.
- Build DPoP proofs through `Attesto.DPoP.Proof`, which requires HTTPS targets,
  rejects userinfo and malformed percent escapes, and preserves key-declared
  algorithms and identifiers. Resource metadata challenge URLs now use the
  same strict URI policy.
- Use Attesto's IANA-registry-based public destination policy for discovery and
  JWKS fetches. Non-global and special-use destinations remain blocked across
  IPv4, IPv6, mapped, compatible, NAT64, and 6to4 forms, while the registries'
  applicable globally reachable exceptions remain available. ORCHIDv2 and
  Drone Remote ID non-locator identifiers remain blocked from fetches.

### Changed

- Require Attesto 2.5.0 or later in the 2.x line. `AttestoClient.DPoP` now
  delegates proof building and algorithm resolution to the core implementation,
  and discovery delegates destination classification to
  `Attesto.IPAddress.public_fetch_destination?/1`.

## [2.8.0] - 2026-10-15

### Security

- Send OID4VCI Nonce Endpoint requests through the unauthenticated open-POST
  path. In split Credential Issuer and Authorization Server deployments this
  prevents forwarding the AS client secret, private-key assertion, client
  attestation, or DPoP proof to the Credential Issuer; endpoint screening,
  pinning, response bounds, and the overall deadline still apply.
- Reject malformed or duplicate `req_options` before network I/O with
  `:unsafe_transport_options`, including nested connection and transport
  options used by unauthenticated by-reference requests.
- Reject private JWK members in verification keys and reject empty, malformed,
  or struct-backed JWKS inputs. A malformed candidate no longer prevents a
  separate valid public verification key from being selected.
- Validate optional `nbf` claims in JARM, signed UserInfo, signed introspection,
  and resource-server tokens, and compare registered JWT `typ` values
  case-insensitively where required.
- Validate wallet and attestation inputs before signing or network I/O,
  including duplicate holder keys, malformed optional claims, protected-header
  values, grant objects, credential issuer identifiers, notification IDs, and
  symmetric keys. Key Attestation `certification` values are now limited to
  absolute HTTP(S) URLs.

### Added

- Support anonymous OID4VCI pre-authorized-code redemption when
  `client_auth: :none` by allowing `client_id` to be omitted. Authenticated
  client methods continue to require a non-empty client identifier.
- Propagate `:alg`, `:kid`, and `:now` through DPoP-enabled authorization-code,
  token, credential, refresh, and nonce-retry paths. Each retry receives a
  fresh `jti` while retaining the selected key algorithm and identifier.

### Changed

- Builders now honor a signing JWK's declared `alg` when `:alg` is omitted and
  return `:unsupported_alg` when an explicit algorithm conflicts with that
  declaration. This enables RSA DPoP keys declared for PS256 instead of
  silently forcing RS256.
- A present `kid` must be a non-empty string. Explicit `kid: nil`, other
  malformed values, and malformed embedded JWK `kid` members now return
  `:invalid_kid` instead of falling back to another identifier.
- `Token.revoke/2` now requires `:client_id`. `Verifier.normalize_jwks/1`
  returns `:invalid_jwks` for empty key sets, and protected algorithms outside
  the accepted set return `:unsupported_alg` instead of `:invalid_signature`.
- An explicit OID4VCI `credential_configuration_id` must be present in the
  credential offer; a mismatch fails before metadata lookup or HTTP.
- Stop requiring every OpenID Provider metadata document to advertise RS256.
  The selected ID Token algorithm must still be advertised, allowing clients
  configured for ES256, EdDSA, or another accepted algorithm to use providers
  that intentionally omit RS256.

### Fixed

- Preserve callback JWKS resolver, timeout, and response-size options while
  using the transaction's pinned issuer metadata.
- Parse every `WWW-Authenticate` field and combined challenge, recognize the
  DPoP scheme case-insensitively, and retry only for an exact
  `error=use_dpop_nonce` parameter.
- Derive canonical DPoP target URIs for IPv6 authorities and carry RSA PS256,
  explicit `kid`, deterministic time, and nonce options through DPoP retries.
- Compute SD-JWT Key Binding `sd_hash` with the issuer-selected `_sd_alg`,
  restoring SHA-384 and SHA-512 interoperability with conforming verifiers.
- Validate and expose `notification_id` consistently for immediate and
  deferred credential responses, reject invalid credential-offer grant values,
  and reject duplicate holder keys before issuing a request.
- Return controlled errors for malformed builder inputs and symmetric
  attestation or holder keys instead of backend exceptions.

## [2.7.0] - 2026-10-08

### Fixed

- Retain the selected ID Token algorithm in `TokenSet` through authorization
  and successive refreshes, including responses without an ID Token. FAPI's
  default ES256 selection now refreshes without repeating `id_token_alg`.
  Reject conflicting explicit algorithms before HTTP and reject shared refresh
  results that do not match the caller's retained algorithm.

### Security

- Require Attesto 2.3.1 or later for exact JWA PSS verification and fail-closed
  algorithm policies, including mixed allowlists. Upgrade core and client together.
- Require authenticated PAR and token requests plus locally bound DPoP in
  HAIP/FAPI flows. Persist profile, client/issuer identity and authentication
  binding through callback and refresh; reject changed or omitted material.
  FAPI supports private-key JWT authentication here; unverified mTLS claims
  cannot substitute for a DPoP key.
- Reject unsolicited DPoP token responses when no local signing key exists,
  including pre-authorized, authorization-code and refresh exchanges.
- Require a bounded certificate chain in `x5c` for HAIP client-attestation
  authentication. Bind the stable client and instance-key identity while
  permitting renewed attestations at callback and refresh.
  Authorization servers remain responsible for attester signature and trust.
- Require the complete profile-bound `TokenSet` for externally supplied HAIP
  credential access tokens. Pass `access_token: tokens` with the retained
  DPoP key; a bare token string cannot establish the required binding.
- Reject reserved parameters, bracket aliases and duplicate roots in discovered
  authorization/PAR/token endpoint queries before performing HTTP requests.
- Require signed HAIP verifier metadata to advertise both A128GCM and A256GCM;
  retain this profile when building or submitting presentation responses.
- Require `digitalSignature` when a signing certificate declares KeyUsage.
  Reject RSA-PSS-constrained SubjectPublicKeyInfo throughout the selected
  certificate path, including the used trust anchor, until its algorithm
  restrictions can be preserved and enforced. Reject non-NULL
  `rsaEncryption` parameters; absent parameters remain accepted for
  interoperability. Additional ecosystem EKU and
  revocation checks remain application-owned.
- Reject empty, invalid and weak wallet algorithm allowlists. HAIP and
  explicitly selected FAPI policy cannot be weakened through caller options.
- Require a DPoP token response whenever pre-authorized issuance requests DPoP,
  before contacting nonce or credential endpoints. HAIP/FAPI authorization-code
  transactions require response `iss` even when discovery omits its support
  flag; the policy is pinned at start and cannot be weakened at callback.
- Preserve DPoP across refresh: require signing material before any network
  request, reject Bearer responses, and compare any locally retained binding
  thumbprint. Legacy manually constructed token sets lack historic key
  provenance and acquire a binding after a successful DPoP refresh.
- Require PAR in HAIP/FAPI authorization-code flows, reject contradictory
  options before discovery, and reject bracketed aliases of protected extra
  authorization/PAR parameters.
- Require verifier format metadata and enforce advertised issuer and holder
  algorithms during presentation generation and caller-built submission.
  Registered authoritative `verifier_metadata` overrides signed fields;
  certificate-bound requests require metadata in their signed request.
- Strip caller cookies, authentication, custom headers and routing options
  from unauthenticated by-reference request and credential-offer fetching.
- Enforce OID4VP request typing, required response mode, URL-safe nonce/state,
  unique nonempty bounded encryption-key IDs, and aggregate response bounds.
  Request URI responses require the request-object media type. Presentation
  response endpoints must return HTTP 200 and a JSON object with the JSON
  media type; malformed or duplicate JSON is rejected.

### Added

- Add plain OAuth authorization-code transactions with S256 PKCE using
  `protocol: :oauth`, RFC 8414 discovery, and no ID Token requirement. Keep
  issuer, browser-session, and one-time state checks; pin the selected protocol
  and any initiating DPoP key in the transaction.
- Support Pushed Authorization Requests with client authentication and DPoP.
  Honor servers requiring PAR, reject explicit downgrades, and remove stored
  transactions when PAR fails or state expires during the operation. Require
  HTTP 201 and cap the returned redirect lifetime to the remaining state and
  PAR lifetimes. Authorization redirects carry only the client identifier and
  returned request URI.
- Add encrypted OID4VCI credential exchanges, bounded deferred issuance
  polling, and encrypted OID4VP `direct_post.jwt` responses. These encrypted
  wallet features require Attesto 2.3.1 or later.
- Verify HAIP `x509_hash` presentation requests against explicit DER
  certificate anchors, bind outer client identities and POST wallet nonces,
  and use the response encryption key in the mdoc session transcript.
- Add opt-in `haip: true` issuer-chain verification for SD-JWT VC and mdoc
  credentials using explicit `trusted_certificates`. Verify credentials with
  the validated leaf key and attach only verified issuer-chain provenance.
  Recognize the critical mdoc document-signer usage only for mdoc issuer
  certificates; retain rejection of unknown critical extensions.
  Fixed-key trust remains the default. Status and revocation policy remain
  application-owned.
- Reject undersized PS256 issuer keys in HAIP issuance and accept a missing
  SD-JWT issuer claim only after verifying certificate identity with Attesto
  2.3.1 or later.
- Evaluate DCQL nested paths, claim alternatives, credential sets and trusted
  authority constraints before disclosure; validate explicit selections too.
- Add a pure `Wallet.Presentation.build_response/3` for consent previews and
  application-owned transports, a progressive credential-wallet guide and an
  encrypted presentation example in the interactive Livebook.
- Allow Client Attestations to include the trusted attester's `issuer:` claim.
- Add `WalletAttestation.fetch_challenge/2` for proactive attestation
  challenges and preserve an optional DPoP nonce for subsequent PAR and token
  requests.

### Changed

- When a DCQL query omits `claims`, disclose only mandatory presentation
  contents, as required by final OID4VP §6.4.1. Selectively disclosable claims
  require an explicit query.
- Ignore `iss` in all signed presentation requests as required by final
  OID4VP; retain audience, client identity, signature and certificate checks.
- Parse encoded OAuth callbacks containing an issuer URL as form bodies,
  while retaining duplicate-parameter detection and callback URI checks.
- Reject bearer token responses when an authorization-code exchange requests
  DPoP, and reject a changed or omitted DPoP key when the transaction started
  with one.
- Bind the requested credential format and returned SD-JWT `vct` or mdoc
  document type to the selected configuration when Credential Issuer
  configuration metadata is supplied.
- Return `:unsupported_mdoc` when the optional CBOR dependency is absent,
  including before issuance makes network requests.
- Use nonempty presentation arrays in both final OID4VP response modes;
  scalar plaintext inputs are rejected. Deferred credential responses require
  HTTP 202 and a positive integer interval; reject duplicate response JSON,
  ambiguous encryption keys, and invalid batch holder bindings.
- Use advertised optional credential encryption under `credential_encryption:
  :auto`; unsupported or malformed advertisements fail closed. `:disabled`
  remains an explicit opt-out only when the issuer permits plaintext.

## [2.6.1] - 2026-10-04

### Security

- Bound compact JWS values and their protected/signature segments before
  splitting or decoding, require canonical Base64URL, and reject duplicate JSON
  members at every nesting depth before verifying signed claims.
- Accept an original callback URI or raw form body in the authorization-code
  client, bound the encoded input to 1,000,000 bytes, and reject repeated or
  percent-encoded alias parameter names before state is consumed. Map input
  remains available for integrations whose parser already enforces uniqueness.
- Bound encoded mdoc credentials before Base64URL decoding and normalize signing
  failures so exception text cannot expose private key material.
- Keep Attesto 1.x compatibility. Deploy with Attesto 2.2.2 or later in the 2.x
  line to include hardening of delegated core JOSE and credential verification.

## [2.6.0] - 2026-10-03

### Changed

- Default private-key client assertion audiences to the trusted authorization
  server issuer and emit `typ: client-authentication+jwt` for rfc7523bis-11.
  Pass `issuer: metadata["issuer"]` to select this profile. Calls without an
  issuer retain endpoint audiences in 2.x and emit deprecation telemetry.
  Assertion `typ:` can be overridden or omitted for a legacy server.
- Retry an attestation Challenge or DPoP nonce at most once each, generating
  fresh proofs and preserving both challenges when the server requires them.
- Validate and expose optional refresh-token expiration response durations.
- Forward DPoP and attestation Challenge callbacks during authorization-code
  redemption and document browser and cross-device deployment policies.
- Require patched Mint and refresh its development/test lock.
- Keep Hex dependency declarations during package tasks even when
  `ATTESTO_PATH` is inherited from a source-development shell.

## [2.5.0] - 2026-08-31

### Changed

- Support both Attesto 1.x and 2.x. Attesto 2.0 changes authorization-server
  storage contracts that AttestoClient does not implement; the protocol and
  verification APIs used by this package remain compatible.
- The published package dependency is `>= 1.13.0 and < 3.0.0`, so ordinary Hex
  resolution can select either supported Attesto major line. No AttestoClient
  application-code migration is required; source checkouts may opt into the
  coordinated Attesto 2 path with `ATTESTO_PATH=1`.

## [2.4.1] - 2026-08-27

### Security

- Carry the screened IP address through every OAuth, wallet, discovery, and
  JWKS request while retaining the external hostname for TLS verification,
  SNI, HTTP authority, DPoP `htu`, and client-assertion audiences. DPoP nonce
  retries reuse the same screened address. This closes the remaining DNS-
  rebinding interval in the shared OAuth HTTP path.
- Isolate protected requests from Req application defaults and caller options
  that can replace routing, credentials, protocol bodies, redirects, TLS peer
  identity, or the screened origin. Unsafe proxies and incompatible Finch
  pools now fail closed; URL-keyed Req caching is disabled because different
  HTTPS authorities can share a pinned IP and path.
- Keep metadata and JWKS retrieval unauthenticated, force discovery requests to
  use GET, remove hop-by-hop request headers, and include DNS resolution and
  request preparation within the caller's overall deadline. OAuth POST response
  bodies are now bounded before decoding as well as by-reference GET bodies.
- Refresh the IPv6 special-purpose address policy from IANA's registry,
  rejecting the dummy, deprecated protocol-assignment, and documentation
  ranges and all reserved space outside conventional global unicast, while
  retaining ordinary globally reachable allocations.

### Upgrade notes

- Protected network requests now reject caller-owned proxies, Finch pools,
  adapters, and Unix sockets because they can bypass the screened destination
  or its TLS identity. Applications that previously supplied one of those
  routing overrides will receive `{:error, :unsafe_transport_options}` and
  should move controlled egress routing outside the request process.

## [2.4.0] - 2026-08-11

### Security

- Pin discovery and JWKS connections to an address that was screened against
  special-use networks, while retaining TLS SNI, certificate verification, and
  the HTTP Host authority on the original hostname. This closes the DNS-
  rebinding interval between the prior pre-flight lookup and the socket connect.
  A host that resolves to no address is now rejected (`:blocked_host`) rather
  than handed to the transport — the screening path is fail-closed.
- Bound discovery and JWKS response bodies before JSON decoding and disable
  transparent response decompression on those trust-root fetches.
- Reject unsafe RSA modulus/exponent parameters from a remote JWKS before JOSE
  constructs bignums or attempts signature verification, preventing scheduler-
  pinning verification work.
- Require `attesto >= 1.13.0`, carrying the matching raw-key bounds and current
  parser, wallet, status-list, and ID-JAG hardening into every client installation.
- Make the ID-JAG builder enforce the server's signed-claim constraints before
  signing: a 256-byte `jti` cap, valid `scope` and `resource`, exactly one
  supported `cnf.jkt` member, and rejection of unsupported
  `authorization_details`.

## [2.3.1] - 2026-08-03

### Added

- Add an end-to-end **digital wallet Livebook** (`guides/digital_wallet.livemd`),
  now rendered in the docs. Issue an SD-JWT VC PID credential, hold it, and
  present it to a verifier with an interactive selective-disclosure form —
  request only `age_over_21` and watch name and birthdate stay in the wallet.
  Runs entirely on the published `attesto` + `attesto_client` libraries.

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
