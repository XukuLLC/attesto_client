# Credential wallet: from a local presentation to HAIP

AttestoClient implements the holder side of OpenID4VCI and OpenID4VP. It
requests and verifies credentials, evaluates presentation queries, creates
holder proofs and handles encrypted exchanges. Your application supplies the
user interface, consent, secure key storage, credential persistence and trust
policy. A protocol library does not establish that a key is hardware protected;
that assurance comes from your wallet provider and key-attestation issuer.

For the encrypted examples, use these dependencies:

```elixir
{:attesto, "~> 2.3"},
{:attesto_client, "~> 2.7"}
```

Add `{:cbor, "~> 1.0"}` when accepting or presenting `mso_mdoc` credentials.
Existing plaintext wallet operations retain support for older core releases.
The [wallet Livebook](digital_wallet.livemd) starts with a complete local
SD-JWT VC selective-disclosure example and then encrypts its response.

## 1. Present one verified credential

Keep each verified credential with its original encoded value, verified claims
and holder binding. For example, an SD-JWT VC received and verified by
`AttestoClient.Wallet` has the following fields:

```elixir
held = %{
  format: "dc+sd-jwt",
  credential: credential,
  claims: verified_claims,
  holder_binding: verified_claims["cnf"]
}
```

`credential`, `verified_claims` and `holder_key` in these examples come from a
completed issuance flow. Never treat unverified JWT claims as a held credential.

Verify the incoming presentation request before displaying the verifier or
requested claims. For a pre-registered verifier, pass its trusted verification
key material:

```elixir
{:ok, request} =
  AttestoClient.Wallet.PresentationRequest.from_uri(incoming_uri, verifier_jwks,
    client_id: verifier_client_id,
    audience: wallet_identifier,
    verifier_metadata: %{
      "vp_formats_supported" => %{
        "dc+sd-jwt" => %{
          "sd-jwt_alg_values" => ["ES256"],
          "kb-jwt_alg_values" => ["ES256"]
        }
      }
    }
  )

{:ok, proposed} =
  AttestoClient.Wallet.Presentation.select(request.dcql_query, [held])
```

`select/2` proposes a selection; it does not obtain consent or send anything.
For this pre-registered request, `verifier_client_id` and `wallet_identifier`
are the expected client identifier and audience established by your registration, not
values copied from an unverified request. HAIP uses the certificate-based
verification described below instead.
Pass `verifier_metadata` only from your trusted registration record. Its fields
override signed metadata. Otherwise the verified request must carry a nonempty
`client_metadata.vp_formats_supported` object. The wallet checks the selected
format and advertised issuer/holder algorithms before generation and submission.
Show the authenticated verifier, the credential format and the actual claims
that would be disclosed. After the user approves, build and submit the
selection with the keys corresponding to the DCQL query IDs:

```elixir
{:ok, vp_token} =
  AttestoClient.Wallet.Presentation.build_vp_token(proposed, request,
    holder_keys: %{"pid" => holder_key}
  )

{:ok, response} =
  AttestoClient.Wallet.Presentation.submit(request, vp_token)
```

The example assumes the selected query ID is `"pid"`. A selection for multiple
query IDs needs a holder key for each. Explicit selections are checked against
the DCQL constraints, including required credential sets and claim alternatives.
When a query omits `claims`, return only mandatory presentation contents,
without selectively disclosable claims. Claims embedded in the issuer's signed JWT
cannot be removed by selective disclosure.
An indivisible disclosure may itself contain several nested fields; show its
actual contents rather than assuming every disclosure contains only one
requested field.
Both response modes map each query ID to a nonempty presentation array.
For example, `vp_token["pid"]` is `[presentation]`, and the verified result from
`Attesto.VpToken.verify/2` is also a list. Scalar plaintext responses are rejected.

For a consent preview or a transport you own, call `build_response/3` instead
of `submit/3`. It returns the form body without network access. Do not log the
plaintext credentials or response body. If a successful response supplies a
`redirect_uri`, open it in the user's browser according to application policy;
do not fetch it from your backend.

## 2. Receive a credential offer and request issuance

Offers may be JSON, an `openid-credential-offer://` link containing an offer, or
a link containing an offer URI:

```elixir
offer_result = AttestoClient.Wallet.CredentialOffer.parse(incoming_offer)

{:ok, offer} =
  case offer_result do
    {:ok, offer} -> {:ok, offer}
    {:fetch, uri} -> AttestoClient.Wallet.CredentialOffer.fetch(uri)
    {:error, reason} -> {:error, reason}
  end
```

Fetch and validate Credential Issuer metadata against `offer.credential_issuer`.
Establish issuer trust separately; metadata or a remote JWKS alone is not a
trust decision. Select an advertised credential configuration and its format.
The following example uses a pre-authorized offer; supply `tx_code:` when the
offer requires a transaction code:

```elixir
{:ok, result} =
  AttestoClient.Wallet.request_credential(offer, holder_key,
    credential_issuer_metadata: validated_issuer_metadata,
    credential_configuration_id: "pid",
    token_endpoint: validated_as_metadata["token_endpoint"],
    client_id: wallet_client_id,
    client_auth: wallet_client_auth,
    format: "dc+sd-jwt",
    trusted: trusted_issuer_keys,
    dpop: dpop_key
  )
```

Endpoint options can be omitted when present in Credential Issuer metadata;
conflicting overrides fail. The token endpoint comes from the selected
authorization server's validated metadata. If an offer names an authorization
server, require it to belong to the Credential Issuer's advertised
`authorization_servers`. Keep exact issuer matching throughout discovery.
When metadata includes `credential_configurations_supported`, the wallet
checks the selected configuration and format before requesting issuance, then
checks the returned SD-JWT `vct` or mdoc document type against that
configuration. If you omit configuration metadata, your application must
check the expected credential type itself. In both cases, your trust policy
must authorize the issuer to issue that type of credential.

`result.credentials` contains verified held credentials, or pending markers
when deferred polling is disabled or no deferred endpoint is supplied. Store
successful credentials securely with the corresponding holder key. A batch
may contain fewer credentials than requested; each returned credential is
checked against the holder keys, and extra or duplicate key bindings fail.

## 3. Use authorization-code issuance with PAR and DPoP

For authorization-code offers, obtain the access token before calling
`Wallet.request_credential/3`. Use an atomic transaction store and an opaque
binding retained in the initiating browser's secure application session:

```elixir
{:ok, pid} = AttestoClient.AuthorizationTransaction.Store.ETS.start_link()
store = {AttestoClient.AuthorizationTransaction.Store.ETS, pid}

{:ok, started} =
  AttestoClient.AuthorizationCode.start(store,
    protocol: :oauth,
    haip: true,
    issuer: authorization_server,
    metadata: validated_as_metadata,
    client_id: wallet_client_id,
    redirect_uri: callback_uri,
    browser_binding: browser_binding,
    scopes: [credential_scope],
    authorization_params: offer_authorization_params,
    par: true,
    dpop: dpop_key,
    client_auth: wallet_client_auth
  )
```

Redirect the browser to `started.url`. `offer_authorization_params` may include
the offer's `issuer_state` and JSON-encoded `authorization_details` required by
the issuer. Choose these from the validated offer and metadata. The library
pins state, PKCE, client ID, redirect URI and the DPoP key; those parameters
cannot be overridden. PAR requires HTTP 201 and a usable response, and a failed
or expired start removes its stored transaction.

At the callback, pass the original URI or encoded form body so duplicate
parameter names remain detectable:

```elixir
{:ok, %{tokens: tokens, id_token_claims: nil}} =
  AttestoClient.AuthorizationCode.callback(store, original_callback,
    browser_binding: browser_binding,
    dpop: dpop_key,
    client_auth: wallet_client_auth
  )
```

Then supply `access_token: tokens` to the issuance example, with
the same DPoP key. Plain OAuth mode does not request an OIDC ID Token. The
protocol mode is retained in state; changing callback options cannot change it.
`haip: true` (or `fapi?: true` for another FAPI client) requires authenticated
PAR and token requests with DPoP. The transaction pins the profile, client and
authentication key or secret identity. Callback and refresh must retain the same
authentication method, identity and DPoP key. FAPI uses private-key JWT client
authentication; this API does not attest an mTLS transport binding. The profile pins
mandatory authorization-response `iss` checking, including when server metadata
omits its support flag. A missing PAR endpoint or `par: false` fails locally.
Both authorization-code and pre-authorized flows reject a Bearer
token response when DPoP was requested, before credential HTTP.
Their returned token sets retain a locally derived `dpop_jkt`; persist that
thumbprint and use the same private key for refresh.
State is single-use, including after a failed exchange. The default ETS store
is for one node; use your own atomic store for a distributed deployment.

## 4. Enable encryption and bounded deferred polling

`credential_encryption: :auto` uses the issuer's advertised encryption
capabilities. Set `:required` to require encrypted requests and responses.
`:disabled` fails when the issuer requires encryption. Supported suites are
ECDH-ES with P-256 and A128GCM or A256GCM. Request encryption is also required
when requesting an encrypted response. The wallet generates a fresh response
key unless you supply `credential_response_encryption_key:`; retain its private
part securely for the operation.

Deferred responses use HTTP 202 and a positive integer interval in seconds. With an
advertised deferred endpoint, polling defaults to ten attempts within 120
seconds. Customize `deferred_max_attempts:` and `deferred_timeout:` (milliseconds) for the
issuer's expected delay. Polling will not wait past its deadline, even when an
issuer returns a much longer interval. Set `deferred_poll: false` to return a
pending marker. This marker is informational: it contains no polling interval,
access token or generated encryption private key, and there is no public resume
API. Prefer automatic polling for a complete exchange. Durable continuation
requires an application-owned deferred transport and credential verification,
a separately retained access token and sender-constraining key, an explicitly
supplied response encryption key, and the issuer's polling timing.

## 5. Add the HAIP trust and attestation integration

HAIP presentation requests use `x509_hash` client identifiers and encrypted
`direct_post.jwt`. Resolve the incoming request using explicitly trusted DER
certificate anchors:

```elixir
{:ok, request} =
  AttestoClient.Wallet.PresentationRequest.from_uri(incoming_uri, nil,
    haip: true,
    trusted_certificates: [trusted_verifier_root_der]
  )
```

The embedded certificate chain must validate to an anchor; it cannot appoint
itself trusted. An optional `certificate_trust:` callback can impose additional
policy after chain validation. Choose anchors through your trust framework,
and plan how you distribute updates and apply certificate revocation policy.
Do not derive trusted-authority identifiers from an unverified `x5c` header.
The credential's `authority_key_identifiers`, when used to match a DCQL trusted
authority, must come from a verified issuer chain.

When a leaf certificate declares KeyUsage, it must permit `digitalSignature`.
RSA-PSS-constrained public keys are rejected throughout the selected path,
including the used trust anchor, until the restrictions can be fully preserved
and enforced. `rsaEncryption` parameters must be NULL; absent parameters are
accepted for interoperability. Unrelated unsupported anchors do not invalidate
another valid path. Ecosystem EKU requirements are a separate
policy from permission to sign. Algorithm allowlists must be nonempty and can
only narrow the supported wallet algorithms; callers cannot enable weak
algorithms or remove the PS256 key-strength check. Select
`enforce_fapi_alg_policy: true` when the ecosystem also requires FAPI's narrower
signature algorithm set.

Signed presentation requests require `typ: oauth-authz-req+jwt`, an explicit
supported `response_mode`, and URL-safe ASCII nonce and state values. The
verified `client_id` binds the verifier; `iss` is ignored. Every advertised
encryption key must have a unique nonempty `kid` of at most 256 bytes.
Aggregate VP-token data and the encoded response are limited to 1 MiB.
Certificate-bound requests must provide all verifier metadata in signed
`client_metadata`, including `vp_formats_supported`. Caller-supplied
`verifier_metadata` cannot fill omissions there. SD-JWT uses
`sd-jwt_alg_values` and `kb-jwt_alg_values`; mdoc uses integer COSE identifiers
in `issuerauth_alg_values` and `deviceauth_alg_values`. Advertised optional
algorithm arrays must be nonempty. The current mdoc ES256/P-256 implementation
matches either COSE `-7` or the fully specified identifier `-9`.

By-reference `request_uri` and `credential_offer_uri` fetching sends only
protocol-owned headers. Caller cookies, authentication, API keys, custom
headers and routing options are not forwarded. Request URI responses require
HTTP 200 and `application/oauth-authz-req+jwt`; credential offers require HTTP
200 and `application/json`. Presentation responses require HTTP 200 and a
JSON object with `application/json`. Charset parameters are accepted, while
malformed and duplicate JSON are rejected.

Enable the corresponding issuer-chain policy during HAIP issuance:

```elixir
{:ok, result} =
  AttestoClient.Wallet.request_credential(offer, holder_key,
    access_token: tokens,
    credential_issuer_metadata: validated_issuer_metadata,
    credential_configuration_id: "pid",
    format: "dc+sd-jwt",
    haip: true,
    trusted_certificates: [trusted_issuer_root_der],
    dpop: dpop_key,
    key_attestation: provider_key_attestation
  )
```

Pass the complete `TokenSet` returned by the authenticated HAIP token flow;
bare access-token strings lack the local profile and key-binding information.
Retain `profile`, `client_auth_binding`, `client_id`, `issuer` and `dpop_jkt`
along with the tokens when persisting them. These fields are set locally and
are never accepted from token-endpoint JSON.

This mode requires an issuer certificate chain in the SD-JWT VC or mdoc,
validates it to the supplied anchors, and verifies the credential with the
leaf key. It does not fall back to fixed `trusted:` keys. Successful held
credentials include the verified `issuer_certificate_chain` and
`authority_key_identifiers`; failed signature or holder-binding checks never
produce a held credential. Add `certificate_trust:` for further issuer policy.
Certificate-identified SD-JWT credentials may omit `iss`; accepting those
requires Attesto 2.3.1 or later. A present malformed issuer still fails.

Credential status remains application-owned. Before storing or presenting a
credential, apply your revocation and freshness policy. For a Token Status
List, safely fetch the status token, validate its certificate chain and
signature, check its subject and freshness, and use `Attesto.StatusList` to
read and enforce the credential's status index. `Wallet` does not automatically
fetch status tokens, enforce revocation, or provide automated mdoc status
handling.

For issuance, the wallet provider supplies a Client Attestation binding the
wallet instance key, and the key-storage provider supplies key attestations
for the holder keys. Configure client authentication as:

```elixir
wallet_client_auth =
  {:client_attestation, provider_attestation, wallet_instance_key,
   [audience: authorization_server]}
```

The HTTP layer creates a fresh Client Attestation PoP for each request and
supports the server's attestation-challenge retry. Keep this instance key
distinct from the DPoP key and the credential holder key. Client Attestations
built with `AttestoClient.WalletAttestation.attestation/2` should include the
trusted attester's `issuer:` identifier. Pass a provider-issued key attestation,
or a callback producing one for the current keys and nonce, as
`key_attestation:` during issuance. Generating a synthetic attestation with a
test key is appropriate for a test harness, not evidence of secure storage.
The PoP's `audience:` is the intended authorization server from trusted
metadata; the provider attestation's `issuer:` identifies the attester.

If the authorization server advertises a `challenge_endpoint`, obtain its
attestation challenge before starting PAR. Use the endpoint from the selected
server's validated metadata:

```elixir
{:ok, challenge} =
  AttestoClient.WalletAttestation.fetch_challenge(
    validated_as_metadata["challenge_endpoint"]
  )

wallet_client_auth =
  {:client_attestation, provider_attestation, wallet_instance_key,
   [audience: authorization_server, challenge: challenge.challenge]}
```

Pass `client_auth: wallet_client_auth` and `dpop_nonce: challenge.dpop_nonce`
alongside the DPoP key in the subsequent PAR or token request. The helper makes
an unauthenticated empty POST, validates the challenge response and preserves
an optional DPoP nonce. Keep these values scoped to the server that issued
them; use newly received values on later requests. It does not discover the
endpoint or establish trust in an authorization server.

Wallet certification covers a versioned, runnable implementation in the
selected OID4VCI/HAIP or OID4VP/HAIP profiles. The existing Attesto issuer and
verifier certifications and AttestoClient's OIDC RP certification do not
certify this wallet role. See the OpenID Foundation's
[VCI testing instructions](https://openid.net/certification/conformance-testing-for-openid-for-verifiable-credential-issuance/)
and [VP testing instructions](https://openid.net/certification/conformance-testing-for-openid-for-verifiable-presentations/).

## Development and verification

When developing both libraries in sibling source checkouts, use
`ATTESTO_PATH=1 mix test` to exercise the coordinated core. AttestoClient 2.7.0
requires Attesto 2.3.1 or later, including for unencrypted wallet operations,
so installations receive the strict PSS and OID4VP verification fixes.

Run conformance against one frozen source or released dependency set. Record
the implementation versions and suite revision, and finish one complete plan
per selected profile. Review the suite's manual evidence, including the
credential format and actual displayed or disclosed contents, before filing.
