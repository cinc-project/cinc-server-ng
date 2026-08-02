# Modern authentication and node registration with Chef backwards-compat

**Status:** proposed (design)
**Date:** 2026-08-02

## Problem

cinc-zero authenticates every request with Chef's Mixlib::Authentication
signed-header protocol (`internal/auth`, wired in `server/auth.go`). That
protocol is the wire contract unmodified `chef-client`/`knife`/`cinc` clients
speak, so it cannot change for them — but on its own it is dated in ways worth
addressing for clients that *can* adopt something new:

- **RSA-only, and SHA-1 for v1.0/v1.1.** Every key parse/encode path is
  `*rsa.PublicKey`/`*rsa.PrivateKey` and rejects non-RSA (`internal/auth/keys.go`);
  keys are hardcoded 2048-bit. v1.0/v1.1 default to SHA-1 and use OpenSSL
  sign-with-recovery verified through a hand-rolled PKCS#1 v1.5 type-1 unpadder
  (`internal/auth/auth.go`, `rsaPublicDecrypt`).
- **Replay window, no nonce.** `checkSkew` (`server/auth.go`) accepts any signed
  request within ±900s. A captured request replays within that window, including
  against non-idempotent endpoints.
- **Key expiry stored but never enforced.** `expiration_date`/`expired` are
  returned by the key API (`internal/api/keys.go`) but no verification path reads
  them, and `resolveAuth` only ever consults the single top-level `public_key`,
  so named keys added via `POST .../keys` cannot actually sign requests.
- **Shared-secret node bootstrap.** Registration uses the org **validator key**:
  `CreateOrganizationWithKey` mints `<org>-validator` with `validator:true` and
  returns one long-lived RSA private key (`internal/api/organizations.go`), copied
  onto every node ever bootstrapped. It never expires, is identical across the
  whole fleet, and grants unlimited client creation to anyone who reads it off one
  box.
- **No token / human-friendly path.** The only schemes anywhere are Mixlib
  signing and (for `/authenticate_user`) a plaintext password compare. There is
  no bearer-token flow for CI jobs or operators.

## Goal

Add a modern authentication and registration story that clients can opt into,
**strictly additively**, so every existing Chef client keeps working byte-for-byte.
Concretely: pluggable auth schemes behind one dispatch, a modern signed-request
scheme (Ed25519, enforced key expiry, real rotation, nonce replay protection), and
a short-lived JWT **bootstrap token** that replaces the shared validator key for
node registration — with the validator path preserved behind a flag. The classic
Mixlib verifier is untouched and remains the default.

Non-goal for this doc: the client-side signer abstraction lives in the sibling
`cinc-api` repo (a `Signer` interface behind `Config`); it is referenced here only
where the two must agree on the wire.

## Design

### 1. Verifier chain (scheme dispatch)

Today `authMiddleware` calls `auth.Parse` then `auth.Verify` inline. Replace the
inline call with an ordered chain of schemes, each of which cheaply sniffs the
request and, if it owns it, returns a verified identity:

```go
// internal/auth
type Scheme interface {
    // Matches reports whether this scheme owns the request (header sniff only).
    Matches(h http.Header) bool
    // Authenticate verifies the request and returns the actor identity.
    Authenticate(r *Request) (Identity, error)
}
```

The server builds `[]Scheme{ modernSig, legacyMixlib, bearerToken }`. `legacyMixlib`
wraps **today's exact code** (`Parse`/`Verify`/`checkSkew`) and `Matches` on the
presence of `X-Ops-Sign`, so the current wire output and behavior are preserved
verbatim — the existing golden vectors (`internal/auth`) must still pass unchanged.
The webui-impersonation path (`X-Ops-Request-Source: web`) and the HMAC file-store
grant path (`internal/auth/presign.go`) stay where they are; the chain sits on the
normal actor-verification branch only.

A `--min-sign-version` / `--allow-legacy-sign` flag lets an operator retire SHA-1
(v1.0/v1.1) or the whole legacy scheme when *they* choose; default permissive.

### 2. `http-sig-v1` — the modern signed scheme

A new scheme, modeled on RFC 9421 HTTP Message Signatures rather than a fourth
bespoke `X-Ops` dialect, so off-the-shelf tooling can speak it:

- **Transport:** `Signature` + `Signature-Input` headers (not `X-Ops-Authorization-N`).
- **Algorithm agility:** `alg` names the algorithm — **Ed25519** default, ECDSA
  P-256 and RSA-PSS-SHA256 permitted. This lets `internal/auth/keys.go` grow an
  Ed25519 path instead of being RSA-pinned.
- **Key identity + rotation:** `keyid` selects a named, versioned key. This is the
  change that makes the existing named-key collection real — `resolveAuth` learns
  to resolve `keyid` against an actor's keys, not just top-level `public_key`.
- **Integrity:** body covered via `Content-Digest` (RFC 9530), actually included in
  the signature base (today's `X-Ops-Content-Hash` is decorative on verify).
- **Enforced expiry:** the `expires` covered parameter and the stored key
  `expiration_date` are **checked** — an expired key fails verification (closing the
  `internal/api/keys.go` gap).
- **Replay:** a server-issued single-use `nonce` in addition to the timestamp
  (§4).

### 2a. Relationship to `X-Ops-Server-API-Version` — auth is a separate axis

Adopting a modern scheme **does not** bump `X-Ops-Server-API-Version`, and the two
are deliberately decoupled. That header negotiates the **resource/endpoint
contract** (request/response shapes and endpoint semantics), currently range `0`–`2`
(`internal/api/server_endpoints.go`), ahead of routing (`withAPIVersion`). It does
not describe how a caller proves identity. Three independent version namespaces exist
and must stay independent:

| Discriminator | Versions | What it versions |
|---------------|----------|------------------|
| `X-Ops-Server-API-Version` | `0`–`2` | resource/endpoint contract |
| `X-Ops-Sign version=` | `1.0`/`1.1`/`1.3` | legacy Mixlib signing protocol |
| `http-sig-v1` (in `Signature-Input`) | `v1`, later `v2`… | the modern auth scheme itself |

Two reasons the scheme must not be selected by the numeric API version:

- **Orthogonality.** A modern client signs with `http-sig-v1` while still speaking
  API-version-1 resource semantics; an old client signs with Mixlib against the same
  version. Tying them would force a resource-contract migration on anyone who only
  wants better crypto, and would break both auth schemes on any future
  version bump.
- **Layering (decisive).** `X-Ops-Server-API-Version` is folded *inside* the v1.3
  signed canonical block, so the server must verify the signature before it can trust
  that header's value. If the auth scheme were chosen *by* that version, verification
  would depend on a value that is only trustworthy *after* verification — a circular
  dependency. The scheme is therefore selected by an outer discriminator (§1): the
  verifier chain sniffs `X-Ops-Sign` → legacy vs. `Signature-Input` → modern *before*
  any version parsing.

Consequences: the new routes (`POST /register`, `/auth/capabilities`, `/auth/nonce`,
`/oauth/token`) are **additive** — they 404 on an old server, which *is* the discovery
fallback (§6), not a version bump. Scheme negotiation lives in `/auth/capabilities`
plus the header discriminator, never in `X-Ops-Server-API-Version`. The one place the
axes touch: `http-sig-v1`'s signature base **covers** `X-Ops-Server-API-Version` (the
modern equivalent of Mixlib folding it into the canonical string), so a proxy cannot
strip or forge the negotiated version — the scheme *protects* the version header, it is
not *selected by* it.

### 3. Node registration via JWT bootstrap token

Replace the shared validator `.pem` with a short-lived, scoped, single-use JWT.

**New endpoint `POST /organizations/{org}/register`.** Auth for *this call only* is
`Authorization: Bearer <jwt>` — the token is the credential, exactly as the
validator key is today; the request carries no Chef signing headers. Flow:

1. Node generates its own keypair locally (Ed25519); the private key never leaves
   the node.
2. Node calls `/register` with the bearer token and its **public key** in the body.
3. Server verifies the JWT (signature via the server's own signing key, `exp`/`nbf`,
   `aud`, and `jti` not already spent), then performs the same store writes the
   validator path does today — create the `clients` record with the node's public
   key, plus the creator ACL / `clients`-group wiring
   (`internal/api/organizations.go`, `authz_enforce.go`). It marks `jti` spent
   (reusing the §4 nonce store).
4. No private key is ever generated or returned server-side — the node already holds
   its key.
5. Every later request is signed by the node's own key under `http-sig-v1`.

**Token minting:** `cinc-zero token create --org <o> --ttl 15m --node-name <n>` (and
an authenticated `POST /organizations/{org}/registration_tokens` for automation).
Tokens are EdDSA-signed by a server key; verification needs no shared secret.

**Attestation (future rung, same endpoint):** because registration is now "present a
verifiable credential", a cloud instance identity document or TPM attestation can be
an alternative `Authorization` scheme at `/register`, giving a zero-secret bootstrap
on supported platforms. Out of scope to implement now; the endpoint is shaped to
allow it.

### 4. Nonce replay protection

A TTL-bounded seen-set sized to the skew window, consulted by `http-sig-v1` (request
nonces) and by `/register` (token `jti`). A `GET /auth/nonce` issues short-lived
nonces; the store is memory-backed by default and, under `--storage sqlite`, may be
persisted (or simply allowed to lapse on restart within the TTL). Legacy Mixlib
requests keep timestamp-only behavior — nonces cannot be retrofitted onto them.

### 5. Optional environment / run-list (or policy) claims in the token

The bootstrap token may carry **optional** provisioning claims so a node comes up
pre-assigned with no separate `knife` step, and — because they are inside the signed
token — as tamper-proof operator intent rather than node-supplied plaintext.

Two mutually exclusive shapes, mirroring Chef's own rule that a node does not carry
both a run-list and a policy:

- **Classic:** `chef_environment` (string) and/or `run_list` (array of
  `recipe[...]`/`role[...]`).
- **Policyfile:** `policy_group` and `policy_name` (both first-class here —
  `internal/api/policies.go`).

A token carrying policy fields *and* `run_list` is refused at mint time. Semantics:

- **Server-stamped.** On `/register` the server seeds the node object with the
  token's values, so the node's first converge already has the correct environment /
  run-list / policy — no first-run race, no `knife node run_list set`.
- **Token wins.** If the node also supplies these locally, the signed token value is
  authoritative; a node-supplied value is used only for fields the token omits.
- **Validated on the way in**, JSON errors per house convention: `chef_environment`
  must exist (auto-create only behind a flag); `run_list` entries must parse;
  `policy_group`+`policy_name` must resolve to a real revision in that group — else
  `412`/`409`.
- **Initial state, not a lock.** The token sets the node's *starting* state; the node
  object is normal afterward and may change subject to ACLs. A `constraining` mode
  (e.g. `allowed_environments`, a `run_list` allowlist) is an opt-in claim for the
  autoscaler case and can land after the prescriptive form.

### 6. Capability discovery

Extend the unauthenticated system surface (`internal/api/system.go`, already bypassed
in `server/auth.go`) with `GET /auth/capabilities` advertising supported schemes,
algorithms, and endpoints:

```json
{ "schemes": ["mixlib-1.3", "mixlib-1.1", "mixlib-1.0", "http-sig-v1"],
  "algorithms": ["ed25519", "ecdsa-p256", "rsa-pss-sha256", "rsa-pkcs1-sha256"],
  "token_endpoint": "/oauth/token", "nonce_endpoint": "/auth/nonce" }
```

A modern client probes this once and picks the best scheme; a missing endpoint or
absent `http-sig-v1` makes it fall back to Mixlib 1.3. New client ↔ old server and
old client ↔ new server both work.

### 7. Bearer tokens for humans/CI (optional, later phase)

A short-lived bearer scheme (`Authorization: Bearer`) issued by `POST /oauth/token`
(or an extended `/authenticate_user`), PASETO v4 or JWT (EdDSA), self-contained with
`exp`/`aud`/`nonce`, verified by the server's public key. This is the natural seam for
later OIDC federation without touching the signing protocol. Listed for completeness;
sequenced last.

## Migration sequence

Each phase is independently shippable and TDD'd:

1. **Verifier-chain refactor, no behavior change.** Wrap today's verify path as
   `legacyMixlib`; golden vectors prove identical wire output. Pure refactor.
2. **`http-sig-v1`** — Ed25519 + `Content-Digest` + enforced `expires`/key expiry +
   `keyid` rotation in `resolveAuth`.
3. **Nonce replay protection** (§4).
4. **JWT registration** — `/register`, token minting, `jti` single-use; validator
   path preserved behind `--allow-validator-bootstrap`.
5. **Optional env/run-list/policy claims** (§5).
6. **Capability discovery** (§6), then **bearer/OIDC** (§7).

## Testing (TDD)

- **Legacy preserved:** existing `internal/auth` golden vectors and the
  server-package signed-request tests pass unchanged; the validator bootstrap
  end-to-end (`server/bootstrap_e2e_test.go`) stays green.
- **Chain dispatch:** a request with `X-Ops-Sign` routes to `legacyMixlib`; a
  `Signature-Input` request routes to `http-sig-v1`; an unmatched request is 401
  (JSON).
- **Version independence:** `http-sig-v1` verifies identically across every
  supported `X-Ops-Server-API-Version` (0–2) and does not change the negotiated
  range; a tampered `X-Ops-Server-API-Version` fails `http-sig-v1` verification
  because it is covered by the signature base.
- **`http-sig-v1`:** Ed25519 round-trip verify; tampered `Content-Digest` fails;
  expired key fails; `keyid` selects the right named key; ECDSA/RSA-PSS vectors.
- **Nonce:** replayed nonce/`jti` is rejected; distinct nonces pass; entries lapse
  after TTL.
- **Registration:** valid token registers a client with the node's public key and
  the same ACL/group wiring as the validator path; expired/spent/wrong-`aud` tokens
  are 401; no private key is ever returned.
- **Provisioning claims:** token `chef_environment`/`run_list` (and policy variant)
  are stamped onto the node; token beats node-supplied values; nonexistent env /
  unresolved policy / policy+run_list combo are rejected; a claim-less token yields
  `_default` + empty run-list.
- **Capabilities:** `/auth/capabilities` unauthenticated and lists what the build
  supports.
- Full `make test && make vet` green at every phase.

## Out of scope

- The `cinc-api` client-side `Signer` interface (separate repo/PR; must agree on the
  `http-sig-v1` wire).
- OIDC/SAML external identity federation beyond the bearer-token seam.
- Cloud/TPM attestation implementation (endpoint is shaped for it; not built here).
- Retiring RSA or SHA-1 by default — gated behind operator flags, not removed.
- Encrypting the plaintext password store (`internal/api/authenticate.go`) — separate
  concern.
