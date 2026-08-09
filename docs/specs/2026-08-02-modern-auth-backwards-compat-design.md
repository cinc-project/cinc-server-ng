# Modern authentication and node registration with Chef backwards-compat

**Status:** proposed (design)
**Date:** 2026-08-02
**Companion:** [JWT bootstrap tokens for node
registration](2026-08-09-jwt-bootstrap-token-design.md) — the normative profile for the
registration credential described in §3/§5 here.

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

Non-goals for this doc:

- The **bootstrap token profile itself** — its JOSE header and claim allowlists,
  algorithm lockdown, audience binding, `single`/`multi` scope modes, revocation, and
  mandatory provisioning claims are normative and live in the [companion
  spec](2026-08-09-jwt-bootstrap-token-design.md). §3 and §5 below summarize only what
  the rest of this design depends on.
- The client-side signer abstraction, which lives in the sibling `cinc-api` repo (a
  `Signer` interface behind `Config`); it is referenced here only where the two must
  agree on the wire.

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

### 3. Node registration via JWT bootstrap token — see companion spec

Replace the shared validator `.pem` with a short-lived, tightly scoped JWT presented at
a new endpoint `POST /organizations/{org}/register`. Auth for *this call only* is
`Authorization: Bearer <jwt>` — the token is the credential, exactly as the validator
key is today; the request carries no Chef signing headers. The node generates its own
Ed25519 keypair locally, sends the **public** half, and the server performs the same
store writes the validator path does today (client record, creator ACL,
`clients`-group wiring — `internal/api/organizations.go`, `authz_enforce.go`). No
private key is ever generated or returned server-side. Every later request is signed by
the node's own key under `http-sig-v1`.

The bootstrap credential has enough security surface of its own — JOSE header
lockdown, claim allowlisting, audience binding, use semantics, revocation — that it
gets a dedicated normative document:

**→ [JWT bootstrap tokens for node
registration](2026-08-09-jwt-bootstrap-token-design.md)**

The parts of it this document depends on:

- The token profile is **fail-closed**: an allowlisted JOSE header (`alg`, `typ`
  only — `jwk`/`x5c`/`kid`/anything unknown is a rejection), an allowlisted claim set,
  asymmetric `alg` only (`none` and the HMAC family are never accepted), and `iss`/`aud`
  binding so a token minted for one server cannot be replayed at another.
- Two scope modes: **`single`** (one named node, burned on first use, `jti` spent in the
  §4 replay store) and **`multi`** (a bounded name pattern for a bounded window, with a
  mint-time registry, optional use cap, per-use audit, and real revocation). `single` is
  the default.
- Registration **never overwrites** an existing client; provisioning intent is mandatory
  and carried inside the signed token (§5).
- It consumes this document's §4 replay store for `jti` spends, and the
  `--no-auth`-hardening rule it specifies applies server-wide.

The validator path is preserved behind `--allow-validator-bootstrap`.

**Attestation (future rung, same endpoint):** because registration is now "present a
verifiable credential", a cloud instance identity document or TPM attestation can be an
alternative `Authorization` scheme at `/register`, giving a zero-secret bootstrap on
supported platforms. Out of scope to implement now; the endpoint is shaped to allow it.

### 4. Nonce replay protection

A TTL-bounded seen-set sized to the skew window, consulted by `http-sig-v1` (request
nonces) and by `/register` (token `jti`). A `GET /auth/nonce` issues short-lived
nonces; the store is memory-backed by default and, under `--storage sqlite`, may be
persisted (or simply allowed to lapse on restart within the TTL). Legacy Mixlib
requests keep timestamp-only behavior — nonces cannot be retrofitted onto them.

### 5. Mandatory environment / run-list (or policy) claims — see companion spec

The bootstrap token **must** carry the node's provisioning intent, in exactly one of two
mutually exclusive shapes mirroring Chef's own rule that a node does not carry both a
run-list and a policy:

- **Classic:** `chef_environment` (`_default` spelled explicitly, not implied) and
  `run_list`.
- **Policyfile:** `policy_group` and `policy_name` (both first-class here —
  `internal/api/policies.go`).

The server stamps these onto the node at registration, so the first converge is already
correct — no first-run race, no `knife node run_list set`, and no window in which a node
self-declares its own environment. A `first_boot_run_list` claim may additionally carry a
one-shot, first-converge-only run list (the `chef-client -o` case), returned in the `201`
body and never persisted onto the node.

Making these claims mandatory rather than optional is a deliberate change from the first
draft of this spec: once the bootstrap credential is a structured signed document, there
is no reason to leave the most important fact about a new node outside the envelope. The
security value is honestly modest — the higher-value work is closing server-side
authorization gaps so a registered node cannot simply rewrite its own environment
afterwards — but the operational value (one round trip, no partially-provisioned node) is
not.

Full rules, validation statuses, and the `multi`-token semantics are in the companion
spec: **[JWT bootstrap tokens for node
registration](2026-08-09-jwt-bootstrap-token-design.md)**, §7.

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
3. **Nonce replay protection** (§4) — also the `jti` store phase 4 depends on.
4. **JWT registration** — `/register`, token minting, `single`-then-`multi` scope
   modes, mandatory provisioning claims; validator path preserved behind
   `--allow-validator-bootstrap`. Broken into its own slices in the [companion
   spec](2026-08-09-jwt-bootstrap-token-design.md).
5. **Capability discovery** (§6), then **bearer/OIDC** (§7).

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
- **Registration:** valid token registers a client with the node's public key and the
  same ACL/group wiring as the validator path; expired/spent/wrong-`aud` tokens are
  401; no private key is ever returned. The full matrix — header and claim allowlists,
  `alg` lockdown, scope modes, revocation, provisioning claims — lives in the
  [companion spec](2026-08-09-jwt-bootstrap-token-design.md).
- **Capabilities:** `/auth/capabilities` unauthenticated and lists what the build
  supports.
- Full `make test && make vet` green at every phase.

## Out of scope

- The normative bootstrap-token profile — [companion
  spec](2026-08-09-jwt-bootstrap-token-design.md).
- The `cinc-api` client-side `Signer` interface (separate repo/PR; must agree on the
  `http-sig-v1` wire).
- OIDC/SAML external identity federation beyond the bearer-token seam.
- Cloud/TPM attestation implementation (endpoint is shaped for it; not built here).
- Retiring RSA or SHA-1 by default — gated behind operator flags, not removed.
- Encrypting the plaintext password store (`internal/api/authenticate.go`) — separate
  concern.
