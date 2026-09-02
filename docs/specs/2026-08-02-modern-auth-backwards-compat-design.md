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

Add a modern **request authentication** story that clients can opt into, **strictly
additively**, so every existing Chef client keeps working byte-for-byte. Concretely:
pluggable auth schemes behind one dispatch, a modern signed-request scheme
(`http-sig-v1`), and the two shared primitives both it and the bootstrap track need —
a replay store (§4) and a key model that is neither RSA-pinned nor single-key, with
expiry actually enforced (§5). The classic Mixlib verifier is untouched and remains the
default.

**Node registration is a separate track.** It is specified in the [JWT bootstrap token
spec](2026-08-09-jwt-bootstrap-token-design.md) and appears here only as §3's pointer.
The dependency runs one way — that document consumes this one's §4 and §5, and this one
does not depend on it at all — so once the shared primitives land, the two tracks can be
built in parallel and in either order.

Non-goals for this doc:

- **Node registration and the bootstrap token profile** — the endpoint, the JOSE header
  and claim allowlists, algorithm lockdown, audience binding, `single`/`multi` scope
  modes, revocation, attribution, and provisioning claims are all normative in the
  [companion spec](2026-08-09-jwt-bootstrap-token-design.md). Nothing about them is
  restated here; §3 is a pointer, not a summary.
- The client-side signer abstraction, which lives in the sibling `cinc-api` repo (a
  `Signer` interface behind `Config`); it is referenced here only where the two must
  agree on the wire.
- The **webui impersonation key** (`X-Ops-Request-Source: web`). Explicitly deferred to
  a future spec of its own, with the risk named rather than glossed — see §1.

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

**Non-goal, deliberately: the webui impersonation key.** It is worth naming the risk
rather than letting the sentence above pass as a routine exclusion, because by
lifetime and scope the webui key is the most powerful credential in the server and this
document does not touch it. Any request signed with that key and carrying
`X-Ops-Request-Source: web` runs as whatever user `X-Ops-Userid` names
(`server/auth.go`); the key defaults to the admin key (`server/server.go`), is RSA-only,
has no expiry, no rotation, and no `keyid`; and `ViaWebUI` is honored as an
authorization bypass on `/authenticate_user` (`internal/api/authenticate.go`).

To be accurate about the delta: because it defaults to the admin key, holding it grants
no *authority* beyond what `pivotal` already has. The defects are the two this work
addresses everywhere else — **attribution** (an impersonated request runs as the target
user and nothing records that the webui key was the real actor) and **unbounded
lifetime and scope** (no expiry, no scoping to a set of impersonable users, no way to
retire it short of replacing the admin key). A reader who has just read the bootstrap
token's mandatory `minter` claim and per-registration audit log will notice the
asymmetry immediately, and should.

It stays a non-goal here for a real reason: it is a distinct credential with a distinct
consumer (a management console), and folding it into the verifier chain in the same
change that introduces two new schemes would put the riskiest refactor on the critical
path of the least risky one. **It gets its own spec**, which should cover at minimum:
disabling impersonation unless a webui key is explicitly configured rather than silently
aliasing the admin key, refusing to impersonate global admins, logging both the real and
effective identity on every impersonated request, and giving the key an expiry and a
rotation path. Until then its behavior is unchanged and
`server/webui_impersonation_test.go` stays green.

A `--min-sign-version` / `--allow-legacy-sign` flag lets an operator retire SHA-1
(v1.0/v1.1) or the whole legacy scheme when *they* choose; default permissive.

### 2. `http-sig-v1` — the modern signed scheme

A new scheme, modeled on RFC 9421 HTTP Message Signatures rather than a fourth
bespoke `X-Ops` dialect, so off-the-shelf tooling can speak it:

- **Transport:** `Signature` + `Signature-Input` headers (not `X-Ops-Authorization-N`).
- **Algorithm agility:** `alg` names the algorithm — **Ed25519** default, ECDSA
  P-256 and RSA-PSS-SHA256 permitted — compared against the stored key's own type,
  never used to dispatch (§5a).
- **Key identity + rotation:** `keyid` selects a named key (§5b).
- **Integrity:** body covered via `Content-Digest` (RFC 9530), actually included in
  the signature base (today's `X-Ops-Content-Hash` is decorative on verify).
- **Enforced expiry:** the `expires` covered parameter is checked here, and the stored
  key's `expiration_date` is checked per §5e.
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

Consequences: the new routes (`POST /register`, `/registration_tokens`,
`/registration_log`, `/auth/capabilities`, `/auth/nonce`, `/oauth/token`) are
**additive** — they 404 on an old server, which *is* the discovery fallback (§6), not a
version bump. Scheme negotiation lives in `/auth/capabilities`
plus the header discriminator, never in `X-Ops-Server-API-Version`. The one place the
axes touch: `http-sig-v1`'s signature base **covers** `X-Ops-Server-API-Version` (the
modern equivalent of Mixlib folding it into the canonical string), so a proxy cannot
strip or forge the negotiated version — the scheme *protects* the version header, it is
not *selected by* it.

### 3. Node registration — a separate track

Registration is deliberately **not** specified here. Replacing the shared validator
`.pem` with a short-lived, scoped credential is its own problem with its own threat
model, and it is normative in:

**→ [JWT bootstrap tokens for node
registration](2026-08-09-jwt-bootstrap-token-design.md)**

The only relationship between the two documents is that registration **consumes** this
one's §4 replay store (to spend a token's `jti` exactly once) and §5 key model (to store
the Ed25519 key a node registers). That dependency is one-way: nothing in this document
requires registration to exist, and a fleet bootstrapped by validator keys can adopt
`http-sig-v1` without it. Once §4 and §5 land, the two tracks proceed independently.

Two notes for a reader of this document only: `/register` is a cinc-zero extension that
no Chef client speaks, and the validator path is preserved behind
`--allow-validator-bootstrap`, so nothing in either document changes how an existing
node bootstraps.

### 4. The replay store

A TTL-bounded set of spent identifiers with atomic first-writer-wins semantics,
answering exactly one question: *has this identifier been used before, and if so what
happened the first time?* `http-sig-v1` spends request nonces against it; the bootstrap
track spends token `jti`s. Legacy Mixlib requests keep timestamp-only behavior — nonces
cannot be retrofitted onto them.

It is specified as a contract rather than a mechanism because it has two consumers that
must not be able to interfere with each other:

```go
// internal/replay

// Record is an opaque, small payload the winner of a spend leaves behind for
// any later caller presenting the same key. Consumers define the encoding.
type Record []byte

type Store interface {
    // Spend atomically records rec under key if key is absent, and reports
    // whether this caller won. On a loss it returns the record the winner
    // left, so the caller can distinguish a retry of the original from a
    // replay by someone else.
    //
    // Spend MUST be a compare-and-set. A read-then-write implementation is a
    // defect, not an optimization: two concurrent presentations of the same
    // single-use credential must not both win.
    Spend(key string, rec Record, ttl time.Duration) (won bool, prior Record, err error)
}
```

Deliberately minimal: there is no `Seen`, because a caller that only wants to test
membership is a caller about to race, and no `Delete`, because entries leave only by
expiry.

- **Namespacing.** Keys are prefixed by consumer (`sig:` for request nonces, `jti:` for
  bootstrap tokens) so a registration can never burn a request nonce or the reverse.
- **Fail closed.** A store error **MUST** cause the caller to reject. This differs from
  the server's convention of reporting store faults as `500` during actor resolution
  (`server/auth.go`), and deliberately: the question here is "is this credential fresh",
  and a store that cannot answer has not said yes.
- **TTL** is set by the caller and **MUST** be at least the remaining validity of what
  is being spent — a signature's `expires`, a token's `exp`. An entry that lapses while
  its credential is still valid reopens replay for the difference.
- **Durability is a consumer concern.** Memory-backed by default, persisted under
  `--storage sqlite`. Each consumer **MUST** state what it does when the store is not
  durable rather than assuming persistence; a restart that forgets spends reopens replay
  for everything still inside its window. (`http-sig-v1`'s answer: a restart is
  indistinguishable from the skew window elapsing, which is acceptable because request
  signatures are short-lived by construction. The bootstrap track's answer is a
  per-process signing key, in its own spec.)

**Implementation constraints.** The bootstrap consumer touches this store once per node,
ever. `http-sig-v1` touches it on *every authenticated request*, which makes it the one
piece of shared mutable state on the hot read path — a fleet check-in is roughly seven
reads to one write, and every one of those reads would now take a write here.

- The memory implementation **MUST** be sharded by key hash, not a single mutex-guarded
  map, or the read path acquires a global serialization point at exactly the fleet sizes
  this project already benchmarks (`cmd/fleetsim`, `cmd/loadtest`).
- Sizing is *window × request rate*, which is one more reason `http-sig-v1` must not
  inherit the ±900s legacy skew window.
- Collection is lazy on access plus a periodic sweep, and **MUST NOT** hold a global
  lock across the set.
- Eviction of a *live* entry **MUST** be a fault (fail closed), never "not seen". A
  silently evicting cache is a replay vulnerability wearing a performance costume.

### 5. The key model

Three changes that `http-sig-v1` needs, that the bootstrap track needs in order to
register a node's Ed25519 key, and that neither owns.

**5a. Algorithm agility.** Actor keys become a sum type rather than `*rsa.PublicKey`:
Ed25519, ECDSA P-256, and RSA (PSS and PKCS#1 v1.5) parse and store through one path
(`internal/auth/keys.go`, `internal/auth/cache.go`, and `parseActorRecord`/`resolveAuth`
in `server/auth.go`, all of which are RSA-typed today and generate hardcoded 2048-bit
keys). Ed25519 is the default for newly generated keys.

The governing rule is the same one the bootstrap profile applies to JOSE `alg`: **the
stored key's own type selects the verification algorithm.** A caller may *name* an
algorithm, in which case the server compares it against the key and its configured
allowlist and rejects a mismatch — but the named value **MUST NOT** dispatch to a
verification routine. Algorithm agility is a server-side policy list, never a client
assertion. Legacy Mixlib verification is untouched and stays RSA-only, reading the same
records through the same resolution path.

**5b. Named keys, resolved by identifier.** The keys collection served by
`internal/api/keys.go` becomes real. It is real storage today that no verification path
consults — `parseActorRecord` reads only the record's top-level `public_key` — so a key
added through `POST .../keys` cannot actually sign a request.

- The identifier is `<scope>/<actor>#<key-name>` — `acme/web-01#default`,
  `users/alice#laptop`. It names both the actor and the key, so a consumer needs no
  second identity header.
- Resolution order mirrors today's `resolveAuth`: org clients first when the path is
  org-scoped, then global users.
- The top-level `public_key` stays valid and is equivalent to the key named `default`,
  so every existing actor keeps working unchanged.
- An actor has a bounded number of keys (`--max-keys-per-actor`, default 5). Unbounded
  key lists amplify trial verification and quietly keep retired credentials alive.
- Resolution **MUST NOT** be an existence oracle: an unknown actor and an unknown key
  name fail identically.

**5c. Expiry enforcement.** Broken out into §5e — it is the one change here that breaks
on upgrade, and it needs its own accounting.

**5d. Rotation and lockout.** Multi-key actors make rotation possible; this is the flow,
which is otherwise merely implied by the existence of the keys API:

- Rotation is *add, then remove*: an actor signs with its current key to add a new one,
  switches, then deletes the old. Both are valid in between, which is what makes the
  switch safe.
- Adding an already-expired key is a `400`.
- **Lockout recovery.** Once expiry is enforced, an actor whose keys have all expired
  cannot sign the request that would add a new one. That is a consequence of the design,
  not a bug, and it needs a documented way out: an actor with update rights on the
  target (an org admin, or `pivotal`) adds a key on its behalf through the existing keys
  API, and the server **SHOULD** surface expiring-soon keys in its status output so the
  cliff is visible before it is reached.

### 5e. Enforcing `expiration_date` — a breaking change, and a gap that must be closed

This is called out separately because both halves of it are true and neither should be
allowed to hide the other.

**It is a real security gap, and closing it is not optional.** `expiration_date` is
accepted from the request body, stored, and returned by the key API
(`internal/api/keys.go`) — and no verification path has ever read it. The practical
consequences are worse than "a field is ignored":

- **Key expiry does not work.** An operator who sets an expiry on a key, or who reads
  one back from the API, is being told a credential is time-bounded when it is not. The
  API reports `expired` and `expiration_date` as facts; they are decoration.
- **It is a silent failure of a control people rely on.** Expiry is how a credential
  issued to a contractor, a CI job, or a decommissioned host is supposed to stop
  working without anyone having to remember to delete it. Here, nothing stops working,
  and nothing says so.
- **Everything else in this design leans on it.** `http-sig-v1` advertises enforced
  expiry (§2) and the whole rotation story (§5d) assumes an old key eventually stops
  being usable. Without enforcement, rotation is addition with extra steps.

A field that claims to bound a credential's lifetime and does not is a vulnerability,
not a rough edge. It gets fixed.

**And it will break existing deployments on upgrade.** The field is written verbatim
from the request body with no validation and defaults to the string `"infinity"`. Any
store baked before this change — including `dev/cinc-dev.db` and any user's durable
server — may hold past dates, or values that are not dates at all. The moment
enforcement lands, those actors stop authenticating, on a restart nobody would connect
to a security fix. An upgrade that silently locks a fleet out of its own server is how a
correct change acquires a bad reputation.

So the break is **managed, not avoided**:

- **Validate on write, going forward.** `expiration_date` **MUST** be `"infinity"` or an
  RFC 3339 timestamp; anything else is a `400` at the keys API. After this, enforcement
  only ever reads values the server itself accepted.
- **Migrate what already exists**, through the schema migration engine
  ([spec](2026-06-29-schema-migration-engine-design.md)): parseable values are rewritten
  canonically, unparseable ones become `"infinity"` — which preserves today's *effective*
  behavior exactly, since the field is currently ignored — and the migration **MUST**
  report how many keys it touched and how many were already expired. That count is the
  operator's warning that an upgrade is about to change who can authenticate.
- **Fail closed at verification.** After migration an unparseable value cannot
  legitimately exist, so verification treats one as expired. There is no lenient parse
  path; the leniency is spent once, in the migration, where it is counted and visible.
- **Give operators one lever.** `--ignore-key-expiry` restores the old behavior for a
  single upgrade cycle, logs loudly at startup, and is documented as temporary. An
  operator surprised by a fleet-wide authentication failure needs an answer that is not
  "downgrade the server".
- **Announce it.** This is a `CHANGELOG`-worthy behavior change and belongs in release
  notes, not only in a spec.

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

**Hard prerequisite: passwords must be hashed before this ships.** Today
`/authenticate_user` compares the submitted password against a plaintext value kept in
the `passwords` collection (`internal/api/authenticate.go`). The comparison is
constant-time, which is the right instinct and beside the point: a store read yields
every user's password directly, in a system whose durable backend is a single SQLite
file, for credentials users demonstrably reuse elsewhere.

That is tolerable only while the password check is a leaf — it authenticates one
request and grants nothing that outlives it. §7 changes exactly that: it makes the
password check the **minting authority for a credential**, so the weakest secret in the
server becomes the root of the newest one, and a store read escalates from "read the
data" to "issue valid tokens as any user." The two changes are individually defensible
and jointly indefensible, which is why the ordering is normative rather than a
preference:

- §7 **MUST NOT** ship before password storage is hashed with a deliberately slow KDF.
  Argon2id is the preferred construction; PBKDF2-HMAC-SHA256 via stdlib `crypto/pbkdf2`
  (Go ≥1.24, and this module is on 1.26) is acceptable and keeps the repo's
  single-direct-dependency posture. Either is categorically better than what is there.
- Verification stays constant-time, per-user salts are mandatory, and the parameters are
  recorded alongside the hash so they can be raised later without a flag day.
- Existing plaintext entries are migrated on upgrade through the schema-migration engine
  (`docs/specs/2026-06-29-schema-migration-engine-design.md`) — rehash in place; there
  is no read path that needs the plaintext.
- `/authenticate_user` and `/oauth/token` **MUST** be rate-limited per identity. An
  unthrottled password endpoint is an online guessing oracle whatever the hash costs,
  and it is currently unthrottled.

Hashing the password store is not otherwise in scope for this document (see Out of
scope) — but it becomes in scope for whichever change implements §7, and that change
owns it.

### 8. Server configuration safety

A server-wide rule, specified here rather than in the bootstrap spec because it governs
the server's configuration rather than any one credential.

cinc-zero already refuses `--no-auth` combined with an explicit `--enforce-acls`
(`cmd/cinc-zero/main.go`). Extend that guard: if the configuration otherwise looks like
a real server — `--storage sqlite`, an existing database — then starting with
`--no-auth` **MUST** be a startup error, overridable only by an explicit `--insecure`
acknowledgement. A server that was durable and authenticated yesterday must not come
back up wide open after a restart or an upgrade because a flag fell out of a unit file.

The signal is deliberately **durability, not the listen address**. A non-loopback
`--addr` is the normal case for the container and CI usage this project exists to
serve — binding `0.0.0.0` with memory storage is the chef-zero experience working as
intended — and a guard that fires there would train everyone to paste `--insecure` into
a Dockerfile, which is the reflex the guard exists to prevent. A non-loopback bind
**SHOULD** print a loud startup banner instead.

Under `--no-auth` the modern schemes are not "relaxed"; their code paths are skipped
entirely, so no partially-authenticating branch exists to be reached by accident.

## Migration sequence

Each phase is independently shippable and TDD'd. Phases 1–3 are the **shared
primitives**: they are what the bootstrap track waits on, and after them the two tracks
have no dependency on each other and may proceed in parallel or in either order.

1. **Verifier-chain refactor, no behavior change.** Wrap today's verify path as
   `legacyMixlib`; golden vectors prove identical wire output. Pure refactor.
2. **Key model** (§5) — de-RSA the parse/store/cache/resolve path and add Ed25519
   (§5a); `keyid` resolution and named keys (§5b); rotation and lockout recovery (§5d);
   then expiry enforcement with its validation, migration, and grace flag (§5e), which
   is sequenced last within this phase because it is the only part that changes who can
   authenticate.
3. **The replay store** (§4) — interface, sharded memory implementation, SQLite
   backing, GC. Independent of phase 2 and may land beside it.
4. **`http-sig-v1`** — the wire scheme itself, on top of phases 2 and 3.
5. **Capability discovery** (§6), then **bearer/OIDC** (§7) — gated on hashed password
   storage landing first or in the same change (§7). That gate is a hard ordering, not
   a preference: shipping §7 over a plaintext password store would make a store read an
   any-user token-minting capability.

**Node registration** is not a phase of this sequence. It depends on phases 2 and 3 and
is otherwise independent; its own slices are in the [companion
spec](2026-08-09-jwt-bootstrap-token-design.md).

## Testing (TDD)

- **Legacy preserved:** existing `internal/auth` golden vectors and the
  server-package signed-request tests pass unchanged; the validator bootstrap
  end-to-end (`server/bootstrap_e2e_test.go`) stays green.
- **Untouched paths stay untouched:** `server/webui_impersonation_test.go` and the
  file-store grant tests (`internal/auth/presign_test.go`) pass unchanged — the
  verifier chain must not alter either branch (§1).
- **Chain dispatch:** a request with `X-Ops-Sign` routes to `legacyMixlib`; a
  `Signature-Input` request routes to `http-sig-v1`; an unmatched request is 401
  (JSON).
- **Version independence:** `http-sig-v1` verifies identically across every
  supported `X-Ops-Server-API-Version` (0–2) and does not change the negotiated
  range; a tampered `X-Ops-Server-API-Version` fails `http-sig-v1` verification
  because it is covered by the signature base.
- **`http-sig-v1`:** Ed25519 round-trip verify; tampered `Content-Digest` fails;
  expired key fails; `keyid` selects the right named key; ECDSA/RSA-PSS vectors.
- **Replay store (§4):** `Spend` is atomic — N concurrent spends of one key yield
  exactly one winner and every loser receives the winner's record; entries lapse at TTL
  and not before; `sig:` and `jti:` keys with the same suffix are distinct; an injected
  store error makes the caller reject rather than admit; eviction of a live entry is a
  fault, not "not seen"; concurrent spends of distinct keys do not serialize (a
  contention benchmark, so a regression to one mutex is visible).
- **Key model (§5):** Ed25519/ECDSA/RSA all round-trip parse→store→cache→resolve; a
  named algorithm disagreeing with the stored key's type is rejected and never selects
  the routine (assert with an Ed25519 key claiming RSA); `keyid` selects the right named
  key; `default` and the top-level `public_key` are equivalent; an actor with only a
  top-level key is untouched; unknown actor and unknown key name fail identically;
  `--max-keys-per-actor` is enforced; add-then-remove rotation keeps the actor
  authenticated throughout.
- **Key expiry (§5e)** — the breaking change, tested as one: an expired key fails
  verification; adding an expired key is `400`; a non-RFC-3339, non-`"infinity"` value
  is `400` on write; a store seeded with past dates, `"infinity"`, and garbage migrates
  with garbage becoming `"infinity"`; **every actor that authenticated before the
  migration still authenticates after it** unless its key was genuinely expired; the
  migration reports the counts it touched and expired; `--ignore-key-expiry` restores
  the old behavior and logs at startup.
- **Capabilities:** `/auth/capabilities` unauthenticated and lists what the build
  supports.
- Full `make test && make vet` green at every phase.

Registration is tested in the [companion
spec](2026-08-09-jwt-bootstrap-token-design.md)'s own matrix, not here.

## Out of scope

- **Node registration in its entirety** — the `/register` endpoint, the bootstrap token
  profile, provisioning claims, attribution, and the token signing key all live in the
  [companion spec](2026-08-09-jwt-bootstrap-token-design.md). This document supplies the
  two primitives that spec consumes (§4, §5) and says nothing else about it.
- The `cinc-api` client-side `Signer` interface and its `Register` call (separate
  repo/PR; must agree on the `http-sig-v1` wire and the companion spec's §5).
- OIDC/SAML external identity federation beyond the bearer-token seam.
- Cloud/TPM attestation implementation (endpoint is shaped for it; not built here).
- Retiring RSA or SHA-1 by default — gated behind operator flags, not removed.
- Hashing the plaintext password store (`internal/api/authenticate.go`) — out of scope
  for the phases specified here, but **not merely a separate concern**: it is a hard
  prerequisite for the §7 bearer scheme, which turns the password check into a
  token-minting authority. Whichever change implements §7 owns it (§7).
- The webui impersonation key — deferred to its own spec, risk named in §1.
- **Local CLI tooling.** Everything specified here is an HTTP API or a server startup
  flag. `cinc-zero` may later grow subcommands — for registration tokens, user creation,
  key management — and when it does they **SHOULD** be thin authenticated clients of
  these APIs rather than a second implementation against the store, which under the
  default memory backend could not reach a running server's state at all. Creating users
  and managing keys already have APIs (`POST /users`, the keys collection in §5b); no
  new actor-creation mechanism is introduced by this design.
