# JWT bootstrap tokens for node registration

**Status:** proposed (design)
**Date:** 2026-08-09
**Companion:** [Modern authentication and node registration with Chef
backwards-compat](2026-08-02-modern-auth-backwards-compat-design.md) — that spec owns
the verifier chain, the `http-sig-v1` request-signing scheme, the replay store, and
capability discovery. This one owns the bootstrap credential and nothing else.

This document is normative. **MUST**/**MUST NOT**/**SHALL**/**SHOULD** are
requirements on the implementation, and each is a test in the registration slice
(phase 4 of the companion spec's migration sequence). The governing rule throughout
is **fail closed**: anything not explicitly permitted here is a rejection, including
fields that do not exist yet.

## Problem

Node bootstrap in cinc-zero uses the org **validator key**.
`CreateOrganizationWithKey` mints `<org>-validator` with `validator:true` and returns
one long-lived RSA private key (`internal/api/organizations.go`), which is then copied
onto every node ever bootstrapped into that org. That credential:

- **never expires** — there is no `exp`, no rotation story short of re-bootstrapping
  the fleet;
- **is identical across the whole fleet** — one key read off one box is the key for
  every box;
- **is unscoped** — it grants unlimited client creation to whoever holds it, not the
  creation of the one node being built;
- **is unattributable** — every registration looks the same, so a rogue enrollment is
  indistinguishable from a legitimate one;
- **carries no operator intent** — environment, run-list, and policy assignment
  happen in a separate, unauthenticated-in-practice second step after the node
  already exists.

It is, in short, a shared secret with unlimited lifetime and unlimited scope, doing a
job that wants a short, single-purpose capability.

## Goal

Replace the validator `.pem` with a **short-lived, tightly scoped** JWT bootstrap
token, specified tightly enough that the implementation has no room for the standard
JWT footguns, and carrying mandatory provisioning intent so a node comes up correctly
assigned in one step. The validator path is preserved behind
`--allow-validator-bootstrap` so no existing bootstrap breaks.

Two scope modes are supported, because two genuinely different bootstrap shapes exist
(§6):

- **`single`** — one token, one named node, burned on first use. The default, and the
  right answer whenever a human or an orchestrator provisions a specific machine.
- **`multi`** — one token, any number of nodes matching a name pattern, valid for a
  bounded time window. The autoscaling-group / golden-image case, where the set of
  node names is not known when the credential is issued.

`multi` is strictly the weaker credential and is treated as such throughout: narrower
naming rules, a mandatory registry so it can be revoked, per-use audit, and an
optional use cap. It is still bounded in time, org, name, and provisioning intent —
all four of which the validator key it replaces is not.

Non-goals: the request-signing scheme the node uses *after* registration
(`http-sig-v1`, companion spec §2), and the human/CI bearer scheme (companion §7).
Both are separate credentials with separate profiles; the only coupling is the
explicit-typing rule in §3 below that keeps them from being confused for each other.

## Design

### 1. Endpoint and flow

**New endpoint `POST /organizations/{org}/register`.** Auth for *this call only* is
`Authorization: Bearer <jwt>` — the token is the credential, exactly as the validator
key is today; the request carries no Chef signing headers.

1. Node generates its own keypair locally (Ed25519); the private key never leaves the
   node.
2. Node calls `/register` with the bearer token and its **public key** in the body.
3. Server verifies the token against §3–§6, then performs the same store writes the
   validator path does today — create the `clients` record with the node's public key,
   plus the creator ACL / `clients`-group wiring (`internal/api/organizations.go`,
   `authz_enforce.go`) — stamps the node per §7, and records the use: a `single` token
   has its `jti` atomically spent in the companion spec's §4 replay store; a `multi`
   token has its use counted and audited against its registry entry (§6).
4. No private key is ever generated or returned server-side — the node already holds
   its key.
5. Every later request is signed by the node's own key under `http-sig-v1`.

### 2. Threat model

What the token defends against, in the order the mitigations are specified:

| Threat | Mitigation |
|---|---|
| Algorithm substitution (`none`; `HS256` forged with a known public key) | Server-side `alg` allowlist, asymmetric only (§3) |
| Attacker-chosen verification key (`jwk`, `jku`, `x5c`, `x5u`, `kid`) | Header parameter allowlist; key material never taken from the token (§3) |
| A future JWT extension silently changing semantics | Unknown header parameter or unknown claim ⇒ reject (§3, §4) |
| Token minted for server A replayed at server B | `iss` + `aud` binding to one server identity (§4) |
| Bootstrap token replayed at the bearer endpoint, or vice versa | Explicit typing: `typ: "cinc-bootstrap+jwt"` (§3) |
| Captured `single` token reused to enroll a second machine | Single-use `jti`, atomically spent (§6) |
| Captured `multi` token used to enroll attacker machines | Name pattern, optional `max_uses`, TTL window, registry revocation, per-use audit (§6, §8) |
| A bootstrap token used to hijack an *existing* node's identity | `/register` never overwrites an existing client — `409` (§6) |
| One token used to create arbitrary clients or call arbitrary API | Scope is one endpoint, one org, and one name (or bounded pattern) (§6) |
| Long-lived credential smeared across a fleet (today's validator) | Short TTL, per-node keypair, revocable registry for `multi` (§6, §8) |
| Provisioning intent forged by the node | Intent is inside the signed token and mandatory (§7) |

### 3. Token format — locked-down JOSE header

The token **SHALL** be a compact-serialization JWS. The header **MUST** consist of
exactly these parameters, and **MUST** be rejected if it carries any other:

| Parameter | Requirement |
|---|---|
| `alg` | **MUST** be a member of the server's configured allowlist (below). |
| `typ` | **MUST** be exactly `"cinc-bootstrap+jwt"` (RFC 8725 explicit typing). |

Specifically — and this list is illustrative, not exhaustive, because the rule is the
allowlist and not the denylist — a header carrying `jwk`, `jku`, `x5c`, `x5u`, `x5t`,
`kid`, `crit`, `cty`, `zip`, or any parameter not named in the table above **MUST**
cause the request to fail with `401` *before any signature verification is attempted*.
If a future JOSE revision introduces an `xyz` parameter, this profile rejects it by
construction rather than passing it into the JWT library. The verification key is
chosen exclusively from the server's own key set; **no field of the token may
influence which key is used, or supply key material.**

Because `kid` is refused, server signing-key rotation is handled server-side: the
server holds an ordered active key set (current + previous), and verification is trial
verification against that set — a bounded, wholly server-controlled list. This keeps
key *selection* out of attacker-influenced input at the cost of at most one extra
Ed25519 verify.

**Algorithm policy.** `alg` is configurable (`--bootstrap-token-alg`), default `EdDSA`
(Ed25519); `ES256` is permitted. Two hard rules that configuration cannot relax:

- `none` **MUST NOT** ever be accepted. The one exception is `--no-auth`
  (chef-zero-compatible, authn/authz-less mode), where `/register` does not require a
  token at all — the code path is skipped, not softened, so no "unsigned token
  accepted" branch exists in the verifier.
- The HMAC family (`HS256`/`HS384`/`HS512`) **MUST NOT** be accepted at all, even by
  configuration. Symmetric signing reintroduces exactly the shared fleet secret this
  design removes, and it is the substrate for algorithm-confusion attacks.

The server **MUST** compare `alg` against its configured allowlist *before*
verification and **MUST NOT** dispatch on the token's own `alg` to select a
verification routine (the classic confusion bug). Same discipline as `http-sig-v1`:
algorithm agility is a server-side policy list, never a client assertion.

**Configuration safety.** cinc-zero already refuses `--no-auth` combined with an
explicit `--enforce-acls` (`cmd/cinc-zero/main.go`). Extend that guard: if the
configuration otherwise looks like a real server — `--storage sqlite`, an existing
database, a non-loopback `--addr` — then starting with `--no-auth` **MUST** be a
startup error, overridable only by an explicit `--insecure` acknowledgement. A server
that was durable and authenticated yesterday must not come back up wide open after a
restart or an upgrade because a flag fell out of a unit file.

### 4. Claim set

The claim set is likewise an allowlist: **any claim not in this table MUST cause
rejection**, and every claim marked required **MUST** be present.

| Claim | Req. | Requirement |
|---|---|---|
| `ver` | MUST | Profile version the server implements; `"1.0"` initially (§9). |
| `use` | MUST | `"single"` or `"multi"` — the scope mode (§6). No other value; absence is not "default to single". |
| `iss` | MUST | This server's configured identity. |
| `aud` | MUST | This server's configured identity; a single string, not an array. |
| `sub` | MUST² | `use: "single"` only: the one client/node name this token may create — `<org>/<node_name>`. **MUST NOT** appear on a `multi` token. |
| `name_pattern` | MUST² | `use: "multi"` only: the bounded name pattern registrations must match (§6). **MUST NOT** appear on a `single` token. |
| `max_uses` | MAY | `use: "multi"` only: positive integer cap on successful registrations (§6). |
| `org` | MUST | The organization named in the request path. |
| `jti` | MUST | ≥128 bits of CSPRNG entropy, unique. Spent on use for `single`; the registry/revocation handle for `multi` (§6, §8). |
| `iat` | MUST | Issued-at. |
| `nbf` | MUST | Not-before. |
| `exp` | MUST | `exp - iat` **MUST NOT** exceed the server's maximum TTL for the token's `use` mode (§6). |
| `chef_environment` + `run_list` | MUST¹ | Classic provisioning shape (§7). |
| `policy_group` + `policy_name` | MUST¹ | Policyfile provisioning shape (§7). |
| `first_boot_run_list` | MAY | One-shot run list for the first converge only (§7). |

¹ Exactly one of the two provisioning shapes **MUST** be present; carrying both, or
neither, is a rejection at both mint and verify time.

² `sub` and `name_pattern` are mutually exclusive and jointly exhaustive: the claim
required is determined by `use`, and the other one appearing is a rejection. A token
carrying both, or neither, is rejected — there is no fallback that would let a `multi`
token be read as `single` or the reverse.

Clock-skew leeway on `nbf`/`exp` **MUST** be bounded and small (≤30s) and **MUST NOT**
be configurable up to the ±900s legacy Mixlib skew window — the point of a short TTL
is lost if the leeway swallows it.

### 5. Verification algorithm

On `POST /organizations/{org}/register`, in this order, any failure being a `401` with
the house JSON error body and no distinguishing detail in the message:

1. Reject unless the request bears exactly one `Authorization: Bearer` credential.
2. Parse the JOSE header; reject on any parameter outside §3's table; reject unless
   `typ == "cinc-bootstrap+jwt"`; reject unless `alg` ∈ configured allowlist.
3. Verify the signature against the server's active key set (trial verification), and
   *only* then treat any claim as data.
4. Reject on any claim outside §4's table; reject on any missing required claim;
   reject unless `use` is exactly `"single"` or `"multi"` and the `sub`/`name_pattern`
   pairing matches it (§4 note 2).
5. Check `ver`, `iss`, `aud`, `org` (must equal the path org), `nbf`/`exp` with
   bounded leeway, and `exp - iat` ≤ the max TTL for this `use` mode.
6. Check the requested client name against the token's scope: for `single`, it **MUST**
   equal `sub`; for `multi`, it **MUST** match `name_pattern`. A mismatch is `403`.
7. Validate the provisioning claims (§7) — a bad environment/run-list/policy is
   `412`/`409`, not `401`.
8. Record the use, atomically (§6):
   - `single` — compare-and-set spend of `jti` in the replay store. Lost race ⇒ `401`.
   - `multi` — look up the registry entry for `jti`; reject if absent or revoked
     (`401`); increment the use counter under the same transaction as the client
     create, refusing if it would exceed `max_uses` (`429`); append an audit record.
9. Create the client, ACL, and group wiring; stamp the node (§7); return `201`. The
   create **MUST** fail with `409` if a client of that name already exists — no
   bootstrap token, of either mode, may overwrite the key of an existing identity.

Steps 1–6 **MUST NOT** consult the store, so an unauthenticated caller cannot use
`/register` as an oracle for which orgs or nodes exist. Provisioning validation (step
7) and the registry lookup (step 8) do read the store, but only after the signature
and every scope check have passed, so their distinguishable statuses are reachable
exclusively by a legitimate token holder.

**Transport.** The token is a bearer credential: it **MUST** be sent over TLS. When
the server is listening on a non-loopback address without TLS it **SHOULD** refuse to
mint or accept bootstrap tokens absent `--insecure`.

### 6. Scope: what a token may do, and how many times

Every bootstrap token, in either mode, is bounded on four axes. These are not
mode-dependent and cannot be widened by any claim:

- **One endpoint** — `POST /organizations/{org}/register`. It **MUST NOT** be accepted
  by any other route, including the companion spec's §7 bearer scheme (enforced by
  `typ`). It is not an identity that can be ACL'd onto anything, and it confers no
  read or write access to any existing object.
- **One org** — `org`, cross-checked against the request path.
- **Create only, never overwrite** — if a client of the requested name already exists,
  registration **MUST** fail `409`, whatever the mode. Re-registering an existing node
  requires an authorized actor to delete the client first. Without this rule a
  bootstrap token would be an identity-takeover primitive: register `web-01`, get
  `web-01`'s key replaced with yours.
- **The node's own key only** — the server records the public key from the request body
  and never generates or returns a private key.

What differs between the modes is *which names* the token covers and *how many times*
it may be used.

#### 6a. `use: "single"` — one named node, burned on first use

The default and the preferred mode. `sub` names exactly one client; the token cannot
create a differently-named client, a second client, a user, or an org. It is a one-shot
capability to create the single client it names.

- **TTL:** default 15m, ceiling 1h (`--max-single-token-ttl`). Measured against `exp`;
  no refresh, no renewal, no sliding window. A token that ages out is replaced by
  minting another.
- **Single-use:** `jti` is recorded in the replay store (companion §4) with a TTL ≥ the
  token's remaining lifetime. The spend **MUST** be an atomic compare-and-set, not
  read-then-write, so two concurrent presentations cannot both succeed; the loser gets
  `401`.
- **Stateless at mint:** nothing is written when the token is created; the server
  learns of it only when it is spent. A `single` token therefore costs nothing to issue
  in bulk (one per node in a provisioning wave).

Two consequences worth stating outright:

- *Retry safety.* A node whose response is lost on the wire holds a spent token. The
  spend record **SHOULD** therefore retain `(jti, sub, public-key fingerprint,
  outcome)` for its TTL and replay the identical `201` for a byte-identical retry —
  same `sub`, same key. Any differing retry is `401`. This preserves single-use
  semantics (only one client is ever created, bound to one key) while making the common
  network-failure case idempotent rather than a hard bootstrap failure.
- *Memory-backed stores forget.* Under the default in-memory store, spends do not
  survive a restart, which would reopen replay for the remainder of a token's TTL.
  Therefore, when the replay store is not durable, the server **MUST** derive a fresh
  token signing key per process: a restart invalidates every in-flight token instead of
  forgetting which ones were spent. Under `--storage sqlite` the signing key and the
  spend set are both persisted.

#### 6b. `use: "multi"` — a bounded name pattern, for a bounded window

An autoscaling group does not know its node names when the credential is baked into a
launch template or an image, so a per-node token cannot be minted in advance. `multi`
serves that case: any number of registrations, for names matching a pattern, until
`exp` (or `max_uses`) runs out.

This is the weaker credential — a captured `multi` token lets an attacker enroll nodes
until it expires — so it carries compensating controls that `single` does not need:

- **Name pattern, not a wildcard.** `name_pattern` **MUST** be `<org>/` followed by a
  non-empty literal prefix and a single trailing `*` — `acme/web-*` matches `web-01`
  and `web-02` but not `db-01`. Interior wildcards, regexes, and multiple `*` are
  rejected at mint. A bare
  `<org>/*` **MUST** be refused unless the server runs with
  `--allow-unrestricted-bootstrap-tokens`, and the mint path warns when it is used.
  Matching is a literal prefix comparison — never a regex — and the resulting name is
  still subject to normal client-name validation.
- **Registry at mint.** Unlike `single`, minting a `multi` token **MUST** write a
  registry record — `jti`, org, pattern, `exp`, `max_uses`, the minting actor, and a
  revoked flag — to the store. Verification **MUST** find that record; a `multi` token
  whose `jti` is unknown is rejected even if its signature is valid. This is what makes
  revocation possible (§8), and it is affordable precisely because `multi` tokens are
  few and operator-minted, where `single` tokens are per-node and may be thousands.
- **Optional use cap.** `max_uses`, when present, is enforced under the same
  transaction as the client create; the request that would exceed it gets `429`. An
  autoscaling group with a known maximum size should set it.
- **Per-use audit.** Every successful registration appends `(jti, client name, public
  key fingerprint, timestamp)` to the token's registry entry, so "which nodes did this
  credential enroll" is answerable — the question the validator key cannot answer at
  all.
- **Longer but still bounded TTL.** Default 1h, ceiling 24h
  (`--max-multi-token-ttl`). The ceiling is a hard clamp at mint; there is no
  never-expires option, because that is the validator key with extra steps.
- **Rate limiting.** The server **SHOULD** rate-limit registrations per `jti` so a
  leaked token cannot enroll a fleet in seconds before an operator notices.

`multi` is not the default and the CLI **MUST NOT** produce one implicitly: `use:
"multi"` requires `--use multi` (or the equivalent field on the mint endpoint), and
absence of `use` is a rejection, never a silent default (§4).

### 7. Mandatory provisioning claims

The token **MUST** carry the node's provisioning intent. Once the bootstrap credential
is a structured, signed document rather than an opaque `.pem`, there is no reason to
leave the most important thing about a new node — what it is going to run — outside
the signed envelope and in a follow-up call.

Exactly one of two mutually exclusive shapes, mirroring Chef's own rule that a node
does not carry both a run-list and a policy:

- **Classic:** `chef_environment` (string; `_default` **MUST** be spelled explicitly
  rather than implied by omission) and `run_list` (array of `recipe[...]`/`role[...]`;
  **MAY** be empty, **MUST** be present).
- **Policyfile:** `policy_group` and `policy_name` (both first-class here —
  `internal/api/policies.go`).

A token carrying policy fields *and* `run_list`, or neither shape, is refused at mint
time and again at verify time.

For a `use: "multi"` token the claims apply identically to **every** node it registers.
That is the autoscaling case exactly — one launch template, one policy group, N
identical nodes — and it is the main reason a `multi` token is still meaningfully
scoped despite not naming its nodes: it cannot enroll a machine into a different
environment or policy group than the one it was minted for. A group needing a second
role needs a second token.

**One-shot run lists.** Initial bootstrap frequently wants a first-converge-only run
list — the Chef `chef-client -o` override — distinct from the node's persistent
assignment. `first_boot_run_list` is therefore permitted alongside either shape. It is
returned in the `201` body for the bootstrap wrapper to pass to the first converge and
is **never** written to the node object; the node's persisted run-list or policy
remains whatever the mandatory shape specified. First-boot *attributes* are out of
scope here.

Semantics of the mandatory claims:

- **Server-stamped.** On `/register` the server seeds the node object with the token's
  values, so the node's first converge already has the correct environment / run-list
  / policy — no first-run race, no `knife node run_list set`.
- **Token wins.** A node-supplied `chef_environment`/`run_list`/policy field in the
  request body is ignored, not merged. The signed token is the only source of
  provisioning intent.
- **Validated on the way in**, JSON errors per house convention: `chef_environment`
  must exist (auto-create only behind a flag); `run_list` entries must parse;
  `policy_group`+`policy_name` must resolve to a real revision in that group — else
  `412`/`409`.
- **Initial state, not a lock.** The token sets the node's *starting* state; the node
  object is normal afterward and may change subject to ACLs. A `constraining` mode
  (e.g. `allowed_environments`, a run-list allowlist) is a later opt-in claim for the
  autoscaler case and can land after the prescriptive form.

**Honest accounting of what this buys.** The security value is modest. Signing the
intent removes a small window in which a node self-declares its environment or
run-list before an operator corrects it, and it makes registrations attributable to a
specific minted token. It does *not* substitute for correct server-side authorization:
if the ACL and group wiring let a registered node rewrite its own `chef_environment`
or run-list afterwards, the signed claim bought a few seconds of integrity. Closing
those server-side gaps is the higher-value work and is tracked in the companion spec's
enforcement sections. The primary justification for making these claims mandatory is
operational — one round trip, no partially-provisioned node, no forgotten second
step — with tamper-evidence as a secondary benefit.

### 8. Known weakness: revocation

The standing criticism of JWTs is that a self-contained token cannot be force-expired
— once minted it is valid until `exp` no matter what the issuer later decides, and
building a revocation list re-introduces the central lookup the format exists to
avoid. That is a real weakness and it is worth naming rather than glossing. The two
modes answer it differently, which is most of the reason they are distinguished at
all.

**`single`: the weakness does not apply, by construction.** The token's entire lifetime
is minutes; it authorizes exactly one create of exactly one named client; and it is
burned on first use. The window in which a revocation list would have anything to say
is bounded by `exp` and usually closed by the node's own successful registration
seconds after minting. There is deliberately no per-token revocation for `single` —
adding a mint-time write to the hot path of a thousand-node provisioning wave would buy
almost nothing. The blunt lever remains: rotating the server's token signing key
invalidates every outstanding token at once, at the cost of interrupting pending
bootstraps.

**`multi`: the weakness is real, so revocation is mandatory.** A `multi` token is
valid for hours and for any matching name, so "expire it early" is a requirement, not a
nicety. The registry entry written at mint (§6b) is the revocation handle:

- `cinc-zero token revoke <jti>` (and an authenticated `DELETE
  /organizations/{org}/registration_tokens/{jti}`) sets the revoked flag; verification
  **MUST** reject a revoked token thereafter.
- `cinc-zero token list --org <o>` enumerates outstanding `multi` tokens with their
  pattern, `exp`, use count, and minting actor, so an operator can see what is
  outstanding before deciding what to revoke.
- Registry entries are garbage-collected once `exp` passes, so the revocation list is
  bounded by the number of live `multi` tokens — a handful — not by history.

The central lookup this reintroduces is exactly the cost of the extra power `multi`
provides, and it is paid only by `multi`. If that cost is unwelcome, the answer is to
use `single` tokens, which is why they are the default.

Contrast with what both modes replace: the validator key has no `exp` at all, is
identical on every node ever bootstrapped, cannot say which nodes it enrolled, and its
"revocation" is a fleet-wide re-bootstrap.

### 9. Profile versioning

`ver` **MUST** be present and is `"1.0"` for this profile. A server **MUST** reject
any `ver` it does not implement rather than best-effort parsing it.

The value is admittedly redundant in the common deployment: the same server both mints
and verifies, so it can never encounter a version it does not know. It is specified
anyway for two reasons. First, a security protocol without a version field has no
clean way to make a breaking change — every future change becomes a compatibility
guess. Second, the deployments where it *does* bite are exactly the ones worth planning
for: an HA pair or rolling upgrade where two servers share a signing key, and any
future minting that is not co-located with verification.

The corollary is accepted deliberately: upgrading a server across a profile version
invalidates the tokens in flight from the old one. For `single` tokens, with a
15-minute TTL, that is a handful of bootstraps that must retry, and arguably a
feature — a security-relevant upgrade *should* not leave old-format credentials
honored. Nobody should be running a provisioning wave through a server upgrade and
expecting it not to be interrupted. `multi` tokens live longer and so are likelier to
be caught by it, which is exactly what `token list` (§8) is for: an operator can see
what a version-bumping upgrade will invalidate and re-mint deliberately, rather than
discovering it when an autoscaling group fails to enroll.

### 10. Minting

Tokens are EdDSA-signed by a server key; verification needs no shared secret. Both
modes are minted by `cinc-zero token create` or, for automation, an authenticated
`POST /organizations/{org}/registration_tokens`:

```
# single (default): one named node, burned on first use
cinc-zero token create --org acme --node-name web-01 \
    --environment production --run-list 'role[base],recipe[nginx]' --ttl 15m

# multi: an autoscaling group, bounded by pattern, window, and count
cinc-zero token create --org acme --use multi --name-pattern 'web-' \
    --policy-group production --policy-name web --ttl 4h --max-uses 50
```

`--name-pattern` takes the literal prefix; the CLI forms the `name_pattern` claim as
`<org>/<prefix>*` (so `--org acme --name-pattern web-` yields `acme/web-*`).
`--node-name` and `--name-pattern` are mutually exclusive, and each is only valid for
its mode — a `--use multi` without `--name-pattern` is an error, not a wildcard.

The mint path **MUST** enforce every constraint the verify path does — the per-mode TTL
ceiling, mutually exclusive provisioning shapes, well-formed `sub`/`name_pattern`,
allowlisted `alg` — so an invalid token cannot be created in the first place. The
verify-side checks are defense in depth, not the only gate. Minting a `multi` token
additionally writes its registry record (§6b) and **MUST** fail closed if that write
fails: no registry entry, no token.

Minting is itself a privileged operation. The mint endpoint **MUST** require an
authenticated actor with create rights on the org's `clients` container — the same
authority the validator key represents today — and the minting actor is recorded in the
registry entry for `multi` tokens.

### 11. Attestation (future rung, same endpoint)

Because registration is now "present a verifiable credential", a cloud instance
identity document or TPM attestation can be an alternative `Authorization` scheme at
`/register`, giving a zero-secret bootstrap on supported platforms. Out of scope to
implement now; the endpoint is shaped to allow it.

## Migration

This work is phase 4 of the companion spec's sequence and depends on the replay store
(its §4). It lands as its own reviewable slices:

1. **Token type + mint path, `single` only.** Header/claim allowlists, `alg` policy,
   TTL ceiling, `cinc-zero token create`. No endpoint yet; unit-tested against
   hand-built tokens including every malformed shape in the testing section.
2. **`POST /register`.** Verification algorithm (§5), client + ACL + group writes
   identical to the validator path, `409` on existing client, atomic `jti` spend,
   retry-safe spend record.
3. **Mandatory provisioning claims** (§7), including `first_boot_run_list` in the
   `201` body.
4. **`use: "multi"`** — pattern matching, mint-time registry, use counting and
   `max_uses`, per-use audit, `token revoke`/`token list`, rate limiting. Deliberately
   last of the token work: the `single` path must be solid before the weaker
   credential exists at all.
5. **Config guards** — `--allow-validator-bootstrap` (default on, so nothing breaks),
   the `--no-auth`-looks-like-a-real-server startup error, TLS/bearer guard,
   `--allow-unrestricted-bootstrap-tokens`.

The validator path stays working and tested throughout; retiring it is a later,
operator-scheduled decision, not part of this work.

## Testing (TDD)

Header and algorithm lockdown — each its own case, each expecting `401`:

- `alg: none`; `alg: HS256` signed with the server's *public* key as the HMAC secret
  (the classic confusion attack); `alg: RS256` when the allowlist is EdDSA-only.
- Header carrying `jwk`, `jku`, `x5c`, `x5u`, `kid`, `crit`, `cty`, `zip`.
- Header carrying an invented `xyz` parameter — proves the allowlist is a whitelist,
  not a hardcoded denylist.
- Missing or wrong `typ`; a valid *bearer* token (companion §7) presented at
  `/register`, and a valid bootstrap token presented at a bearer-authenticated route.
- Rejection happens before signature verification (assert via a token whose signature
  is garbage but whose header is illegal — the failure must be the header one).

Claims:

- Unknown claim ⇒ `401`; each required claim missing in turn ⇒ `401`.
- `iss`/`aud` belonging to a different server ⇒ `401`; a token minted by a second
  cinc-zero instance ⇒ `401`.
- `org` disagreeing with the path org ⇒ `401`; `sub` disagreeing with the body's
  client name ⇒ `403`.
- `ver` absent, `"2.0"`, or non-string ⇒ `401`.
- `exp` in the past, `nbf` in the future, `exp - iat` over the ceiling for the mode ⇒
  `401`; skew leeway is bounded at 30s (a 60s-stale token fails).
- `use` absent, `"Single"`, `""`, or any value outside `{single, multi}` ⇒ `401` —
  absence in particular must not default to `single`.
- `single` token carrying `name_pattern` or `max_uses` ⇒ `401`; `multi` token carrying
  `sub` ⇒ `401`; a token carrying both `sub` and `name_pattern`, or neither ⇒ `401`.

Scope shared by both modes:

- Registering a name that already exists ⇒ `409`, for `single` and `multi` alike, and
  the existing client's public key is unchanged (identity-takeover regression test).
- A successful registration confers no other access: the new client cannot create a
  second client, and the token cannot be used at any other route.

`use: "single"`:

- Replayed `jti` ⇒ `401`; two concurrent presentations of the same token ⇒ exactly one
  `201`, one `401`, and exactly one client in the store.
- Byte-identical retry (same `sub`, same key fingerprint) returns the same `201`; same
  `jti` with a different public key ⇒ `401`.
- Restart with a memory-backed store invalidates outstanding tokens (fresh per-process
  signing key); with `--storage sqlite`, the signing key and spend set survive and a
  pre-restart token is still rejected as spent.
- Minting writes nothing to the store (assert no registry entry appears).

`use: "multi"`:

- Two different matching names register successfully off one token; a third after
  `max_uses: 2` ⇒ `429`, and no client is created.
- Concurrency: N simultaneous registrations against `max_uses: k` yield exactly `k`
  successes and exactly `k` clients — the counter increments in the same transaction
  as the create.
- Name pattern: `acme/web-*` accepts `web-01`, rejects `db-01` (`403`), rejects
  `web-01/../admin` and any name failing normal client-name validation; interior
  wildcard, regex metacharacters, multiple `*`, and empty prefix are refused at mint.
- Bare `<org>/*` is refused at mint by default and accepted with
  `--allow-unrestricted-bootstrap-tokens`.
- A validly signed `multi` token whose `jti` has no registry entry ⇒ `401` (covers a
  token minted before a registry wipe, and a token forged with a leaked signing key
  but never minted).
- Revocation: `token revoke <jti>` makes the next registration `401` while an already
  registered node keeps working; `token list` shows pattern, `exp`, use count, and
  minting actor.
- Audit: each successful registration appends `(jti, client name, key fingerprint,
  timestamp)`; the entries match the clients actually created.
- Registry entries are collected after `exp`, and a token whose entry has been
  collected fails `401` rather than succeeding.
- Mint fails closed: a registry write error yields no token to the caller.
- Mint requires an authenticated actor with create rights on `clients`; an
  unauthorized mint attempt is `403`.

Registration result:

- Valid token registers a client with the node's public key and the same ACL and group
  wiring as the validator path (assert against the validator-path fixtures).
- No private key is ever returned in any response body.
- Steps 1–6 touch no store: a token for a nonexistent org fails identically to one for
  an existing org (no existence oracle).

Provisioning claims:

- A token with neither shape, or both shapes, is refused at mint *and* rejected at
  verify.
- `chef_environment`/`run_list` and the policy variant are stamped onto the node;
  node-supplied values in the body are ignored, not merged.
- Nonexistent environment ⇒ `412`; unresolvable `policy_group`+`policy_name` ⇒ `409`.
- `first_boot_run_list` appears in the `201` body and is *not* written to the node
  object.
- A `multi` token stamps the same environment/run-list (or policy) onto every node it
  registers, and a node-supplied override is ignored for each of them.

Configuration and compatibility:

- `--no-auth` with `--storage sqlite` (or a non-loopback `--addr`) is a startup error;
  `--insecure` overrides it; `--no-auth` on loopback+memory still works for the
  chef-zero experience, with `/register` requiring no token.
- The existing validator bootstrap end-to-end (`server/bootstrap_e2e_test.go`) stays
  green with `--allow-validator-bootstrap` at its default.
- Full `make test && make vet` green at every slice.

## Out of scope

- The request-signing scheme used after registration (`http-sig-v1`) and the replay
  store — companion spec.
- Human/CI bearer tokens and OIDC federation — companion spec §7.
- Cloud/TPM attestation implementation (the endpoint is shaped for it; not built here).
- Retiring the validator path by default — gated behind an operator flag, not removed.
- First-boot node *attributes* (only `first_boot_run_list` is specified).
- Constraining claims (`allowed_environments`, run-list allowlists) — later rung.
