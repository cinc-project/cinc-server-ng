# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

cinc-server-ng is a drop-in replacement for **both** Chef Infra Server and chef-zero, written in Go. It speaks the real Chef Infra Server API and authenticates unmodified `chef-client`/`knife`/`cinc` clients via genuine Mixlib::Authentication signed requests. State lives behind a pluggable `store.Backend`: in memory by default (instant, disposable test servers, the chef-zero role) or in SQLite for durable state that survives restarts (`--storage sqlite --db <path>`), so the same server spans CI fixtures and full-scale production fleets. Fidelity to real Chef Infra Server behavior is the goal; Policyfiles/policy groups are first-class.

## Commands

- `make build` — compile the `cinc-server-ng` binary (version metadata via ldflags); it lands at `./cinc-server-ng` in the repo root.
- `make test` — `go test ./... -race -cover` (the full suite).
- `make vet` / `make fmt` — `go vet ./...` / `gofmt -w .`.
- `make conformance` — drives the real `knife` CLI against an in-process server (ACL enforcement **on**, as the binary ships); needs Cinc Workstation and is gated behind `-tags conformance`. It skips when knife is unusable unless `CINC_SERVER_NG_REQUIRE_CONFORMANCE=1` (which CI and the make target set), which turns that into a failure.
- `make differential` — compares responses against a real Chef Infra Server (`-tags differential`, needs both servers; see `.github/workflows/differential.yml`). The harness itself is unit-tested without a real server by comparing two cinc-server-ng instances, so `go test ./differential/` runs in the normal suite.
- Single test: `go test ./internal/api/ -run TestName -v` (most logic lives in `internal/api`).
- `make run ARGS="--enforce-acls --orgs acme"` — build and run; flags: `--addr`, `--orgs` (CSV), `--admin`, `--no-auth`, `--enforce-acls`, `--repo`, `--key-out`, `--storage` (`memory` default / `sqlite`), `--db` (SQLite path; required for `--storage sqlite`; env `CINC_SERVER_NG_STORAGE`/`CINC_SERVER_NG_DB`), `--init` (seed the store and exit without serving — used to pre-bake a DB).
- `make dev-db` bakes `dev/test-repo` into `dev/cinc-dev.db` (git-ignored); `make run-dev` serves the seed in-memory (no auth), `make run-dev-sqlite` serves the durable SQLite copy with auth on. Developer setup, test accounts, and cinc-console wiring live in `docs/DEVELOPMENT.md`.

Always run `make test && make vet` before committing. Development is strict TDD: write a failing test first.

## Architecture

Request flow and layering (each layer is a separate package; understanding the request path requires all of them):

```
cmd/cinc-server-ng (flag parsing)
  └─ server.New(Options)            server/        — bootstraps store+admin+orgs, wires middleware
       authMiddleware               server/auth.go — verifies Mixlib signature (skipped if DisableAuth),
         └─ withAPIVersion          internal/api   — stores the actor in ctx via api.WithActor
              └─ authzMiddleware     (api, only when EnforceACL) — ACL/group enforcement
                   └─ withJSONErrors (api) — converts unrouted 404/405 to JSON
                        └─ mux       internal/api/api.go — http.ServeMux, one handler set per resource
```

- **`internal/store`** — the only state. `Store` holds a global space (collections `users`, `organizations`) plus per-org `Org`s. `Org.data` is `collection -> key -> raw JSON []byte` (e.g. `nodes`, `roles`, `acls`, `groups`, `association_users`); `Org.blobs` is `checksum -> bytes` (cookbook file store). Values are stored as canonical JSON so payloads round-trip exactly. Methods: `Get/Put/Create/Delete/Keys`, `PutBlob/Blob/HasBlob/DeleteBlob`.
- **`internal/api`** — all HTTP handlers, one file per resource (`nodes`/generic in `object.go`, `cookbooks.go`, `databags.go`, `policies.go`, `acl.go`, `authz.go`, `association*.go`, `search.go`, `keys.go`, `server_endpoints.go`, …). `api.Handler()` builds the mux; `register<Resource>Routes` registers each.
- **`internal/auth`** — Mixlib signed-header verification/signing (protocol 1.0/1.1/1.3), verified against the real gem.
- **`internal/search`** — in-process Solr-style query engine + Chef document flattener (no external search engine).
- **`internal/repo`** — loads an on-disk chef-repo (objects, data bags, cookbook dirs) into an org at startup.
- `internal/authz`, `cookbook`, `policyfile`, `repoloader`, `router` are **empty placeholder dirs** — ignore them; the real authz/cookbook/policy code is in `internal/api`.

## Conventions

- **Errors are always JSON.** Use `writeError(w, status, msg...)` → `{"error":[...]}`; never `http.Error`. Responses use `writeJSON` / `writeRaw` (`respond.go`). The `withJSONErrors` catch-all guarantees even unrouted 404/405 are JSON.
- **Handler shape:** `org := a.org(w, r)` (writes 404 and returns nil if the org is missing); read path params with `r.PathValue(...)`; resolve the actor (when needed) from context.
- **Authorization gating is opt-in at the api/server layer** (the `EnforceACL` option / `authz_enforce.go`; the library zero value is permissive), but the standalone `cinc-server-ng` binary enforces by default (`--enforce-acls=false` to opt out; `--no-auth` implies off). When enforcing, object creation grants the creator full control via a per-object ACL (`writeCreatorACL`) and a registered client joins the org's `clients` group (`addClientToOrgGroup`) which has create on the nodes container — mirroring real Chef so the standard chef-client bootstrap works. The bootstrap admin (`pivotal`) is a superuser. Don't assume enforcement in handlers.
- **API version negotiation** runs ahead of routing (`withAPIVersion`, `server_endpoints.go`): non-numeric `X-Ops-Server-API-Version` → 400, out-of-range → 406.
- **README prose uses no em dashes.** Use a colon, comma, or parentheses instead. (This applies to `README.md` only, not to code comments or other docs.)
- **Tests:** API-layer tests use `newTestAPI(t)` + `do(t, method, url, body)` (no auth, raw store). Server-layer tests use `startServer(t, Options{})` + `signed(t, srv, …)` (full middleware, real signatures). Note `newTestAPI` does **not** seed default groups/ACLs — only `server.New`/`CreateOrganization` do.

The README status table is the authoritative feature map; package doc comments are accurate. Design specs live in `docs/specs/`.

## Authorization: the two fail-open surfaces

Enforcement can leak in two independent ways, and a change usually has to answer for both. Getting one right proves nothing about the other.

1. **An unclassified route.** `classifyRequest` is an allowlist; a route it does not recognize is *permitted*. `refuseUnclassifiedWrite` closes this for mutating methods (declare a deliberate exception in `openWrites`, with a reason), but unclassified **reads** are still allowed through by design. A read route that should be restricted needs either a case in `classifyRequest` or its own check in the handler — and if you choose the handler, write the check, don't just note it in a comment.
2. **An object with no stored ACL.** `loadACL` falls back to `defaultACL()`, which grants read to `admins`/`users`/`clients` and create/update/delete to `admins`/`users`. Every org member is in `users`, so "no ACL stored" means "every member has CRUD". `grantCreator` only writes a per-object ACL from `createObject` and `createActor`; data bags, cookbooks, artifacts, policies, policy groups, groups and containers are created by dedicated handlers that never call it, and organizations never get one at all.

Other invariants that are easy to violate one half of:

- **ACLs are keyed `"<type>/<name>"` and match actors by bare name.** So an ACL outlives its object unless the delete handler removes it explicitly, and a client and a global user sharing a name are the same principal to `allowedWith` — which is also why `resolveAuth` preferring org clients over global users is load-bearing.
- **Group membership is the union of the group document and the `group_members` rows.** The split is what keeps fleet bootstrap linear. Read it with `groupMembership()`, never from the document alone, and revoke both halves — dropping only the rows leaves a hand-authored or explicitly-written document still naming the actor.
- **Adding an actor to a group grants permission; removing the actor from the org must remove it from the groups.** `association_users` and group membership are read by different code (`orgViewAllowed` vs `actorAllowed`), so a half-revocation looks correct from the membership endpoints.

## Derived indexes and the write stream

`searchIdx` and `groups` are patched from `store.Watch` observers, which run **synchronously on the goroutine performing the write**. So an observer must be cheap, must not write back into the store, and must be safe against the readers of whatever it mutates — a published index is not frozen, and the cache lock only guards *which* index is current, not the contents of one that is. `groupsGen` deliberately does not advance for `group_members` writes (that would restore the quadratic bootstrap), so a rebuild has to be serialized against the observer rather than relying on the generation.

## Backend differences the default tests will not catch

Almost every test runs on the memory backend. These differ under `--storage sqlite`:

- **`Range` slice identity.** The memory backend passes the stored slice; SQLite scans a fresh slice per row, per call. Anything caching on pointer identity silently never hits.
- **`Range` ordering.** SQLite is `ORDER BY key`; the memory backend is map iteration order. Sort if you depend on order.
- **`Tx` isolation.** SQLite is a real transaction; the memory backend snapshots and restores whole maps on rollback, and is not isolated against concurrent writers.
- **Blob and object bytes are copies** on both, but only SQLite pays a real read per `Get` — read amplification shows up in `store.Counts()`.

When a change touches a store read path, ask what it does on both, and reach for `sqlite.Open(t.TempDir()+"/x.db")` in the test if the answer differs.

## Writing a test for an authorization change

Server-layer, with real signatures, is where authz behaviour is worth pinning:

```go
srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
key := []byte(createUser(t, srv, `{"name":"mallory"}`))   // returns chef_key.private_key
code := statusOf(t, signedAs(t, "mallory", key, "GET", srv.URL()+"/users", ""))
```

`srv.ValidatorKey(org)` is the bootstrap key a node registers with — the right actor for "what can someone who only has a validator key do?". Always assert the **baseline denial** before the exploit, or a test can pass because the setup was wrong. `make test` runs `-race`; a race in a derived index only surfaces if the test drives writes and reads concurrently through the real handler.

## Repo notes

- `.claude/worktrees/` holds a full stale copy of the tree. `grep -r` and `find` hit it and return duplicate matches — exclude it.
- `server.test` (a compiled test binary) is checked in at the repo root and should not be.
