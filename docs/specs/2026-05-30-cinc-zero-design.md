# cinc-server-ng — In-Memory Chef Infra Server (Design)

Date: 2026-05-30
Status: Approved — building

## Goal

A fully in-memory Chef Infra Server, written in Go, for use in test pipelines.
Roughly matches `chef-zero` functionality but treats **Policyfiles and policy
groups** as first-class. Real `chef-client` / `knife` / `cinc` / InSpec tooling
should talk to it unmodified.

## Confirmed scope decisions

| Area            | Decision |
|-----------------|----------|
| Authentication  | **Full** Mixlib::Authentication signed-header verification (v1.0 SHA1/RSA + v1.3 SHA256) |
| Search          | **Full Lucene fidelity** via embedded Bleve + Chef expander + Solr→Bleve translation |
| Consumption     | Embeddable Go library **+** standalone binary **+** Docker image |
| Cookbooks       | **Full**: sandbox/checksum flow, blob store, `/cookbooks`, `/cookbook_artifacts`, `/universe` |
| Seeding         | **chef-repo directory loader** (live HTTP API always works inherently) |
| Org model       | **Full multi-org** + org management API |
| Authz (ACLs)    | Structural only — groups/containers/actors stored & returned; **enforcement permissive** by default (hook left for strict mode). The public API PDF has no `/_acl` API. |

## Package layout

```
cinc-server-ng/
  cmd/cinc-server-ng/         # CLI wrapper (flags, signals)
  server/                # public embeddable API: New(opts) *Server; Start/Stop/URL/AdminKey
  internal/router/       # chi router; full Chef API surface
  internal/api/          # one file per resource group
  internal/store/        # Store interface + in-memory impl (org->type->name, RWMutex)
  internal/auth/         # Mixlib signed-header verification, key registry
  internal/authz/        # groups, containers, ACLs (permissive)
  internal/search/       # Bleve index + Chef expander + Solr->Bleve translator
  internal/cookbook/     # sandbox/checksum flow, in-memory blob store
  internal/policyfile/   # policies, revisions, policy_groups
  internal/repoloader/   # chef-repo directory ingestion
  Dockerfile
```

The CLI and Docker image are thin wrappers; all testable logic is in the library.

## Endpoint surface (from the Chef Infra Server API PDF)

- **Root**: `/_status`, `/_stats`, `/license`, `/authenticate_user`,
  `/users` (+ `/users/NAME`, `/users/USER/keys[/KEY]`),
  `/organizations` (+ CRUD), `/universe`
- **Org-scoped** `/organizations/NAME/…`: `clients` (+keys), `nodes`, `roles`
  (+`/environments[/NAME]`), `environments` (+`/cookbooks`,
  `/cookbook_versions`, `/nodes`, `/recipes`, `/roles/NAME`), `data` (+items),
  `cookbooks` (+`_latest`,`_recipes`,`/NAME/VERSION`), `cookbook_artifacts`,
  `sandboxes`, `search` (+`/INDEX`, GET & POST partial), `groups`, `containers`,
  `principals/NAME`, `association_requests`, `users` (membership),
  `updated_since`, `required_recipe`, `policies`, `policy_groups`

### Policyfile write API (not in the public PDF; sourced from chef-zero + chef-client)
- `GET /policies`, `GET/DELETE /policies/NAME`
- `GET/PUT/DELETE /policies/NAME/revisions/REV`, `POST /policies/NAME/revisions`
- `GET /policy_groups`, `GET/DELETE /policy_groups/NAME`
- `GET/PUT/DELETE /policy_groups/NAME/policies/POLICY_NAME`

## Component designs

### Data store
`Store` interface; single `memstore` implementation. Nested maps keyed
`org → type → name`, guarded by `sync.RWMutex`, values stored as canonical
`map[string]any` JSON so client payloads round-trip exactly. Org-scoped
throughout. No persistence; chef-repo loader is the seed path.

### Authentication
Verify `X-Ops-Sign`, `X-Ops-Userid`, `X-Ops-Timestamp`, `X-Ops-Content-Hash`
and chunked `X-Ops-Authorization-N`. Support v1.0 (SHA1/RSA) and v1.3 (SHA256).
Canonicalize request, look up actor public key, RSA-verify, enforce timestamp
skew. Bootstrap admin client+key at `New()`, exposed via `AdminKey()`.

### Authorization
`/groups`, `/containers`, actor model stored & returned faithfully; default org
groups auto-created. ACL enforcement permissive (authenticated ⇒ authorized)
with an `authz.Mode` hook for future strict enforcement.

### Search
On write, flatten objects like chef-server's expander (`key`, `key_value`,
nested `a_b_c`, plus raw doc) and index per `org/index` in in-memory Bleve.
Translate Chef/Solr query syntax → Bleve queries for wildcard/range/boolean/
fuzzy fidelity. POST partial search projects requested attribute paths. Indexes
rebuild from store on load.

### Cookbooks
Full sandbox/checksum flow: `POST /sandboxes` → client `PUT`s file content to a
server-served upload URL → `PUT /sandboxes/ID` commits. Files in in-memory blob
store keyed by MD5. `cookbook_artifacts` share the blob store; Policyfiles pin
to artifact identifiers.

### Policyfiles & policy groups
A policy revision pins `cookbook_locks` to `cookbook_artifacts` identifiers;
pushing a revision into a group is the deploy. `chef-client` with
`policy_name`/`policy_group` pulls the assigned revision.

### chef-repo loader
Walk `nodes/ roles/ environments/ data_bags/<bag>/ policies/ policy_groups/
clients/ cookbooks/ cookbook_artifacts/`; insert into store and index. Matches
`knife upload` on-disk shapes.

### Delivery
- Library: `srv,_ := cinczero.New(cinczero.Options{...}); srv.Start(); defer srv.Stop()` → `srv.URL()`, `srv.AdminKey()`
- CLI: `cinc-server-ng --port 8889 --repo ./repo --org test` writes knife-ready key/config
- Docker: distroless image running the CLI

## Testing
TDD per resource (table-driven endpoint tests). Conformance suite running real
`knife`/`chef-client`/`cinc` against the server in CI. Golden tests for auth
canonicalization and search query translation.

## Build sequence
1. Skeleton: router, store, `_status`, library/CLI scaffold
2. Auth + admin bootstrap
3. CRUD: clients, nodes, roles, environments, data bags
4. Cookbooks + sandboxes + blob store
5. Search (expander + Bleve + translator)
6. Policyfiles + policy groups + cookbook_artifacts
7. Multi-org + org management + users/groups/containers
8. chef-repo loader + Docker + conformance CI

## Out of scope (YAGNI)
Real persistence, ACL deny-enforcement, LDAP/SAML external auth, `/license`
business logic beyond a stub, analytics/reporting, HA.
