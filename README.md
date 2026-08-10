# cinc-server-ng

A lightweight, drop-in alternative to
[Chef Infra Server](https://docs.chef.io/server/), implemented in Go. It speaks
the real Chef Infra Server API and authenticates unmodified `chef-client` /
`knife` / `cinc` clients using genuine
[Mixlib::Authentication](https://github.com/chef/mixlib-authentication) signed
requests. Run it fully **in memory** for instant, disposable test servers, or
back it with **SQLite** for durable state that survives restarts. The same
server scales from a throwaway CI fixture to lightweight production
infrastructure. It ships as a single static binary, with no Ruby runtime and no
external database to operate. Packaged as a minimal container image, it drops
cleanly into modern orchestration such as Kubernetes (a persistent volume for the
SQLite database is all the state it needs).

## Why cinc-server-ng

**Complete API, including Policyfiles.** cinc-server-ng implements the full surface a
real client touches: nodes, roles, environments, clients, users, data bags,
cookbooks, search, authz groups/containers, ACLs, key management, org
association, and multi-org management. Mixlib authentication (v1.0 / 1.1 / 1.3)
is verified byte-for-byte against the real gem, so unmodified `chef-client`,
`knife`, and `cinc` clients just work. **Policyfiles and policy groups are
first-class**, and WebUI-key impersonation lets a console like cinc-console sign
on a user's behalf.

**Fast under fleet load.** Go handles requests concurrently across all cores,
with none of the global-lock contention that single-threaded Ruby servers hit.
In-memory state keeps disk out of the request path, and the hot paths for
search, auth, and object access are optimized to stay fast with large node
counts and many concurrent clients.

**One binary, no Ruby.** A single static Go binary (or Docker image) with no
Ruby, no gems, no native extensions. Drop it in and point your clients at it, or
embed it directly in Go tests as a library.

**Tiny attack and patch surface.** A production Chef Infra Server is a large
multi-service stack (Erlang, Ruby, PostgreSQL, a search service, a message
queue, a reverse proxy) built from thousands of dependencies to track and patch.
cinc-server-ng's **only third-party dependencies are the pure-Go SQLite driver and
its support libraries**, and those only run when you choose the durable backend;
everything else is the Go standard library. No extra services to harden, no
runtime in the image, and the distroless/scratch container has no shell to
exploit, all while still authenticating with the genuine Mixlib protocol.

## Use as a Go library

```go
import "github.com/tas50/cinc-server-ng/server"

srv, _ := server.New(server.Options{Orgs: []string{"test"}})
_ = srv.Start()
defer srv.Stop(context.Background())

baseURL  := srv.URL()                 // http://127.0.0.1:NNNNN
adminKey := srv.AdminKey()            // PEM private key for the admin user
adminID  := srv.AdminName()           // "pivotal"
// Sign requests with auth.SignRequest, or point knife/chef-client at baseURL.
```

For tests that don't want to sign requests, set `Options{DisableAuth: true}`.

As a Go library the zero value is permissive: ACLs and group membership are
stored but not enforced, so every authenticated actor is permitted and test
pipelines stay friction-free. To exercise authorization-dependent behavior
(requests a real server answers with `403 Forbidden`), set
`Options{EnforceACL: true}`. (The standalone `cinc-server-ng` binary takes the
opposite, production-leaning default: it **enforces** unless told otherwise; see
"Use as a binary".) Enforcement matches a real Chef Infra Server: the creator of
an object is granted full control of it, a registered client joins the org's
`clients` group and can create and manage its own node, and the standard
chef-client bootstrap works end to end. It honors the default groups/ACLs seeded
at org creation, resolves actor membership through nested groups, and checks
authentication → existence → authorization in that order (so a missing object
reports `404`, not `403`). Enforcement covers the
org-scoped object endpoints (nodes, roles, data bags, cookbooks, groups,
containers, …), the org's own `_acl`, and the global actor endpoints: the
`/users` collection is superuser-only (a user may still read or update its own
record), and `/users/<name>/_acl` is governed by the grant permission on that
user. The bootstrap admin is a superuser and bypasses ACLs, mirroring Chef's
`pivotal`. `EnforceACL` requires authentication and cannot be combined with
`DisableAuth`.

## Use as a binary

```sh
go build -o cinc-server-ng ./cmd/cinc-server-ng
./cinc-server-ng --addr 127.0.0.1:8889 --orgs test --key-out admin.pem
```

The binary **enforces ACLs by default**. A freshly bootstrapped org behaves like
a real Chef Infra Server, and the standard chef-client lifecycle (a validator
registers a client, which then creates and updates its own node) works out of the
box. Pass `--enforce-acls=false` for a permissive server where every authenticated
actor is allowed. Pass `--no-auth` to disable signature verification entirely
(this also disables enforcement, since it needs an authenticated actor); asking
for `--no-auth` together with an explicit `--enforce-acls` is a contradiction and
errors out.

Pass `--repo ./chef-repo` to preload an on-disk chef-repo (its `nodes/`,
`roles/`, `environments/`, `clients/`, `policies/`, `policy_groups/`,
`data_bags/`, and `cookbooks/`) into the first org at startup, mirroring
`knife upload`. Files under `policies/` are Policyfile locks (named
`<name>-<revision>.json`); each loads as a policy revision keyed by its
`revision_id`, and `policy_groups/<group>.json` pins policies to a group.
Cookbook directories are checksummed into the blob store and served with a
synthesized manifest.

## Persistence and storage

By default cinc-server-ng keeps all state in memory: the ephemeral "zero" experience
that needs no disk and resets on exit. To persist state across restarts, point it
at a SQLite database:

```sh
./cinc-server-ng --storage sqlite --db ./cinc.db
```

`--storage` accepts `memory` (default) or `sqlite`; `--storage sqlite` requires
`--db <path>`. Both flags also read from the environment
(`CINC_SERVER_NG_STORAGE`, `CINC_SERVER_NG_DB`), which is handy in containers. SQLite uses
the pure-Go [`modernc.org/sqlite`](https://pkg.go.dev/modernc.org/sqlite) driver,
so the static binary and `scratch`/`distroless` images keep working with
`CGO_ENABLED=0`.

**High write throughput.** Concurrently-pending writes are batched into shared
transactions (group commit), amortizing SQLite's per-commit cost. Under
concurrent fleet load this is worth roughly 2.5x write throughput and about an
order of magnitude in tail latency (p99 5.06ms → 488µs on a 16-writer
workload). It costs a few microseconds on a write that finds no batch to join,
so a lone serialized writer — a CI fixture doing one thing at a time — can turn
it off with `--sqlite-group-commit=false`.

The storage layer is pluggable behind a small `store.Backend` interface
(`(org, collection, key) → bytes` plus a blob store), so PostgreSQL/RDS can be
added later as a driver swap rather than a rewrite.

**Restarts.** A SQLite-backed server is safe to stop and restart on the same
database: it reloads existing organizations and data instead of recreating them,
and the bootstrap admin/validator keys are persisted so the key written by
`--key-out` keeps authenticating after a restart. (The in-memory backend always
starts fresh.)

**Backups** are delegated to the backend; cinc-server-ng ships no backup subsystem.
For SQLite, take a consistent online copy while the server runs:

```sh
sqlite3 cinc.db "VACUUM INTO 'backup.db'"
```

or simply copy the `.db` file while the server is stopped. (A future Postgres/RDS
backend would use `pg_dump` or managed snapshots.)

**Upgrades** are forward-only: the SQLite schema carries a `schema_migrations`
version and any pending migrations are applied automatically at startup, so
upgrading the binary against an existing database just works. Because object
bodies are stored as opaque JSON, the schema is tiny and rarely changes.
Downgrading the binary against a newer database is not supported.

## Metrics

`GET /_stats` reports what the server is doing. It requires authentication, like
any other API route, and answers in two formats:

```sh
# JSON metric families (the default)
curl -s .../_stats

# Prometheus text exposition, for a scraper
curl -s -H 'Accept: text/plain' .../_stats
```

What it exposes is chosen to answer the questions that decide whether the server
is keeping up with a fleet:

| Metric | Why it matters |
| --- | --- |
| `cinc_server_ng_http_requests_total{outcome}` | Request rate split by `2xx`/`3xx`/`4xx`/`5xx`, with `401` broken out — rejected credentials mean something different from bad requests. |
| `cinc_server_ng_http_request_duration_seconds` | Latency as a histogram. A mean hides the stalls; the buckets do not. |
| `cinc_server_ng_store_reads_total` / `_writes_total` / `_deletes_total` | Read amplification is what limits throughput on a durable backend — the check-in path costs several reads per write, so watch the ratio, not just the totals. |
| `cinc_server_ng_store_scans_total` | Collection scans. A rising rate means work that grows with the size of your data. |
| `cinc_server_ng_search_queries_total{resolution}` | `indexed` vs `scanned`. A query the planner cannot handle silently falls back to scanning the whole collection; this is how you find out. |
| `cinc_server_ng_search_indexed_documents` | Documents held in the inverted search indexes. |
| `cinc_server_ng_uptime_seconds`, `cinc_server_ng_goroutines`, `cinc_server_ng_heap_bytes` | Process health. |

Instrumentation is measured rather than assumed: it costs about 150ns per
request, which is ~3% of the cheapest possible request (no auth, in-memory) and
is not measurable on a realistic authenticated one.

Embedding programs can read the same numbers directly with `srv.Metrics()`
instead of going through HTTP.

## Docker

```sh
docker build -t cinc-server-ng .
docker run -p 8889:8889 cinc-server-ng
```

Release images are published to GitHub Container Registry:

```sh
docker run -p 8889:8889 ghcr.io/tas50/cinc-server-ng:latest
```

To persist state across container restarts, mount a volume and point SQLite at
it (a single static binary on a `scratch`/`distroless` base, so the volume is the
only stateful piece):

```sh
docker run -p 8889:8889 -v cinc-data:/data \
  ghcr.io/tas50/cinc-server-ng:latest --storage sqlite --db /data/cinc.db
```

## Compatibility with Chef Infra Server

Fidelity is the point of this project, so it is tested three ways, each
answering a different question.

**Unit and API tests** (`make test`) check cinc-server-ng against its own idea of
correct. Fast, broad, and unable to tell you that idea is wrong.

**Conformance** (`make conformance`) drives the real `knife` CLI against an
in-process server, so a genuine signed-request lifecycle has to work end to end
— reads, writes, search, policyfiles, authorization, and the cookbook
sandbox/upload flow. It runs with ACL enforcement on, matching what the binary
ships with; testing the permissive configuration would leave every
authorization path unexercised by a real client. CI sets
`CINC_SERVER_NG_REQUIRE_CONFORMANCE=1`, which turns "knife is unusable" from a skip
into a failure: a conformance job that quietly executes nothing while reporting
success is worse than no job at all.

**Differential** (`make differential`) issues the same requests to cinc-server-ng and
to a real Chef Infra Server and diffs the responses. This is the only suite that
can find a response we have confidently got wrong, because clients are lenient —
`knife` will accept a missing field, an extra field, or the wrong type, so "the
client did not error" says little about fidelity. It needs a full Chef Infra
Server, so it runs on demand and weekly rather than per-PR (see
`.github/workflows/differential.yml`).

Responses cannot match byte for byte — different hosts, different generated
identifiers, different keys — so they are normalized first. Those rules are kept
deliberately narrow, in `differential/normalize.go`: every rule erases a
difference, so an over-broad one hides the bugs the suite exists to find. A
value is only replaced when it is unequal *by construction*.

Anything left over is either a bug or an accepted deviation recorded in
`differential/known.go` with a reason. **That list, not a percentage, is the
compatibility statement.** "100% compatible" is not a claim anyone can check;
"here are the ways we differ, and why each is acceptable" is — and an
unexplained difference fails the run, so the list only grows deliberately.

## Development

Building, testing, the `knife` conformance suite, the dev fixtures
(`dev/test-repo` and the SQLite database `make dev-db` bakes from it), running a
fully-seeded local server, the test account logins, and connecting a management
console such as cinc-console are all covered in
**[`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md)**. A quick taste:

```sh
make test             # go test ./... -race -cover
make run-dev          # in-memory, no auth, pre-loaded with the dev/test-repo seed
make run-dev-sqlite   # a durable SQLite copy of the same data, auth on (for cinc-console)
```

## License

cinc-server-ng is licensed under the [Business Source License 1.1](LICENSE).
