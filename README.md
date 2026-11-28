# cinc-server-ng

A fast, drop-in replacement for **both**
[Chef Infra Server](https://docs.chef.io/server/) and
[chef-zero](https://github.com/chef/chef-zero), implemented in Go: one binary
that covers the throwaway local test server *and* full-scale production. It
speaks the real Chef Infra Server API and authenticates unmodified `chef-client`
/ `knife` / `cinc` clients using genuine
[Mixlib::Authentication](https://github.com/chef/mixlib-authentication) signed
requests. Run it fully **in memory** for instant, disposable test servers (the
job chef-zero does, without the Ruby), or back it with **SQLite** for durable
state that survives restarts and serves a production fleet. The same server
spans a CI fixture and the fleet it ships to, with no change of software. It
is a single static binary, with no Ruby runtime and no external database to
operate. Packaged as a minimal container image, it drops cleanly into modern
orchestration such as Kubernetes (a persistent volume for the SQLite database is
all the state it needs).

## Why cinc-server-ng

**Complete API, including Policyfiles.** cinc-server-ng implements the full surface a
real client touches: nodes, roles, environments, clients, users, data bags,
cookbooks, search, authz groups/containers, ACLs, key management, org
association, and multi-org management. Mixlib authentication (v1.0 / 1.1 / 1.3)
is verified byte-for-byte against the real gem, so unmodified `chef-client`,
`knife`, and `cinc` clients just work. **Policyfiles and policy groups are
first-class**, and WebUI-key impersonation lets a console like cinc-console sign
on a user's behalf.

**One server for local testing and production.** chef-zero, the in-memory Ruby
server behind `chef-client --local-mode`, `knife -z`, and Test Kitchen's
`chef_zero` provisioner, is deliberately a test-only tool, and a real Chef Infra
Server is a multi-service stack you would never stand up in a unit test. This is
one binary for both. It covers chef-zero's disposable, start-it-and-throw-it-away
job (in-memory backend, ~100 ms boot, embeddable directly in Go tests) and then
keeps going: it verifies Mixlib signatures rather than trusting the caller,
enforces ACLs so `403`-dependent behavior is exercised instead of assumed, treats
Policyfiles as first-class, persists to SQLite when the state must outlive the
process, and exposes metrics for running it under real fleet load. Measured on
one machine, it serves ~50-160x chef-zero's throughput at concurrency 10. Against
Chef Infra Server, with durable SQLite storage, it serves ~18-37x the throughput
on object reads and writes and ~6-8x on search, at a peak of 37 MiB of memory
where Chef Infra Server idles at 5.2 GiB ([benchmarks](docs/benchmarks/v0.15.0.md)).
The practical payoff:
the server you test against and the server your fleet checks in to are the same
software, so "passes against chef-zero, breaks against the real server" stops
being a category of bug.

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
import "github.com/cinc-project/cinc-server-ng/server"

srv, _ := server.New(server.Options{Orgs: []string{"test"}})
_ = srv.Start()
defer srv.Stop(context.Background())

baseURL  := srv.URL()                 // http://127.0.0.1:NNNNN
adminKey := srv.AdminKey()            // PEM private key for the admin user
adminID  := srv.AdminName()           // "pivotal"
// Sign requests with auth.SignRequest, or point knife/chef-client at baseURL.
```

For tests that don't want to sign requests, set `Options{DisableAuth: true}`.
This is the chef-zero-in-your-test-suite pattern with no Ruby, no gems, and no
subprocess: the server runs inside your test binary and disappears with it.

As a Go library the zero value is permissive: ACLs and group membership are
stored but not enforced, so every authenticated actor is permitted and test
pipelines stay friction-free. To exercise authorization-dependent behavior
(requests a real server answers with `403 Forbidden`), set
`Options{EnforceACL: true}`. (The standalone `cinc-server-ng` binary takes the
opposite, production-leaning default: it **enforces** unless told otherwise; see
"Use as a binary".) Enforcement matches a real Chef Infra Server: a new object
of any kind (node, role, environment, client, data bag, cookbook, cookbook
artifact, policy, policy group or group) starts from its container's ACL (so
narrowing a container narrows what is created in it afterwards), its creator
is granted full control of it (except a validator, which holds nothing on the
clients it registers and cannot create another validator; unlike Chef Infra
Server, only an org admin or the superuser may change a client's `validator`
flag, and `<org>-validator` counts as a validator whatever its flag), a new container
holds only its creator, a new group starts with no members (they are added
with a `PUT`), a registered client holds its own record and keys, joins the
org's `clients` group and can create and manage its own node, and the
standard chef-client bootstrap works end to end. The default groups and the
ACLs on each container, group and the org itself follow erchef's org creation policy (so a
plain client can read the nodes, roles, environments, cookbooks, data bags and
policies it converges from, but not list the org's clients or groups). Making
a new object of any kind, including a new cookbook, cookbook artifact, policy
or policy group, takes create on its container, and pushing a policy to a group
is checked on both the policy and the group. Uploading cookbook files (creating
and committing a sandbox) takes create on the `sandboxes` container, which by
default only admins and users hold, so a client (the validator included)
cannot store files. Unlike Chef Infra Server, only the superuser may delete one
of the default containers (`clients`, `nodes`, `cookbooks`, ...), whose ACLs
every create in the org is checked against; containers created with
`POST /containers` delete as before. Objects loaded from a chef-repo or state directory, or
stored by an older version without such an ACL, are given it at startup. A user
who is not a member of the org (never invited, or removed from it) is refused
every request under `/organizations/<org>` with `403`, whatever ACLs or groups
still name them; clients and the superuser are exempt. It
resolves actor membership through nested groups, and checks
authentication → org membership → existence → authorization in that order (so
a missing object reports `404` to a member, not `403`). Enforcement covers the
org-scoped object endpoints (nodes, roles, data bags, cookbooks, groups,
containers, …), the org's own ACL (`/organizations/<org>/organizations/_acl`,
erchef's path), and the global actor endpoints: the
`/users` collection is superuser-only (a user may still read or update its own
record), and `/users/<name>/_acl` is governed by the grant permission on that
user. The bootstrap admin is a superuser and bypasses ACLs, mirroring Chef's
`pivotal`.

Members of the global `server-admins` group hold what Chef Infra Server grants
it: they may list and create users, and read, update and delete any user that
is not a superuser, including its keys. Going beyond Chef Infra Server (where
only the superuser can), they may also create organizations with
`POST /organizations`, and the creator becomes a member of the new org and of
its `users` and `admins` groups, so it can run the org and invite others
without the superuser's key. (An org the superuser creates gets no such member,
as on Chef.) They get nothing more: no user `_acl` access, no access to an
organization they did not create, and no way to set a user's superuser flag.
Chef manages membership with `chef-server-ctl grant-server-admin-permissions`;
here the superuser uses `/_cinc/server_admins`, a cinc-server-ng route with no
Chef equivalent (for example `knife raw -m PUT /_cinc/server_admins/alice`).
`GET` lists the members (superusers included), `PUT /<user>` adds one and
`DELETE /<user>` removes one. Deleting a user also removes it from the group. `EnforceACL` requires authentication and cannot be combined with
`DisableAuth`. Whether or not ACLs are enforced, an authenticated actor other
than the superuser cannot take the `admins` group off a grant ACE that lists
it: the write is refused with `403`, as erchef refuses it.
As in erchef, `GET .../_acl?detail=granular` reports each permission's actors
split into `users` and `clients`, and `PUT .../_acl/<perm>` accepts that split
form (with `actors` set to `[]`). An org client and a user may share a name,
as on Chef Infra Server (a node's hostname often matches a username). They are
separate actors: a request authenticates as whichever one's key verifies, a
grant to one never applies to the other, and a merged-form `PUT` naming a client
that is also a member user is refused with `422` until the split form says which.
ACLs stored by older versions are converted to this typed form at startup.
A `PUT` whose body names a client, user or group other than its path renames
it, answering `201` with a `Location` (`409` if the name is taken), as erchef
does; an organization cannot be renamed. Unlike Chef Infra Server, the org's
default groups and its `<org>-validator` client cannot be renamed either
(`400`), since cinc-server-ng finds them by name. The renamed object keeps its ACL, its
group memberships and every ACL entry naming it (and a user its keys, org
memberships and invitations), and the old name keeps nothing, so an object
later created under it starts fresh. As on Chef Infra Server, a renamed client
loses its default key until one is added.

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

Request bodies are capped as on Chef Infra Server, and one over its cap gets a
`413`. `--max-request-size` (default `2000000` bytes, the packaged
`opscode_erchef['max_request_size']`) caps API requests; `--max-file-size`
(default 250 MiB, nginx's `client_max_body_size` there) caps cookbook files
uploaded to the file store. A negative value removes a cap. The server checks
a request's signing headers, clock skew, declared length and actor before it
reads the body, so a request it refuses from its headers costs no body read.
A body must also arrive in time: `--body-timeout` (default `2m`) is the most an
API request body may take, and the longest a cookbook file upload may go
without sending data. `--max-connections` (default no limit) caps the
connections held open at once. See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

A fresh server has only the key-based superuser (`pivotal`), so nobody can log
in to a web console such as
[cinc-console](https://github.com/cinc-project/cinc-console), which signs users
in with a password. `--bootstrap-user` creates that first human admin at
startup: a password user in the global `server-admins` group and a member and
admin (`users` and `admins` groups) of every `--orgs` org. The password comes
from `--bootstrap-password-file` (one trailing newline is dropped) or the
`CINC_SERVER_NG_BOOTSTRAP_PASSWORD` environment variable, never from a flag, so
it stays off the command line. `--bootstrap-email` sets the user's email
(default `<user>@localhost.localdomain`). A one-command production start:

```sh
cinc-server-ng --storage sqlite --db /data/cinc.db --orgs myorg \
  --webui-key webui_pub.pem --key-out /data/pivotal.pem \
  --bootstrap-user alice --bootstrap-password-file /run/secrets/alice
```

`--key-out` is still how you get `pivotal`'s key. On a restart against the same
database the user is left as it is (its password and profile may have been
changed since), and only its memberships are ensured, including in any org newly
added to `--orgs`. `--init` applies it too, so a pre-baked database can ship with
its console admin. The memberships go only to the user the bootstrap created: if
that user was deleted or renamed and someone else has since taken the name, the
server starts without granting them anything and prints a warning.

Pass `--repo ./chef-repo` to preload an on-disk chef-repo (its `nodes/`,
`roles/`, `environments/`, `clients/`, `policies/`, `policy_groups/`,
`data_bags/`, and `cookbooks/`) into the first org at startup, mirroring
`knife upload`. Files under `policies/` are Policyfile locks (named
`<name>-<revision>.json`); each loads as a policy revision keyed by its
`revision_id`, and `policy_groups/<group>.json` pins policies to a group.
Cookbook directories are checksummed into the blob store and served with a
synthesized manifest.

## Persistence and storage

By default cinc-server-ng keeps all state in memory: the ephemeral chef-zero
experience that needs no disk and resets on exit. To persist state across
restarts, and to run the same binary for a production fleet, point it at a
SQLite database:

```sh
./cinc-server-ng --storage sqlite --db ./cinc.db
```

`--storage` accepts `memory` (default) or `sqlite`; `--storage sqlite` requires
`--db <path>`. Both flags also read from the environment
(`CINC_SERVER_NG_STORAGE`, `CINC_SERVER_NG_DB`), which is handy in containers. SQLite uses
the pure-Go [`modernc.org/sqlite`](https://pkg.go.dev/modernc.org/sqlite) driver,
so the static binary and `scratch`/`distroless` images keep working with
`CGO_ENABLED=0`.

**File permissions.** The database holds user passwords, actor keys and data
bags, so it is owner-only: a new database and its `-wal` and `-shm` files are
created with mode `0600`, whatever the umask. On open, group and other
permissions are removed from an existing database and its sidecar files, so a
database created by an earlier version is tightened on upgrade. If the server
cannot do that (it does not own the file), it refuses to start rather than run
with a readable database; `chown` the file to the server's user.

**High write throughput.** Concurrently-pending writes are batched into shared
transactions (group commit), amortizing SQLite's per-commit cost. Under
concurrent fleet load this is worth roughly 2.5x write throughput and about an
order of magnitude in tail latency (p99 5.06ms → 488µs on a 16-writer
workload). It costs a few microseconds on a write that finds no batch to join,
so a lone serialized writer (a CI fixture doing one thing at a time) can turn
it off with `--sqlite-group-commit=false`.

The storage layer is pluggable behind a small `store.Backend` interface
(`(org, collection, key) → bytes` plus a blob store), so PostgreSQL/RDS can be
added later as a driver swap rather than a rewrite.

**Object times.** As Chef Infra Server does, every object records when it was
created and last changed, and which user or client changed it last. These are
kept beside the object, not in it, so the documents clients read and write back
are unchanged. The API does not return them yet. Objects stored before an upgrade
to this version have no recorded creation time.

**Restarts.** A SQLite-backed server is safe to stop and restart on the same
database: it reloads existing organizations and data instead of recreating them,
and the bootstrap admin/validator keys are persisted so the key written by
`--key-out` keeps authenticating after a restart. (The in-memory backend always
starts fresh.)

**Backups** are delegated to the backend; cinc-server-ng ships no backup subsystem.
For SQLite, any of these gives a consistent copy:

- **Online, with the `sqlite3` CLI** on a machine that can open the database
  file:

  ```sh
  sqlite3 cinc.db "VACUUM INTO 'backup.db'"
  ```

  The container image has no shell and no `sqlite3`, so in Docker or
  Kubernetes run this from the host against the volume's files, or from a
  sidecar or job that mounts the same volume.
- **A filesystem or volume snapshot** (ZFS, LVM, EBS, a CSI `VolumeSnapshot`)
  taken while the server runs. A snapshot is crash-consistent, and SQLite
  recovers from it on the next open, the same as after a power loss. It must
  capture the `.db`, `-wal` and `-shm` files together, in one snapshot.
- **A file copy with the server stopped.** Copying the `.db` file of a running
  server is not safe: recent writes may only be in its `-wal` file.

(A future Postgres/RDS backend would use `pg_dump` or managed snapshots.)

**Upgrades** are forward-only: the SQLite schema carries a `schema_migrations`
version and any pending migrations are applied automatically at startup, so
upgrading the binary against an existing database just works. Because object
bodies are stored as opaque JSON, the schema is tiny and rarely changes.
Downgrading the binary against a newer database is not supported.

**Passwords** (the ones `authenticate_user` checks) are stored as salted
PBKDF2-HMAC-SHA256 hashes, never in plain text. Databases written by earlier
versions held them in plain text; the first start on such a database hashes
them in place. SQLite can keep the old values in free pages and the WAL until
they are reused, so after that first start, stop the server and run
`sqlite3 cinc.db VACUUM` to clear them.

## Metrics

`GET /_stats` reports what the server is doing. As on Chef Infra Server, it is
protected by HTTP Basic auth rather than a signed request (a valid API key is not
enough), and answers in two formats:

```sh
# JSON metric families (the default)
curl -s -u "statsuser:$STATS_PASSWORD" .../_stats

# Prometheus text exposition, for a scraper
curl -s -u "statsuser:$STATS_PASSWORD" -H 'Accept: text/plain' .../_stats
curl -s -u "statsuser:$STATS_PASSWORD" '.../_stats?format=text'
```

The JSON is Chef Infra Server's shape, so a client written for it decodes it
unchanged: every number is a string, `labels` is an object (left out when a
metric has none), and a histogram's `sample_sum`, `sample_count` and `bucket`
list sit on its metric. `?format=json` or `?format=text` overrides `Accept`, and
any other `format` is a 406.

The user defaults to `statsuser`, Chef Infra Server's, and is set with
`--stats-user` (or `CINC_SERVER_NG_STATS_USER`). Set the password with
`--stats-password` or, to keep it out of the process list,
`CINC_SERVER_NG_STATS_PASSWORD`. There is deliberately no fixed default password,
since one published in this repository would protect nothing: when none is set,
the server generates a random one at startup and prints it in the startup banner,
much as Chef Infra Server generates its `stats_password` at install. Missing or
wrong credentials get a 401 with a `WWW-Authenticate: Basic` challenge. With
`--no-auth`, `/_stats` is open like every other route. Embedding programs set
`Options.StatsUser`/`Options.StatsPassword` and read the effective pair with
`srv.StatsCredentials()`.

What it exposes is chosen to answer the questions that decide whether the server
is keeping up with a fleet:

| Metric | Why it matters |
| --- | --- |
| `cinc_server_ng_http_requests_total{outcome}` | Request rate split by `2xx`/`3xx`/`4xx`/`5xx`, with `401` broken out, because rejected credentials mean something different from bad requests. |
| `cinc_server_ng_http_request_duration_seconds` | Latency as a histogram. A mean hides the stalls; the buckets do not. |
| `cinc_server_ng_store_reads_total` / `_writes_total` / `_deletes_total` | Read amplification is what limits throughput on a durable backend: the check-in path costs several reads per write, so watch the ratio, not just the totals. |
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
docker run -p 8889:8889 ghcr.io/cinc-project/cinc-server-ng:latest
```

To persist state across container restarts, mount a volume and point SQLite at
it (a single static binary on a `scratch`/`distroless` base, so the volume is the
only stateful piece):

```sh
docker run -p 8889:8889 -v cinc-data:/data \
  ghcr.io/cinc-project/cinc-server-ng:latest --storage sqlite --db /data/cinc.db
```

The image defines a `HEALTHCHECK` that runs `cinc-server-ng healthcheck`, which
probes `/_status` on `127.0.0.1:8889` and exits non-zero unless it answers 200.
If you change the listen port, override the check with `--addr` (for example
`--health-cmd "/cinc-server-ng healthcheck --addr 127.0.0.1:9000"`). The same
subcommand works as a Kubernetes `exec` probe.

The container runs with a read-only root filesystem and no capabilities. A
hardened Docker Compose example is in
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md#docker-compose-hardened).

## TLS and load balancers

cinc-server-ng serves HTTPS itself, so no proxy is required:

```sh
./cinc-server-ng --addr 0.0.0.0:443 --tls-cert server.crt --tls-key server.key
```

Send `SIGHUP` after renewing the certificate and it is reloaded without a
restart (and, on the memory backend, without losing state). It also works
behind a reverse proxy or load balancer that terminates TLS: returned URLs
follow the `Host` and `X-Forwarded-Proto` headers, or a fixed `--external-url`
when the proxy rewrites them. `GET /_status` is the health check, and
`--shutdown-delay` drains the instance (health check failing, requests still
served) before it stops. Run a single active instance, since search and
authorization indexes live in the process.
**[`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md)** has nginx, Caddy, AWS and
Docker setups and the details that matter behind a proxy.

## Compatibility with Chef Infra Server

Fidelity is the point of this project, so it is tested three ways, each
answering a different question.

**Unit and API tests** (`make test`) check cinc-server-ng against its own idea of
correct. Fast, broad, and unable to tell you that idea is wrong.

**Conformance** (`make conformance`) drives the real `knife` CLI against an
in-process server, so a genuine signed-request lifecycle has to work end to end:
reads, writes, search, policyfiles, authorization, and the cookbook
sandbox/upload flow. It runs with ACL enforcement on, matching what the binary
ships with; testing the permissive configuration would leave every
authorization path unexercised by a real client. CI sets
`CINC_SERVER_NG_REQUIRE_CONFORMANCE=1`, which turns "knife is unusable" from a skip
into a failure: a conformance job that quietly executes nothing while reporting
success is worse than no job at all.

**Differential** (`make differential`) issues the same requests to cinc-server-ng and
to a real Chef Infra Server and diffs the responses. This is the only suite that
can find a response we have confidently got wrong, because clients are lenient:
`knife` will accept a missing field, an extra field, or the wrong type, so "the
client did not error" says little about fidelity. It needs a full Chef Infra
Server, so it runs on demand and weekly rather than per-PR (see
`.github/workflows/differential.yml`).

Responses cannot match byte for byte (different hosts, different generated
identifiers, different keys), so they are normalized first. Those rules are kept
deliberately narrow, in `differential/normalize.go`: every rule erases a
difference, so an over-broad one hides the bugs the suite exists to find. A
value is only replaced when it is unequal *by construction*.

Anything left over is either a bug or an accepted deviation recorded in
`differential/known.go` with a reason. **That list, not a percentage, is the
compatibility statement.** "100% compatible" is not a claim anyone can check;
"here are the ways we differ, and why each is acceptable" is, and an
unexplained difference fails the run, so the list only grows deliberately.

One deviation is a security choice rather than a limitation: **every failed
authentication gets the same 401 body.** Chef Infra Server answers a request
naming an unknown user or client with "Failed to authenticate as '<name>'..."
but a bad signature from a real one with "Invalid signature for user or client
'<name>'", so anyone who can reach it, holding no credential, can list which
user and node names exist. cinc-server-ng answers both (and an actor whose keys
have all expired, and a failed web-UI request) with the first message, which
echoes only the name the caller sent, and logs the specific reason on the
server. Clients act on the 401 status, not the text, so nothing that works
against Chef Infra Server stops working.

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

cinc-server-ng is licensed under the [Apache License 2.0](LICENSE).
