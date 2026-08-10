# dev/test-repo — a ready-to-run cinc-server-ng server state

This directory is a **full server-state** fixture: a populated `acme`
organization plus the global users and authz group that a plain chef-repo
can't express. Boot a realistic dev/demo server from it with:

```sh
make run-dev
# equivalently:
cinc-server-ng --no-auth --state dev/test-repo --key-out dev-admin.pem
```

It is loaded by the experimental `--state` flag (`server.Options.StatePath`),
which is a superset of `--repo`: it hydrates global users, every organization,
and each org's chef-objects **plus** authz groups. Data is read from disk at
runtime — nothing is embedded in the binary.

## Web login

`tim` is seeded with a password so a management console (e.g. cinc-console) has
a ready login. Run **with auth on** (not `--no-auth`) so the console's
webui-signed `authenticate_user` is exercised:

```sh
cinc-server-ng --state dev/test-repo --key-out webui.pem   # admin key doubles as the webui key
```

| user | password | access | notes |
| ---- | -------- | ------ | ----- |
| `tim` | `tim123` | **org admin** (acme `admins` group) | full read/write/grant; logs in via `authenticate_user` |
| `jack` | _(none)_ | regular member (acme `users` group) | read access, no admin/grant; has a key but no web password |
| `pivotal` | _(none)_ | global superuser | bootstrap admin, key-only, bypasses ACLs |

Access levels mirror real Chef: `tim` is a full org admin (the fixture
equivalent of `org-user-add acme tim --admin`), while `jack` is a plain member
the loader adds to the `users` group. Under ACL enforcement the console acts as
the logged-in user, so `tim` can edit everything and `jack` can only browse.

Passwords are stashed out-of-band on load, mirroring `POST /users`: the
`password` field is moved into the `passwords` collection and stripped from the
stored user record, so it is never returned by the API. As elsewhere in
cinc-server-ng the password is kept in memory as-is rather than hashed.

## Layout

```
dev/test-repo/
  users/                       global users: tim, jack
  organizations/
    acme/
      nodes/                   107 nodes (see "Fleet" below)
      roles/                   base, web, database, cache, loadbalancer,
                               monitoring, app, ci
      environments/            production, staging, development
                               (each with default/override attributes and
                               cookbook version pins)
      cookbooks/               app, chef-client, haproxy, jenkins, nginx,
                               postgresql, prometheus, redis (one small
                               version each, covering every run-list recipe)
      policies/                web-app-1.0.0, database-1.0.0 (Policyfile locks)
      policy_groups/           production, staging (pin both policies @ 1.0.0)
      data_bags/               users (deploy, ops, jenkins), secrets
                               (postgresql, redis, jenkins), apps (webapp, api)
      groups/                  devs (authz group)
      members.json             org membership: tim, jack
```

`members.json` associates global users with the org (its `association_users`),
so they appear under `GET /users/<name>/organizations` and a console's org
picker. Each entry may be a bare `"username"` or an object shaped
`{"username":…}` / `{"user":{"username":…}}` (knife-ec-backup style).

`--state` loads each org's `nodes/ roles/ environments/ clients/ policies/
policy_groups/ data_bags/ cookbooks/` through the same loader `--repo` uses,
then layers on `users/` (global) and per-org `groups/`.

## Fleet

107 nodes spanning three environments and run-list (role-based), Policyfile
(policy-based), and unconfigured management:

- **production** (42) — web (×15), app (×8), database (×8), cache (×5),
  loadbalancer (×3), monitoring (×3)
- **staging** (20) — web (×6), app (×5), database (×4), cache (×2), ci (×3)
- **development** (18) — web (×5), app (×3), database (×3), bare boxes (×4),
  Windows boxes (×3)
- **policy-based** (19) — pinned to the `web-app` / `database` policies via the
  `production` and `staging` policy groups (`chef_environment` `_default`, as
  real policy nodes use)
- **unconfigured** (8) — `unassigned-01`…`08`, freshly-bootstrapped boxes with
  **no run-list and no policy**, sitting in the `_default` environment as a real
  node does before it is assigned work

Run-lists reference only roles that exist here, and policy nodes reference only
policies pinned in their group — the `internal/state` seed test enforces that
there are no dangling references. Each node carries a unique `ipaddress` and
`macaddress`; the original 24 use the low `10.0.0.x` range, the rest `10.0.1.x`+.

### Client version drift

The fleet models a realistic upgrade in progress: **88 nodes run the current
`cinc-client` / `chef-client` 19.3.14**, while ~10% (11 nodes) lag on a spread
of older real releases (chef 13.12.14 through 18.4.12) across every environment.
This exercises "who's behind?" reporting and search. The version lives in
`automatic.chef_packages.chef.version` and is stamped independently of the
platform fingerprint below.

### Last check-in

Every node's `automatic.ohai_time` is a recent timestamp, randomly splayed
within a one-hour window, so the fixture reads as an active fleet that has all
reported in lately rather than a stale snapshot. The splay is derived
deterministically from each node's name, so the committed state is reproducible.

## Node automatic attributes — fauxhai provenance

Each node's `automatic` attributes are derived from real [fauxhai][] Ohai
dumps (`lib/fauxhai/platforms/<platform>/<version>.json`), trimmed to the
commonly-used subset (platform/kernel/os, cpu, memory, virtualization) so the
fixture stays a few KB per node. Per-node identity (`fqdn`, `hostname`,
`ipaddress`, `macaddress`), the client version (see "Client version drift"), and
the last check-in (see "Last check-in") are stamped on top.

Platforms vendored (fauxhai `main`):

| Platform key | fauxhai source            | family |
|--------------|---------------------------|--------|
| ubuntu 22.04 | `ubuntu/22.04.json`       | debian |
| ubuntu 20.04 | `ubuntu/20.04.json`       | debian |
| debian 12    | `debian/12.json`          | debian |
| redhat 9     | `redhat/9.json`           | rhel   |
| rocky 9      | `rocky/9.json`            | rhel   |
| almalinux 9  | `almalinux/9.json`        | rhel   |
| amazon 2023  | `amazon/2023.json`        | amazon |
| suse 15      | `suse/15.json`            | suse   |
| windows 2022 | `windows/2022.json`       | windows|

[fauxhai]: https://github.com/chef/fauxhai

## Not yet expressed

Custom per-object **ACLs** (`acls/`) are not part of this fixture yet. Access
works through group membership instead: objects with no explicit ACL fall back
to the default ACL (read for `admins`/`users`/`clients`), and the loader puts
each member in the `users` group — so members read by default and `admins`
(e.g. `tim`) can do everything. An on-disk `acls/` format for overriding
individual objects can be added to the `--state` format in a follow-up once its
shape is pinned against the API handlers.
