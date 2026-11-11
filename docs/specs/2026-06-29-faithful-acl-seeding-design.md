# Faithful ACL seeding for org bootstrap and the `--state` loader

**Status:** approved (design)
**Date:** 2026-06-29

## Problem

Under default ACL enforcement, a user logged into a management console
(cinc-console) signs requests with the webui key *on behalf of a logged-in
user* (`X-Ops-Request-Source: web`). Those requests run under **that user's**
ACLs — not as the `pivotal` superuser. Today such a user is denied almost
everything:

| Actor | node list | node show | role list |
|-------|-----------|-----------|-----------|
| `pivotal` (direct superuser) | 200 | 200 | 200 |
| `tim` via webui (cinc-console) | 403 | 403 | 403 |

Root cause — the seed ships almost no ACLs:

- `CreateOrganizationWithKey` writes ACLs for only the `nodes` and `clients`
  containers (organizations.go). The other ten default containers have none, so
  a non-superuser cannot even *list* roles/environments/etc.
- The `--state`/`repo` loader writes objects straight into the store, bypassing
  the API's `writeCreatorACL`, so **no loaded object has a per-object ACL** —
  item reads (e.g. `node show`) are denied for everyone but `pivotal`.
- The loader writes `members.json` users directly into `association_users`,
  bypassing `associateUser`, so members are **not** added to the `users` group
  and inherit no grants.
- The seeded `admins`/`users` groups are empty; `tim`/`jack` are only in the
  custom `devs` group, which grants nothing.

The `pivotal` superuser works because it bypasses ACLs entirely
(authz_enforce.go). The test-repo README already flags this gap: "Object ACLs
are not part of this fixture yet."

## Correction after deeper investigation

The first framing assumed objects/containers had *no* effective ACL. That is
wrong: `loadACL` (acl.go) **falls back to `defaultACL()`** when no ACL is stored,
granting `admins`/`users`/`clients` read on any unstored object or container —
proven by the existing `TestActorAllowedViaGroupDefaultACL`. So explicitly
seeding container/per-object ACLs everywhere would be pure redundancy with no
observable behavioral difference (enforcement *and* `_acl` reads already use the
fallback).

The real, narrower root cause: the seed never puts the human users in a group
the default ACL grants. `tim`/`jack` are only in the custom `devs` group, which
the fallback does not grant, so they are denied everything. The faithful fix is
therefore **group membership**, not ACL seeding:

- The `--state` loader must add `members.json` users to the `users` group
  (exactly what `associateUser` does at association.go:111) — it currently writes
  `association_users` directly and skips that step.
- The dev seed must put `tim` in the `admins` group (a full org admin), keeping
  the existing nodes/clients special container grants untouched.

Parts 1 (seed all container ACLs) and 2 (per-object ACLs in the loader) from the
original design are **dropped** as unnecessary. Parts 3 (loader → `users` group)
and 4 (`tim` → `admins`) are the fix.

## Goal

Make the seed faithful to a real Chef Infra Server: every container and every
object carries a default ACL, org members join the `users` group, and the dev
user `tim` is a full **org admin** (mirroring `chef-server-ctl org-user-add
acme tim --admin`). After this, `tim` can browse and modify all of `acme` in
cinc-console under genuine ACL enforcement.

## Design

Existing helpers are reused (no new ACL shape is invented):

- `defaultACL()` — `create:[admins,users]`, `read:[admins,users,clients]`,
  `update:[admins,users]`, `delete:[admins,users]`, `grant:[admins]`.
- `writeCreatorACL(org, typ, name, creator)` — per-object ACL = `defaultACL()`
  plus the creator as a named actor.
- `addUserToOrgGroup(org, "users", name)` — already used by `associateUser`.

### 1. Org bootstrap seeds all container ACLs

In `CreateOrganizationWithKey`, write `defaultACL()` for **every** default
container, not just `nodes`/`clients`. The two existing special grants are
preserved by starting from `defaultACL()` and layering the extra `create`
grants:

- `clients` container: `create` also grants the org validator (actor) — lets the
  validator key register clients/nodes.
- `nodes` container: `create` grants the `clients` group — lets a registered
  client create its own node.

All other containers get a plain `defaultACL()`. Net result: `admins` = full
control, `users`/`clients` = read, on every container — matching real Chef.

### 2. `--state` loader writes per-object ACLs

After `repo.Load` populates an org's objects, write a per-object ACL
(`defaultACL()`, no named creator — the seed has no creating user) for each
loaded object in the ACL-enforced collections, so item operations resolve:

- `nodes`, `roles`, `environments`, `clients`, `policies`, `policy_groups`
  (keyed `<seg>/<name>`),
- data-bag items and cookbooks per how `classifyRequest` looks them up.

This is the loader-level equivalent of the `writeCreatorACL` that the API
handlers run on create. It lives in the loader (`internal/state` / `internal/repo`)
so any loaded repo — not just the dev seed — gets faithful object ACLs.

### 3. `--state` loader adds members to the `users` group

In `loadMembers`, after recording each user in `association_users`, also call
`addUserToOrgGroup(org, "users", name)` — exactly what `associateUser` does — so
regular members inherit the container/object read grants.

### 4. Dev seed: `tim` is a full org admin

Add `tim` to the acme `admins` group (the seed fixture). This is the fixture
equivalent of `org-user-add acme tim --admin`. `jack` remains a regular member
(in `users` via step 3); `pivotal` is the global superuser.

`tim`/`jack` are removed from the custom `devs` group (the user chose "tim as
full org admin", not "keep devs"). The `devs` group file is retained but
emptied — it stays in the fixture as a standalone example of a custom authz
group the loader handles, now with no members.

### 5. Documentation

Document `tim`'s access level in the dev docs:

- `docs/DEVELOPMENT.md` test-accounts table — note `tim` is a full **org admin**
  (acme `admins` group; browse + modify), `jack` a regular read member, and how
  this maps to `org-user-add --admin`.
- `dev/test-repo/README.md` Web login section — same note.

## Testing (TDD)

- **Org bootstrap:** a freshly created org has a `defaultACL()` on every default
  container; the `nodes`/`clients` special create grants are preserved.
- **Loader per-object ACLs:** after loading the seed, a representative object of
  each enforced type has a per-object ACL granting `users` read.
- **Loader membership:** seed members are in the `users` group.
- **End-to-end (server package, enforcement on):** a webui-impersonated `tim`
  gets 200 on node list, node show, role list, environment list, and can PUT a
  node (admin write); a webui `jack` gets 200 on reads; an unassociated user is
  still 403. (This is the regression test that encodes the original bug.)
- Full suite (`make test`) stays green; adapt any test that assumed the old
  two-ACL bootstrap.

## Out of scope

- An on-disk `acls/` format for `--state` (custom ACLs per object). This design
  seeds *default* ACLs programmatically; a future change can let the state
  format carry explicit ACLs.
- Global `server-admins` modeling. (Since added, outside this design: see
  `internal/api/server_admins.go`. The group's grants are applied by
  `classifyUsers`, not seeded into ACLs, because the user routes are not
  ACL-gated.)
