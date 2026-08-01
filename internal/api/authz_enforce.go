package api

import (
	"context"
	"net/http"
	"slices"
	"strings"

	"github.com/tas50/cinc-zero/internal/store"
)

// ctxKey is the private type for context keys set by this package.
type ctxKey int

const actorContextKey ctxKey = iota

// WithActor returns a copy of ctx carrying the authenticated actor, for the
// authorization layer to read. The authentication middleware sets this once a
// request's signature verifies.
func WithActor(ctx context.Context, a Actor) context.Context {
	return context.WithValue(ctx, actorContextKey, a)
}

// actorFromContext returns the actor stored in ctx, if any.
func actorFromContext(ctx context.Context) (Actor, bool) {
	a, ok := ctx.Value(actorContextKey).(Actor)
	return a, ok
}

// authzMiddleware enforces object ACLs and group membership on each request. It
// is only installed when enforcement is enabled.
func (a *API) authzMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r, ok := a.authorize(w, r)
		if ok {
			next.ServeHTTP(w, r)
		}
	})
}

// authorize reports whether the request may proceed. When it denies the request
// it writes the response (404 for a missing object, 403 for a permission
// failure) and returns false. The ordering is authentication (already done) →
// existence → authorization, so a missing object reports 404 rather than
// leaking 403 to an actor that also lacks permission.
func (a *API) authorize(w http.ResponseWriter, r *http.Request) (*http.Request, bool) {
	actor, ok := actorFromContext(r.Context())
	if !ok {
		// No actor: an authentication-exempt path (the file store, _status).
		return r, true
	}
	if actor.IsGlobalAdmin {
		return r, true // pivotal-style superuser bypasses ACLs
	}
	check, ok := classifyRequest(r.Method, r.URL.Path)
	if !ok {
		// Nothing classified this request. For a read that means the route
		// carries no ACL restriction; for one that changes state it means
		// nobody decided, and deciding by default in the caller's favour is
		// what produced this file's history.
		if a.refuseUnclassifiedWrite(r) {
			writeError(w, http.StatusForbidden, "missing permission")
			return r, false
		}
		return r, true
	}
	// A user may always act on its own global record (self-service); the global
	// admin already returned above, so anyone else hits the superuser gate.
	if check.allowSelf != "" && actor.Name == check.allowSelf {
		return r, true
	}
	if check.superuserOnly {
		writeError(w, http.StatusForbidden, "missing "+check.perm+" permission")
		return r, false
	}
	// Global checks (the user collection and user ACLs) evaluate against the
	// global space; org-scoped checks resolve the org from the path.
	org := a.store.Global()
	if !check.global {
		// classifyRequest only succeeds for org-scoped paths, so parts[1] is the org.
		orgName := strings.Split(strings.Trim(r.URL.Path, "/"), "/")[1]
		var err error
		org, ok, err = a.store.Org(orgName)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return r, false
		}
		if !ok {
			return r, true // unknown org: let the handler emit its own 404
		}
	}
	if check.existColl != "" {
		raw, ok, err := org.Get(check.existColl, check.existKey)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return r, false
		}
		if !ok {
			writeError(w, http.StatusNotFound, check.existMsg)
			return r, false
		}
		// Hand the bytes forward so a read handler need not fetch them again.
		r = withPreread(r, org.Name(), check.existColl, check.existKey, raw)
	}
	allowed, err := a.actorAllowed(org, actor, check.aclType, check.aclName, check.perm)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return r, false
	}
	if !allowed {
		writeError(w, http.StatusForbidden, "missing "+check.perm+" permission")
		return r, false
	}
	return r, true
}

// authzCheck describes the authorization a request must pass: holding perm on
// the object identified by aclType/aclName. When existColl is non-empty the
// object's existence is verified first (returning a 404 with existMsg if it is
// missing) so that, per Chef, a missing object reports 404 rather than leaking
// 403 to an actor that lacks permission.
type authzCheck struct {
	aclType, aclName, perm        string
	existColl, existKey, existMsg string
	// global evaluates the ACL against the global space (users and their ACLs)
	// rather than an org resolved from the path.
	global bool
	// superuserOnly denies everyone but the global admin (who already bypassed
	// authorization). It gates the global users collection, where perm names
	// the operation only for the error message.
	superuserOnly bool
	// allowSelf names the user permitted to act on its own global record; when
	// it matches the actor the request is allowed before the superuser gate.
	allowSelf string
}

// enforceSegs are the generic object collections whose container ACL governs
// list/create and whose per-object ACL governs item operations.
var enforceSegs = map[string]bool{
	"nodes": true, "roles": true, "environments": true, "clients": true,
	"groups": true, "containers": true, "policies": true, "policy_groups": true,
}

// existenceSegs are the subset of enforceSegs stored one-key-per-object under a
// collection named after the segment, so the middleware can check existence
// (and report Chef's 404) before authorization.
var existenceSegs = map[string]bool{
	"nodes": true, "roles": true, "environments": true,
	"clients": true, "groups": true, "containers": true,
}

// classifyRequest maps a request to the authorization it requires, or reports
// ok=false for requests that carry no ACL restriction (search, the authenticate
// endpoints, sandbox/file uploads, association management, and server-global
// routes), which are allowed through unchanged.
func classifyRequest(method, path string) (*authzCheck, bool) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) >= 1 && parts[0] == "users" {
		return classifyUsers(method, parts[1:])
	}
	// Provisioning an organization is a server-level operation, so it is
	// superuser-only. Listing them stays open: it exposes only names, which a
	// caller can already enumerate via /users/{user}/organizations.
	if len(parts) == 1 && parts[0] == "organizations" {
		if method == http.MethodPost {
			return &authzCheck{superuserOnly: true, perm: "create"}, true
		}
		return nil, false
	}
	if len(parts) < 2 || parts[0] != "organizations" || parts[1] == "" {
		return nil, false // not an org-scoped path
	}
	org, rest := parts[1], parts[2:]
	read := method == http.MethodGet || method == http.MethodHead

	// ACL endpoints (/.../_acl[/{perm}]) require grant on the target object.
	if i := slices.Index(rest, "_acl"); i >= 0 {
		switch obj := rest[:i]; len(obj) {
		case 0:
			return &authzCheck{aclType: "organizations", aclName: org, perm: "grant"}, true
		case 2:
			return &authzCheck{aclType: obj[0], aclName: obj[1], perm: "grant"}, true
		}
		return nil, false
	}

	if len(rest) == 0 { // /organizations/{org}
		perm, ok := itemPerm(method)
		if !ok {
			return nil, false
		}
		return &authzCheck{aclType: "organizations", aclName: org, perm: perm}, true
	}

	switch seg := rest[0]; {
	case seg == "data":
		return classifyDataBag(method, rest, read)
	case seg == "cookbooks" || seg == "cookbook_artifacts":
		return classifyCookbook(method, seg, rest, read)
	case seg == "users" || seg == "association_requests":
		return classifyOrgMembership(method, rest)
	case enforceSegs[seg]:
		return classifyGeneric(method, seg, rest, read)
	}
	return nil, false
}

// classifyOrgMembership gates the org-membership routes:
// /organizations/{org}/users[/{user}] and the invitations that lead to them,
// /organizations/{org}/association_requests[/{id}].
//
// Changing who belongs to an org is governed by the org's "groups" container,
// because association writes the org's "users" group — so an actor outside the
// org, which belongs to none of its groups, can never let itself in. Issuing an
// invitation is gated the same way: acceptance re-checks that the inviter still
// has the authority, but an outsider should not be able to create the
// invitation in the first place. The read routes are left to the handler's own
// membership check (orgViewAllowed).
func classifyOrgMembership(method string, rest []string) (*authzCheck, bool) {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodDelete:
		if len(rest) > 2 {
			return nil, false
		}
		return &authzCheck{aclType: "containers", aclName: "groups", perm: "update"}, true
	}
	return nil, false
}

// classifyUsers handles the global /users routes (rest is the path after
// "users"). The collection and operations on a user are superuser-only — though
// a user may act on its own record — while a user's _acl is governed by the
// grant permission on that user object in the global space. User key
// sub-endpoints carry no ACL restriction and fall through to allow-through.
func classifyUsers(method string, rest []string) (*authzCheck, bool) {
	switch len(rest) {
	case 0: // /users
		switch method {
		case http.MethodGet, http.MethodHead:
			return &authzCheck{superuserOnly: true, perm: "read"}, true
		case http.MethodPost:
			return &authzCheck{superuserOnly: true, perm: "create"}, true
		}
		return nil, false
	case 1: // /users/{name}
		name := rest[0]
		switch method {
		case http.MethodGet, http.MethodHead, http.MethodPut, http.MethodDelete:
			perm := map[string]string{http.MethodGet: "read", http.MethodHead: "read", http.MethodPut: "update", http.MethodDelete: "delete"}[method]
			return &authzCheck{superuserOnly: true, perm: perm, allowSelf: name}, true
		}
		return nil, false
	}
	// /users/{name}/_acl[/{perm}] — grant on the user object (global space).
	if rest[1] == "_acl" {
		return &authzCheck{global: true, aclType: "users", aclName: rest[0], perm: "grant"}, true
	}
	// /users/{name}/keys[/{key}] — a user's public_key is the credential the
	// auth layer verifies against, so rewriting it is an account takeover.
	// Gated like the user record itself: superuser-only, except that a user may
	// always rotate its own keys.
	if rest[1] == "keys" {
		perm, ok := userKeyPerm(method)
		if !ok {
			return nil, false
		}
		return &authzCheck{superuserOnly: true, perm: perm, allowSelf: rest[0]}, true
	}
	return nil, false
}

// userKeyPerm names the operation a method performs on a user's key set. The
// permission is only used for the denial message (the check is superuser-only),
// but naming it accurately keeps that message truthful.
func userKeyPerm(method string) (string, bool) {
	if method == http.MethodPost {
		return "create", true
	}
	return itemPerm(method)
}

// classifyGeneric handles the standard object collections (container ACL for
// list/create, object ACL for item operations).
func classifyGeneric(method, seg string, rest []string, read bool) (*authzCheck, bool) {
	switch len(rest) {
	case 1:
		switch {
		case read:
			return &authzCheck{aclType: "containers", aclName: seg, perm: "read"}, true
		case method == http.MethodPost:
			return &authzCheck{aclType: "containers", aclName: seg, perm: "create"}, true
		}
	case 2:
		name := rest[1]
		perm, ok := itemPerm(method)
		if !ok {
			return nil, false
		}
		c := &authzCheck{aclType: seg, aclName: name, perm: perm}
		if existenceSegs[seg] {
			c.existColl, c.existKey, c.existMsg = seg, name, "Cannot find "+seg+" "+name
		}
		return c, true
	}
	return classifySubResource(method, seg, rest)
}

// classifySubResource gates the routes nested under a named object —
// {seg}/{name}/{sub}[/...]. Each collapses onto the parent object's ACL, the
// way classifyCookbook collapses a cookbook's versions onto the cookbook. They
// are enumerated rather than allowed wholesale because each one writes state
// that authentication or fleet convergence depends on:
//
//   - keys: an actor's public_key IS the credential the auth layer verifies
//     against, so writing it is an account takeover.
//   - policies/{name}/revisions: a revision carries the run_list every node in
//     a group converges on.
//   - policy_groups/{group}/policies: the deploy operation that points a group
//     at a revision.
func classifySubResource(method, seg string, rest []string) (*authzCheck, bool) {
	if len(rest) < 3 {
		return nil, false
	}
	name, sub := rest[1], rest[2]
	read := method == http.MethodGet || method == http.MethodHead

	perm := ""
	switch {
	case sub == "keys":
		// Adding, replacing, or removing a key all mutate the actor.
		perm = "update"
	case seg == "policies" && sub == "revisions":
		perm = "update"
		if method == http.MethodDelete {
			perm = "delete"
		}
	case seg == "policy_groups" && sub == "policies":
		// Removing a policy from a group edits the group, not the policy.
		perm = "update"
	default:
		return nil, false
	}
	if read {
		perm = "read"
	}
	return &authzCheck{aclType: seg, aclName: name, perm: perm}, true
}

// classifyCookbook handles cookbooks and cookbook_artifacts, which are
// versioned: the cookbook object's ACL governs all of its versions, and the
// container governs the collection and the _latest/_recipes pseudo-endpoints.
func classifyCookbook(method, seg string, rest []string, read bool) (*authzCheck, bool) {
	switch len(rest) {
	case 1:
		if read {
			return &authzCheck{aclType: "containers", aclName: seg, perm: "read"}, true
		}
	case 2:
		if name := rest[1]; strings.HasPrefix(name, "_") {
			if read {
				return &authzCheck{aclType: "containers", aclName: seg, perm: "read"}, true
			}
		} else if read {
			return &authzCheck{aclType: seg, aclName: name, perm: "read"}, true
		}
	case 3:
		name := rest[1]
		perm, ok := itemPerm(method)
		if !ok {
			return nil, false
		}
		return &authzCheck{aclType: seg, aclName: name, perm: perm}, true
	}
	return nil, false
}

// classifyDataBag handles data bags, whose items share the bag object's ACL.
// The "data" container governs the collection; the bag's existence (not the
// item's) is what the middleware checks before authorizing item operations.
func classifyDataBag(method string, rest []string, read bool) (*authzCheck, bool) {
	bagExist := func(bag string) (string, string, string) {
		return dataBagsColl, bag, "Cannot find data bag " + bag
	}
	switch len(rest) {
	case 1:
		switch {
		case read:
			return &authzCheck{aclType: "containers", aclName: "data", perm: "read"}, true
		case method == http.MethodPost:
			return &authzCheck{aclType: "containers", aclName: "data", perm: "create"}, true
		}
	case 2:
		bag := rest[1]
		perm := map[string]string{http.MethodGet: "read", http.MethodHead: "read", http.MethodPost: "update", http.MethodDelete: "delete"}[method]
		if perm == "" {
			return nil, false
		}
		c := &authzCheck{aclType: "data", aclName: bag, perm: perm}
		c.existColl, c.existKey, c.existMsg = bagExist(bag)
		return c, true
	case 3:
		bag := rest[1]
		perm := map[string]string{http.MethodGet: "read", http.MethodHead: "read", http.MethodPut: "update", http.MethodDelete: "update"}[method]
		if perm == "" {
			return nil, false
		}
		c := &authzCheck{aclType: "data", aclName: bag, perm: perm}
		c.existColl, c.existKey, c.existMsg = bagExist(bag)
		return c, true
	}
	return nil, false
}

// itemPerm maps an HTTP method to the permission needed on an individual object.
func itemPerm(method string) (string, bool) {
	switch method {
	case http.MethodGet, http.MethodHead:
		return "read", true
	case http.MethodPut:
		return "update", true
	case http.MethodDelete:
		return "delete", true
	}
	return "", false
}

// This file implements optional ACL enforcement. When enabled (the server's
// -enforce-acls flag), requests are checked against the target object's ACL and
// the actor's transitive group membership before reaching the handler. When
// disabled, none of this runs and every authenticated actor is permitted — the
// permissive default that keeps test pipelines friction-free.

// Actor is the authenticated identity a request is authorized against. It is
// populated by the authentication layer and carried in the request context.
type Actor struct {
	Name string
	// IsClient distinguishes an org-scoped client from a global user, which
	// determines whether membership is matched against a group's clients[] or
	// users[] list.
	IsClient bool
	// IsGlobalAdmin marks a global user with admin:true — Chef's "pivotal"
	// superuser, which bypasses ACL checks entirely.
	IsGlobalAdmin bool
	// ViaWebUI marks a request the webui key signed on this actor's behalf
	// (X-Ops-Request-Source: web). The webui is trusted like the superuser for
	// credential checks (authenticate_user), while object operations still run
	// as this actor under its own ACLs.
	ViaWebUI bool
}

// actorAllowed reports whether the actor holds perm on the object identified by
// aclType/aclName, via a direct actor entry or any group it transitively
// belongs to. This is the uncached form: it is the definition the cached path
// must agree with, and what unit tests exercise directly.
func actorAllowed(org *store.Org, actor Actor, aclType, aclName, perm string) (bool, error) {
	return allowedWith(org, actor, aclType, aclName, perm, actorGroups)
}

// actorAllowed is the same check, resolving group membership through the
// cached reverse index rather than rescanning every group.
func (a *API) actorAllowed(org *store.Org, actor Actor, aclType, aclName, perm string) (bool, error) {
	return allowedWith(org, actor, aclType, aclName, perm, a.actorGroups)
}

// allowedWith evaluates an ACL entry, deferring group resolution to groupsOf so
// the cached and uncached forms share one definition. Group membership is only
// resolved when the entry does not already name the actor, which keeps the
// common "creator owns its object" grant free of any group work at all.
func allowedWith(org *store.Org, actor Actor, aclType, aclName, perm string,
	groupsOf func(*store.Org, Actor) (map[string]bool, error)) (bool, error) {
	acl, err := loadACL(org, aclType, aclName)
	if err != nil {
		return false, err
	}
	ace, _ := acl[perm].(map[string]any)
	if ace == nil {
		return false, nil
	}
	// A direct actor grant settles it without resolving groups.
	if slices.Contains(anyStrings(ace["actors"]), actor.Name) {
		return true, nil
	}
	if len(anyStrings(ace["groups"])) == 0 {
		return false, nil
	}
	member, err := groupsOf(org, actor)
	if err != nil {
		return false, err
	}
	return aceAllows(ace, actor, member), nil
}

// aceAllows reports whether a single ACL entry grants actor, given the set of
// groups it belongs to. Callers that evaluate many objects against one actor
// (search result filtering) resolve membership once and reuse it here, rather
// than paying actorGroups per object.
func aceAllows(entry any, actor Actor, member map[string]bool) bool {
	ace, _ := entry.(map[string]any)
	if ace == nil {
		return false
	}
	if slices.Contains(anyStrings(ace["actors"]), actor.Name) {
		return true
	}
	for _, g := range anyStrings(ace["groups"]) {
		if member[g] {
			return true
		}
	}
	return false
}

// anyStrings coerces a JSON-decoded array into a []string. It accepts both
// []any (parsed from stored JSON) and []string (the in-memory default ACL
// literals), dropping non-string elements.
func anyStrings(v any) []string {
	switch arr := v.(type) {
	case []string:
		return arr
	case []any:
		out := make([]string, 0, len(arr))
		for _, e := range arr {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}
