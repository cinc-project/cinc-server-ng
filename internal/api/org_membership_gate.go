package api

import (
	"net/http"
)

// The org membership gate.
//
// erchef refuses an org-scoped request from a user who is not associated with
// the org before it consults any ACL (oc_chef_wm_base:is_authorized →
// authorized_by_org_membership_check). ACL entries and group rows naming a
// user are left behind when the user leaves an org, and an admin may name any
// global user in a group or ACL; neither grants anything to a user outside the
// org because of this check. It covers every org route, classified or not,
// which is why it runs ahead of classifyRequest.
//
// Clients are members of their org by definition (and resolveAuth only finds
// clients of the org in the path), so the check is a user's. The superuser
// has already bypassed authorization before it runs.

// membershipExempt are the org route segments erchef answers without
// is_authorized: chef_wm_named_principal doesn't mix it in, and
// required_recipe is served by nginx, never reaching erchef.
var membershipExempt = map[string]bool{
	"principals":      true,
	"required_recipe": true,
}

// orgMembershipGate refuses a user who is not associated with the org named in
// the path, writing erchef's 403. It lets the request through when the path
// names no org, the org does not exist, or no route matches (the 404 or 405
// stands, as webmachine decides both before is_authorized). The request it
// returns records the org it looked up, so that authorize and the handler act
// on that same answer (org_resolution.go): an org that was missing here gets
// the handler's 404 even if it has been created since.
func (a *API) orgMembershipGate(w http.ResponseWriter, r *http.Request, actor Actor) (*http.Request, bool) {
	parts := PathSegments(r.URL.EscapedPath())
	if len(parts) < 2 || parts[0] != "organizations" || parts[1] == "" {
		return r, true
	}
	if actor.IsClient || (len(parts) > 2 && membershipExempt[parts[2]]) {
		return r, true
	}
	if !a.routeMatched(r) {
		return r, true
	}
	r, org, ok, err := a.lookupOrg(r, parts[1])
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return r, false
	}
	if !ok {
		return r, true
	}
	// View: only presence matters, so skip the copy. One keyed read; the
	// clients that make up a fleet's traffic never get here.
	_, member, err := org.View(assocColl, actor.Name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return r, false
	}
	if !member {
		writeError(w, http.StatusForbidden,
			"'"+actor.Name+"' not associated with organization '"+org.Name()+"'")
		return r, false
	}
	return r, true
}
