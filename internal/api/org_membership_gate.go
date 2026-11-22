package api

import (
	"net/http"
	"strings"

	"github.com/cinc-project/cinc-server-ng/internal/store"
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
// the path, writing erchef's 403. For an org-scoped request it also returns
// the org it resolved, for the caller to reuse; it returns a nil org, and lets
// the request through, when the path names no org, the org does not exist (the
// handler writes the 404), or no route matches (the 404 or 405 stands, as
// webmachine decides both before is_authorized).
func (a *API) orgMembershipGate(w http.ResponseWriter, r *http.Request, actor Actor) (*store.Org, bool) {
	parts := strings.SplitN(strings.Trim(r.URL.Path, "/"), "/", 4)
	if len(parts) < 2 || parts[0] != "organizations" || parts[1] == "" {
		return nil, true
	}
	if actor.IsClient || (len(parts) > 2 && membershipExempt[parts[2]]) {
		return nil, true
	}
	if !a.routeMatched(r) {
		return nil, true
	}
	org, ok, err := a.store.Org(parts[1])
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return nil, false
	}
	if !ok {
		return nil, true
	}
	// View: only presence matters, so skip the copy. One keyed read; the
	// clients that make up a fleet's traffic never get here.
	_, member, err := org.View(assocColl, actor.Name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return nil, false
	}
	if !member {
		writeError(w, http.StatusForbidden,
			"'"+actor.Name+"' not associated with organization '"+org.Name()+"'")
		return nil, false
	}
	return org, true
}
