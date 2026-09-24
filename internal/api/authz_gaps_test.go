package api

import (
	"net/http"
	"slices"
	"testing"
)

// These cases cover routes that previously fell through classifyRequest to
// allow-through even though they mutate credentials, deployed policy, org
// membership, or the org itself. Each one is a privilege-escalation path when
// ACL enforcement is on, so each must now resolve to a concrete check.

func TestClassifyActorKeyRoutes(t *testing.T) {
	cases := []struct {
		method, path string
		want         authzCheck
	}{
		// A user's keys are its credential: superuser-only, but a user may
		// rotate its own.
		{"GET", "/users/bob/keys", authzCheck{superuserOnly: true, perm: "read", allowSelf: "bob"}},
		{"POST", "/users/bob/keys", authzCheck{superuserOnly: true, perm: "create", allowSelf: "bob"}},
		{"GET", "/users/bob/keys/default", authzCheck{superuserOnly: true, perm: "read", allowSelf: "bob"}},
		{"PUT", "/users/bob/keys/default", authzCheck{superuserOnly: true, perm: "update", allowSelf: "bob"}},
		{"DELETE", "/users/bob/keys/default", authzCheck{superuserOnly: true, perm: "delete", allowSelf: "bob"}},
		// A client's keys are governed by the client object's own ACL.
		{"GET", "/organizations/acme/clients/node1/keys", authzCheck{aclType: "clients", aclName: "node1", perm: "read"}},
		{"POST", "/organizations/acme/clients/node1/keys", authzCheck{aclType: "clients", aclName: "node1", perm: "update"}},
		{"PUT", "/organizations/acme/clients/node1/keys/default", authzCheck{aclType: "clients", aclName: "node1", perm: "update"}},
		{"DELETE", "/organizations/acme/clients/node1/keys/default", authzCheck{aclType: "clients", aclName: "node1", perm: "update"}},
	}
	for _, c := range cases {
		got, ok := classifyRequest(c.method, c.path)
		if !ok {
			t.Errorf("%s %s: allow-through, want %+v", c.method, c.path, c.want)
			continue
		}
		if *got != c.want {
			t.Errorf("%s %s:\n got %+v\nwant %+v", c.method, c.path, *got, c.want)
		}
	}
}

func TestClassifyPolicyfileWriteRoutes(t *testing.T) {
	cases := []struct {
		method, path string
		want         authzCheck
	}{
		// Policy revisions are governed by the policy object.
		{"GET", "/organizations/acme/policies/base/revisions/abc123", authzCheck{aclType: "policies", aclName: "base", perm: "read"}},
		{"POST", "/organizations/acme/policies/base/revisions", authzCheck{aclType: "policies", aclName: "base", perm: "update"}},
		{"DELETE", "/organizations/acme/policies/base/revisions/abc123", authzCheck{aclType: "policies", aclName: "base", perm: "delete"}},
		// Deploying a policy to a group is an update of that group.
		{"GET", "/organizations/acme/policy_groups/prod/policies/base", authzCheck{aclType: "policy_groups", aclName: "prod", perm: "read"}},
		{"PUT", "/organizations/acme/policy_groups/prod/policies/base", authzCheck{aclType: "policy_groups", aclName: "prod", perm: "update"}},
		{"DELETE", "/organizations/acme/policy_groups/prod/policies/base", authzCheck{aclType: "policy_groups", aclName: "prod", perm: "update"}},
	}
	for _, c := range cases {
		got, ok := classifyRequest(c.method, c.path)
		if !ok {
			t.Errorf("%s %s: allow-through, want %+v", c.method, c.path, c.want)
			continue
		}
		if *got != c.want {
			t.Errorf("%s %s:\n got %+v\nwant %+v", c.method, c.path, *got, c.want)
		}
	}
}

func TestClassifyOrgMembershipRoutes(t *testing.T) {
	// As on erchef: force-associating is superuser-only, and every other change
	// to who belongs to an org needs update on the organization, which only the
	// admins group holds (fallbackACL). A user may always remove themself, and
	// a missing membership is a 404 before it is a 403.
	orgUpdate := authzCheck{aclType: "organizations", aclName: "acme", perm: "update"}
	cases := []struct {
		method, path string
		want         authzCheck
	}{
		{"POST", "/organizations/acme/users", authzCheck{superuserOnly: true, perm: "create"}},
		{"DELETE", "/organizations/acme/users/bob", authzCheck{
			aclType: "organizations", aclName: "acme", perm: "update", allowSelf: "bob",
			existColl: assocColl, existKey: "bob", existMsg: "Cannot find user bob in organization acme",
		}},
		{"POST", "/organizations/acme/association_requests", orgUpdate},
		{"DELETE", "/organizations/acme/association_requests/bob-acme", orgUpdate},
		{"PUT", "/organizations/acme/users/bob", orgUpdate},
	}
	for _, c := range cases {
		got, ok := classifyRequest(c.method, c.path)
		if !ok {
			t.Errorf("%s %s: allow-through, want %+v", c.method, c.path, c.want)
			continue
		}
		if *got != c.want {
			t.Errorf("%s %s:\n got %+v\nwant %+v", c.method, c.path, *got, c.want)
		}
	}
}

// The organization and the default groups must not fall back to defaultACL,
// which grants update to every member: update on the organization is what
// manages membership, and admins/users membership is what carries it.
func TestFallbackACLReservesOrgAuthorityToAdmins(t *testing.T) {
	for _, c := range []struct{ typ, name string }{
		{"organizations", "acme"},
		{"groups", "admins"},
		{"groups", "users"},
		{"groups", "clients"},
		{"groups", "billing-admins"},
	} {
		acl := fallbackACL(c.typ, c.name)
		for _, p := range []string{"create", "update", "delete", "grant"} {
			if got := anyStrings(acl[p].(map[string]any)["groups"]); !slices.Equal(got, []string{"admins"}) {
				t.Errorf("%s/%s %s groups = %v, want [admins]", c.typ, c.name, p, got)
			}
		}
		if got := anyStrings(acl["read"].(map[string]any)["groups"]); !slices.Contains(got, "users") {
			t.Errorf("%s/%s read groups = %v, want users to keep read", c.typ, c.name, got)
		}
	}
	// Any other object keeps the permissive default.
	if got := anyStrings(fallbackACL("groups", "ops")["update"].(map[string]any)["groups"]); !slices.Contains(got, "users") {
		t.Errorf("groups/ops update groups = %v, want the default", got)
	}
}

func TestClassifyOrganizationLifecycleRoutes(t *testing.T) {
	cases := []struct {
		method, path string
		want         authzCheck
	}{
		// Reading an org's metadata is governed by its ACL, so a member can see
		// the org it belongs to. Changing or destroying one is a server-level
		// operation like provisioning it: no ACL is ever stored for the
		// organization object, so anything else would fall back to defaultACL(),
		// which grants update and delete to the org's own "users" group.
		{"GET", "/organizations/acme", authzCheck{aclType: "organizations", aclName: "acme", perm: "read"}},
		{"PUT", "/organizations/acme", authzCheck{superuserOnly: true, perm: "update"}},
		{"DELETE", "/organizations/acme", authzCheck{superuserOnly: true, perm: "delete"}},
		{"POST", "/organizations", authzCheck{superuserOnly: true, perm: "create"}},
	}
	for _, c := range cases {
		got, ok := classifyRequest(c.method, c.path)
		if !ok {
			t.Errorf("%s %s: allow-through, want %+v", c.method, c.path, c.want)
			continue
		}
		if *got != c.want {
			t.Errorf("%s %s:\n got %+v\nwant %+v", c.method, c.path, *got, c.want)
		}
	}
}

// Listing organizations stays open: knife reads it during setup and it exposes
// only names the caller can already discover via /users/{user}/organizations.
func TestClassifyOrganizationListStaysOpen(t *testing.T) {
	if got, ok := classifyRequest(http.MethodGet, "/organizations"); ok {
		t.Errorf("GET /organizations: classified %+v, want allow-through", got)
	}
}
