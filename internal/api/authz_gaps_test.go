package api

import (
	"net/http"
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
	// Changing who belongs to an org is governed by the org's groups container,
	// so a non-member (who is in none of the org's groups) can never do it.
	want := authzCheck{aclType: "containers", aclName: "groups", perm: "update"}
	for _, c := range []struct{ method, path string }{
		{"POST", "/organizations/acme/users"},
		{"DELETE", "/organizations/acme/users/bob"},
	} {
		got, ok := classifyRequest(c.method, c.path)
		if !ok {
			t.Errorf("%s %s: allow-through, want %+v", c.method, c.path, want)
			continue
		}
		if *got != want {
			t.Errorf("%s %s:\n got %+v\nwant %+v", c.method, c.path, *got, want)
		}
	}
}

func TestClassifyOrganizationLifecycleRoutes(t *testing.T) {
	cases := []struct {
		method, path string
		want         authzCheck
	}{
		{"PUT", "/organizations/acme", authzCheck{aclType: "organizations", aclName: "acme", perm: "update"}},
		{"DELETE", "/organizations/acme", authzCheck{aclType: "organizations", aclName: "acme", perm: "delete"}},
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
