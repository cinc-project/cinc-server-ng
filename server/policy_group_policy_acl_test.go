package server

import (
	"fmt"
	"net/http"
	"testing"
)

// erchef's oc_chef_wm_policy_group_policy_rev checks a request on a policy
// already in a group against both the policy and the group, each for the
// request's own permission (read for GET, delete for DELETE), so the group's
// ACL is no way around the policy's.

func TestPolicyGroupPolicyReadNeedsReadOnPolicy(t *testing.T) {
	srv, base, bob := memberSetup(t)
	mustStatus(t, signed(t, srv, "PUT", base+"/policy_groups/prod/policies/payments", fmt.Sprintf(policyBody, "aa01", "payments")), http.StatusOK)
	node := createClientAndKey(t, srv, base, "node1")
	for _, who := range []struct {
		name string
		key  []byte
	}{{"bob", bob}, {"node1", node}} {
		// Baseline: the default ACLs let members and clients read both.
		mustStatus(t, signedAs(t, who.name, who.key, "GET", base+"/policy_groups/prod/policies/payments", ""), http.StatusOK)
	}

	mustStatus(t, signed(t, srv, "PUT", base+"/policies/payments/_acl/read",
		`{"read":{"actors":[],"groups":["admins"]}}`), http.StatusOK)
	for _, who := range []struct {
		name string
		key  []byte
	}{{"bob", bob}, {"node1", node}} {
		mustStatus(t, signedAs(t, who.name, who.key, "GET", base+"/policies/payments/revisions/aa01", ""), http.StatusForbidden)
		mustStatus(t, signedAs(t, who.name, who.key, "GET", base+"/policy_groups/prod/policies/payments", ""), http.StatusForbidden)
	}
	// The admins, who read both, still can.
	mustStatus(t, signed(t, srv, "GET", base+"/policy_groups/prod/policies/payments", ""), http.StatusOK)
}

func TestPolicyGroupPolicyDeleteNeedsDeleteOnBoth(t *testing.T) {
	srv, base, bob := memberSetup(t)
	push := func(group string) {
		mustStatus(t, signed(t, srv, "PUT", base+"/policy_groups/"+group+"/policies/web", fmt.Sprintf(policyBody, "aa01", "web")), http.StatusOK)
	}
	push("dev")
	push("prod")
	// Baseline: the default ACLs let a member remove a policy from a group.
	mustStatus(t, signedAs(t, "bob", bob, "DELETE", base+"/policy_groups/dev/policies/web", ""), http.StatusOK)
	push("dev")

	// Delete on the policy is needed, not only on the group.
	mustStatus(t, signed(t, srv, "PUT", base+"/policies/web/_acl/delete",
		`{"delete":{"actors":[],"groups":["admins"]}}`), http.StatusOK)
	mustStatus(t, signedAs(t, "bob", bob, "DELETE", base+"/policy_groups/dev/policies/web", ""), http.StatusForbidden)
	mustStatus(t, signed(t, srv, "PUT", base+"/policies/web/_acl/delete",
		`{"delete":{"actors":[],"groups":["admins","users"]}}`), http.StatusOK)

	// And on the group it is delete, not update.
	mustStatus(t, signed(t, srv, "PUT", base+"/policy_groups/prod/_acl/delete",
		`{"delete":{"actors":[],"groups":["admins"]}}`), http.StatusCreated)
	mustStatus(t, signedAs(t, "bob", bob, "DELETE", base+"/policy_groups/prod/policies/web", ""), http.StatusForbidden)
	mustStatus(t, signedAs(t, "bob", bob, "DELETE", base+"/policy_groups/dev/policies/web", ""), http.StatusOK)
}
