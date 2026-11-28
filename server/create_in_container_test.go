package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

// erchef authorizes making a new cookbook, cookbook artifact, policy or policy
// group with create on its container ({create_in_container, ...} in
// chef_wm_cookbook_version, oc_chef_wm_named_cookbook_artifact_version,
// oc_chef_wm_named_policy_revisions and oc_chef_wm_policy_group_policy_rev),
// and only an existing one with its own ACL. Pushing a policy to a group is
// checked on both the policy and the group.

const (
	cookbookBody = `{"name":"%s-%s","cookbook_name":"%s","version":"%s","metadata":{"version":"%s"}}`
	artifactBody = `{"name":"probe","identifier":"%s","version":"1.0.0","metadata":{"version":"1.0.0"}}`
	policyBody   = `{"revision_id":"%s","name":"%s","run_list":["recipe[demo::default]"],` +
		`"cookbook_locks":{"demo":{"identifier":"f04cc40faf628253fe7d9566d66a1733fb1afbe9","version":"1.2.3"}}}`
)

func cookbook(name, version string) string {
	return fmt.Sprintf(cookbookBody, name, version, name, version, version)
}

// memberSetup starts an enforcing server with bob, a plain member of acme, and
// returns the org base URL and bob's key.
func memberSetup(t *testing.T) (*Server, string, []byte) {
	t.Helper()
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	base := srv.URL() + "/organizations/acme"
	key := createUserKey(t, srv, "bob")
	mustStatus(t, signed(t, srv, "POST", base+"/users", `{"username":"bob"}`), http.StatusCreated)
	return srv, base, key
}

// narrowCreate leaves create on the named container to the admins alone.
func narrowCreate(t *testing.T, srv *Server, base, container string) {
	t.Helper()
	mustStatus(t, signed(t, srv, "PUT", base+"/containers/"+container+"/_acl/create",
		`{"create":{"actors":[],"groups":["admins"]}}`), http.StatusOK)
}

func TestNewCookbookNeedsCreateOnContainer(t *testing.T) {
	srv, base, bob := memberSetup(t)
	// The default container ACL lets members upload cookbooks.
	mustStatus(t, signedAs(t, "bob", bob, "PUT", base+"/cookbooks/apache/1.0.0", cookbook("apache", "1.0.0")), http.StatusCreated)

	narrowCreate(t, srv, base, "cookbooks")
	mustStatus(t, signedAs(t, "bob", bob, "PUT", base+"/cookbooks/nginx/1.0.0", cookbook("nginx", "1.0.0")), http.StatusForbidden)
	// A new version of a cookbook that exists is an update of that cookbook.
	mustStatus(t, signedAs(t, "bob", bob, "PUT", base+"/cookbooks/apache/1.1.0", cookbook("apache", "1.1.0")), http.StatusCreated)
	// The admins may still create it.
	mustStatus(t, signed(t, srv, "PUT", base+"/cookbooks/nginx/1.0.0", cookbook("nginx", "1.0.0")), http.StatusCreated)
}

func TestNewCookbookArtifactNeedsCreateOnContainer(t *testing.T) {
	srv, base, bob := memberSetup(t)
	first, second := "1111111111111111111111111111111111111111", "2222222222222222222222222222222222222222"
	mustStatus(t, signedAs(t, "bob", bob, "PUT", base+"/cookbook_artifacts/probe/"+first, fmt.Sprintf(artifactBody, first)), http.StatusCreated)

	narrowCreate(t, srv, base, "cookbook_artifacts")
	// Artifacts are immutable: every new identifier is a creation, even of a
	// name that already has one.
	mustStatus(t, signedAs(t, "bob", bob, "PUT", base+"/cookbook_artifacts/probe/"+second, fmt.Sprintf(artifactBody, second)), http.StatusForbidden)
	mustStatus(t, signed(t, srv, "PUT", base+"/cookbook_artifacts/probe/"+second, fmt.Sprintf(artifactBody, second)), http.StatusCreated)
}

func TestNewPolicyNeedsCreateOnContainer(t *testing.T) {
	srv, base, bob := memberSetup(t)
	mustStatus(t, signedAs(t, "bob", bob, "POST", base+"/policies/web/revisions", fmt.Sprintf(policyBody, "aa01", "web")), http.StatusCreated)

	narrowCreate(t, srv, base, "policies")
	mustStatus(t, signedAs(t, "bob", bob, "POST", base+"/policies/db/revisions", fmt.Sprintf(policyBody, "bb01", "db")), http.StatusForbidden)
	// Another revision of an existing policy is an update of it.
	mustStatus(t, signedAs(t, "bob", bob, "POST", base+"/policies/web/revisions", fmt.Sprintf(policyBody, "aa02", "web")), http.StatusCreated)
}

func TestPolicyGroupPushChecksBothObjects(t *testing.T) {
	srv, base, bob := memberSetup(t)
	mustStatus(t, signedAs(t, "bob", bob, "PUT", base+"/policy_groups/dev/policies/web", fmt.Sprintf(policyBody, "aa01", "web")), http.StatusOK)

	// A new group needs create on the policy_groups container.
	narrowCreate(t, srv, base, "policy_groups")
	mustStatus(t, signedAs(t, "bob", bob, "PUT", base+"/policy_groups/prod/policies/web", fmt.Sprintf(policyBody, "aa01", "web")), http.StatusForbidden)
	mustStatus(t, signedAs(t, "bob", bob, "PUT", base+"/policy_groups/dev/policies/web", fmt.Sprintf(policyBody, "aa02", "web")), http.StatusOK)

	// A new policy pushed into an existing group needs create on policies.
	narrowCreate(t, srv, base, "policies")
	mustStatus(t, signedAs(t, "bob", bob, "PUT", base+"/policy_groups/dev/policies/db", fmt.Sprintf(policyBody, "bb01", "db")), http.StatusForbidden)

	// And an existing policy needs update on it as well as on the group.
	mustStatus(t, signed(t, srv, "PUT", base+"/policies/web/_acl/update",
		`{"update":{"actors":[],"groups":["admins"]}}`), http.StatusOK)
	mustStatus(t, signedAs(t, "bob", bob, "PUT", base+"/policy_groups/dev/policies/web", fmt.Sprintf(policyBody, "aa03", "web")), http.StatusForbidden)
}

// Pushing an existing revision_id to a group the pusher may write must not
// replace what other groups deploy: a revision is immutable once stored.
func TestPolicyGroupPushCannotReplaceAnotherGroupsRevision(t *testing.T) {
	srv, base, bob := memberSetup(t)
	const rev = "aa01"
	mustStatus(t, signed(t, srv, "PUT", base+"/policy_groups/prod/policies/web", fmt.Sprintf(policyBody, rev, "web")), http.StatusOK)
	mustStatus(t, signed(t, srv, "PUT", base+"/policy_groups/prod/_acl/update",
		`{"update":{"actors":[],"groups":["admins"]}}`), http.StatusCreated) // erchef's status for a policy group ACL

	evil := `{"revision_id":"` + rev + `","name":"web","run_list":["recipe[evil::default]"],` +
		`"cookbook_locks":{"evil":{"identifier":"f04cc40faf628253fe7d9566d66a1733fb1afbe9","version":"6.6.6"}}}`
	// Baseline: bob cannot push to prod.
	mustStatus(t, signedAs(t, "bob", bob, "PUT", base+"/policy_groups/prod/policies/web", evil), http.StatusForbidden)
	// He may push the same revision_id to a group of his own...
	mustStatus(t, signedAs(t, "bob", bob, "PUT", base+"/policy_groups/scratch/policies/web", evil), http.StatusOK)

	// ...but prod still deploys the revision as first stored.
	resp, err := http.DefaultClient.Do(signed(t, srv, "GET", base+"/policy_groups/prod/policies/web", ""))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc struct {
		RunList []string `json:"run_list"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || len(doc.RunList) != 1 || doc.RunList[0] != "recipe[demo::default]" {
		t.Fatalf("prod serves %d %v, want the original revision", resp.StatusCode, doc.RunList)
	}
}
