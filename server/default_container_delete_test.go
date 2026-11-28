package server

import (
	"net/http"
	"testing"
)

// The default containers carry the ACLs every create in the org is checked
// against, and removing one drops its stored ACL. Only the superuser may delete
// one; org admins and members are refused even where the org policy gives them
// delete on it (the users group holds delete on clients, nodes, cookbooks...).
// Containers created through POST /containers delete as before.
func TestDefaultContainersAreNotDeletableByOrgActors(t *testing.T) {
	f := newOrgMembershipFixture(t)

	// Baseline: an org admin creates and deletes a container of its own, and
	// the policy gives the users group delete on the clients container.
	if code := f.as(t, "boss", f.bossKey, "POST", f.acme+"/containers", `{"containername":"custom"}`); code != http.StatusCreated {
		t.Fatalf("admin creates a container = %d, want 201", code)
	}
	if code := f.as(t, "boss", f.bossKey, "DELETE", f.acme+"/containers/custom", ""); code != http.StatusOK {
		t.Fatalf("admin deletes its container = %d, want 200", code)
	}
	acl := granularACL(t, f.srv, f.acme+"/containers/clients/_acl")
	if !contains(acl["delete"]["groups"], "users") {
		t.Fatalf("clients container delete = %v, want the users group on it", acl["delete"])
	}

	for _, c := range []string{"clients", "nodes", "cookbooks", "data", "containers"} {
		if code := f.as(t, "member", f.memberKey, "DELETE", f.acme+"/containers/"+c, ""); code != http.StatusForbidden {
			t.Errorf("member deletes default container %s = %d, want 403", c, code)
		}
		if code := f.as(t, "boss", f.bossKey, "DELETE", f.acme+"/containers/"+c, ""); code != http.StatusForbidden {
			t.Errorf("admin deletes default container %s = %d, want 403", c, code)
		}
	}

	// The clients container and its ACL are intact, so the validator still
	// registers nodes.
	mustStatus(t, signed(t, f.srv, "GET", f.acme+"/containers/clients/_acl", ""), http.StatusOK)
	createClientAndKey(t, f.srv, f.acme, "node1")
}

// The superuser may still delete a default container. Its ACL then falls back
// to the org policy, and for the clients container that includes the
// validator's create, so node registration keeps working.
func TestSuperuserDeletedClientsContainerKeepsValidatorCreate(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	base := srv.URL() + "/organizations/acme"
	createClientAndKey(t, srv, base, "before")

	mustStatus(t, signed(t, srv, "DELETE", base+"/containers/clients", ""), http.StatusOK)
	createClientAndKey(t, srv, base, "after")
}
