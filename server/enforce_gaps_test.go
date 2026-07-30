package server

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// Regression tests for privilege-escalation paths that were reachable by any
// authenticated actor because their routes fell through classifyRequest to
// allow-through. Each test drives the real signed-request path end to end.

// createActor creates a client or user through the API as the bootstrap admin
// and returns the generated private key.
func createActor(t *testing.T, srv *Server, url, body string) []byte {
	t.Helper()
	resp, err := http.DefaultClient.Do(signed(t, srv, "POST", url, body))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create %s = %d: %s", url, resp.StatusCode, raw)
	}
	var created struct {
		ChefKey struct {
			PrivateKey string `json:"private_key"`
		} `json:"chef_key"`
	}
	if err := json.Unmarshal(raw, &created); err != nil || created.ChefKey.PrivateKey == "" {
		t.Fatalf("no private key in create response: %s", raw)
	}
	return []byte(created.ChefKey.PrivateKey)
}

// publicKeyOf returns an actor's stored public key, used to forge a key-rotation
// body that would hand the attacker the victim's identity.
func publicKeyOf(t *testing.T, srv *Server, url string) string {
	t.Helper()
	resp, err := http.DefaultClient.Do(signed(t, srv, "GET", url, ""))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var doc struct {
		PublicKey string `json:"public_key"`
	}
	json.Unmarshal(raw, &doc)
	if doc.PublicKey == "" {
		t.Fatalf("no public_key at %s: %s", url, raw)
	}
	return doc.PublicKey
}

// A non-admin user must not be able to overwrite the superuser's public key,
// which is the credential the auth layer verifies every request against.
func TestEnforceACLDeniesUserKeyTakeover(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	users := srv.URL() + "/users"
	aliceKey := createActor(t, srv, users, `{"name":"alice"}`)
	alicePub := publicKeyOf(t, srv, users+"/alice")

	takeover, _ := json.Marshal(map[string]string{"public_key": alicePub})
	if code := statusOf(t, signedAs(t, "alice", aliceKey, "PUT",
		users+"/"+srv.AdminName()+"/keys/default", string(takeover))); code != http.StatusForbidden {
		t.Fatalf("alice rewrites admin key = %d, want 403", code)
	}

	// The admin's own key must still authenticate.
	if code := statusOf(t, signed(t, srv, "GET", users, "")); code != http.StatusOK {
		t.Fatalf("admin still authenticates = %d, want 200", code)
	}
}

// A user may still rotate its own key: the gate is superuser-or-self, not
// superuser-only, so ordinary credential rotation keeps working.
func TestEnforceACLAllowsSelfKeyRotation(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	users := srv.URL() + "/users"
	aliceKey := createActor(t, srv, users, `{"name":"alice"}`)

	if code := statusOf(t, signedAs(t, "alice", aliceKey, "GET", users+"/alice/keys", "")); code != http.StatusOK {
		t.Fatalf("alice lists own keys = %d, want 200", code)
	}
}

// A node's client key is the lowest-privilege credential in a fleet. It must
// not be able to seize another client's identity in its own org.
func TestEnforceACLDeniesClientKeyTakeover(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	base := srv.URL() + "/organizations/acme"
	nodeKey := createActor(t, srv, base+"/clients", `{"name":"node1"}`)

	if code := statusOf(t, signedAs(t, "node1", nodeKey, "PUT",
		base+"/clients/acme-validator/keys/default", `{"public_key":"x"}`)); code != http.StatusForbidden {
		t.Fatalf("node1 rewrites validator key = %d, want 403", code)
	}
}

// Deploying a policy revision to a policy group decides what every node in that
// group converges on, so it must not be reachable from an ordinary client.
func TestEnforceACLDeniesPolicyDeploy(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	base := srv.URL() + "/organizations/acme"
	nodeKey := createActor(t, srv, base+"/clients", `{"name":"node1"}`)

	revision := `{"revision_id":"deadbeef","name":"base","run_list":["recipe[evil]"]}`
	if code := statusOf(t, signedAs(t, "node1", nodeKey, "PUT",
		base+"/policy_groups/prod/policies/base", revision)); code != http.StatusForbidden {
		t.Fatalf("node1 deploys policy = %d, want 403", code)
	}
	if code := statusOf(t, signedAs(t, "node1", nodeKey, "POST",
		base+"/policies/base/revisions", revision)); code != http.StatusForbidden {
		t.Fatalf("node1 creates policy revision = %d, want 403", code)
	}
}

// A global user who belongs to no organization must not be able to add itself
// to one — that would cross the tenancy boundary the org model enforces.
func TestEnforceACLDeniesSelfAssociation(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	malloryKey := createActor(t, srv, srv.URL()+"/users", `{"name":"mallory"}`)
	orgUsers := srv.URL() + "/organizations/acme/users"

	if code := statusOf(t, signedAs(t, "mallory", malloryKey, "POST",
		orgUsers, `{"username":"mallory"}`)); code != http.StatusForbidden {
		t.Fatalf("mallory self-associates = %d, want 403", code)
	}
	// And so remains unable to read the org's objects.
	if code := statusOf(t, signedAs(t, "mallory", malloryKey, "GET",
		srv.URL()+"/organizations/acme/nodes", "")); code != http.StatusForbidden {
		t.Fatalf("mallory lists nodes = %d, want 403", code)
	}
}

// Destroying an organization wipes every object and blob it holds, so it must
// not be reachable from an actor with no authority in that org.
func TestEnforceACLDeniesOrgDeletion(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	base := srv.URL() + "/organizations/acme"
	nodeKey := createActor(t, srv, base+"/clients", `{"name":"node1"}`)

	if code := statusOf(t, signedAs(t, "node1", nodeKey, "DELETE", base, "")); code != http.StatusForbidden {
		t.Fatalf("node1 deletes org = %d, want 403", code)
	}
	// The org survives.
	if code := statusOf(t, signed(t, srv, "GET", base, "")); code != http.StatusOK {
		t.Fatalf("org still present = %d, want 200", code)
	}
}
