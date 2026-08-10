package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/tas50/cinc-server-ng/internal/store"
)

// TestPutKeyReplaceNamedKey covers replacing an existing named key: the stored
// key is overwritten and its "name" is pinned to the path segment.
func TestPutKeyReplaceNamedKey(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	do(t, "POST", base+"/clients", `{"name":"web01"}`)
	do(t, "POST", base+"/clients/web01/keys", `{"name":"key2"}`)

	const replacement = "-----BEGIN PUBLIC KEY-----\nKEY2-REPLACED\n-----END PUBLIC KEY-----\n"
	body, _ := json.Marshal(map[string]any{"public_key": replacement, "expiration_date": "2030-01-01T00:00:00Z"})
	resp, got := do(t, "PUT", base+"/clients/web01/keys/key2", string(body))
	if resp.StatusCode != 200 {
		t.Fatalf("put key2 = %d: %s", resp.StatusCode, got)
	}
	var stored map[string]any
	json.Unmarshal([]byte(got), &stored)
	if stored["public_key"] != replacement {
		t.Errorf("public_key = %v, want the replacement", stored["public_key"])
	}
	if stored["name"] != "key2" {
		t.Errorf("name = %v, want key2 (pinned to the path)", stored["name"])
	}
}

// TestPutDefaultKeyRewritesActorPublicKey covers the synthetic-default branch:
// PUTting "default" when no stored default key exists rewrites the actor's own
// public_key.
func TestPutDefaultKeyRewritesActorPublicKey(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	do(t, "POST", base+"/clients", `{"name":"web01"}`)

	const newPub = "-----BEGIN PUBLIC KEY-----\nNEW-DEFAULT\n-----END PUBLIC KEY-----\n"
	body, _ := json.Marshal(map[string]any{"public_key": newPub})
	resp, got := do(t, "PUT", base+"/clients/web01/keys/default", string(body))
	if resp.StatusCode != 200 {
		t.Fatalf("put default = %d: %s", resp.StatusCode, got)
	}
	var key map[string]any
	json.Unmarshal([]byte(got), &key)
	if key["public_key"] != newPub {
		t.Errorf("returned default key public_key = %v, want the new key", key["public_key"])
	}
	// The actor record itself now carries the new public key.
	_, actorBody := do(t, "GET", base+"/clients/web01", "")
	var actor map[string]any
	json.Unmarshal([]byte(actorBody), &actor)
	if actor["public_key"] != newPub {
		t.Errorf("actor public_key = %v, want the rewritten key", actor["public_key"])
	}
}

// TestPutMissingNamedKey404 covers the not-found branch for a non-default key.
func TestPutMissingNamedKey404(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	do(t, "POST", base+"/clients", `{"name":"web01"}`)
	resp, _ := do(t, "PUT", base+"/clients/web01/keys/ghost", `{"public_key":"x"}`)
	if resp.StatusCode != 404 {
		t.Fatalf("put missing key = %d, want 404", resp.StatusCode)
	}
}

// TestContainerCreate covers createContainer: the containername field, the "id"
// alias, the missing-name error, and that a created container is retrievable.
func TestContainerCreate(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"

	if resp, body := do(t, "POST", base+"/containers", `{"containername":"reports"}`); resp.StatusCode != 201 {
		t.Fatalf("create container = %d: %s", resp.StatusCode, body)
	}
	if resp, body := do(t, "POST", base+"/containers", `{"id":"widgets"}`); resp.StatusCode != 201 {
		t.Fatalf("create container by id = %d: %s", resp.StatusCode, body)
	}
	if resp, _ := do(t, "POST", base+"/containers", `{}`); resp.StatusCode != 400 {
		t.Fatalf("create container without name = %d, want 400", resp.StatusCode)
	}
	if resp, body := do(t, "GET", base+"/containers/reports", ""); resp.StatusCode != 200 || !strings.Contains(body, "reports") {
		t.Fatalf("get created container = %d: %s", resp.StatusCode, body)
	}
}

// TestOrgACLSinglePermission covers getOrgACLPerm: a valid org permission and
// the 404 for an unknown one.
func TestOrgACLSinglePermission(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"

	resp, body := do(t, "GET", base+"/_acl/read", "")
	if resp.StatusCode != 200 {
		t.Fatalf("org acl read = %d: %s", resp.StatusCode, body)
	}
	var got map[string]aclPerm
	json.Unmarshal([]byte(body), &got)
	if _, ok := got["read"]; !ok || len(got) != 1 {
		t.Fatalf("single-permission response = %s", body)
	}
	if resp, _ := do(t, "GET", base+"/_acl/bogus", ""); resp.StatusCode != 404 {
		t.Fatalf("org acl bogus = %d, want 404", resp.StatusCode)
	}
}

// TestInviterAuthorized covers the invite-revocation authorization logic, whose
// branches decide whether an accepted invitation is still honored.
func TestInviterAuthorized(t *testing.T) {
	st := store.New()
	org, _ := st.CreateOrg("acme")
	seedAuthz(org)
	a := New(st)

	authorized, err := a.inviterAuthorized(org, "")
	if err != nil {
		t.Fatal(err)
	}
	if !authorized {
		t.Error("empty inviter (no authenticated actor) should be authorized")
	}

	if authorized, err = a.inviterAuthorized(org, "ghost"); err != nil {
		t.Fatal(err)
	} else if authorized {
		t.Error("unknown inviter should not be authorized")
	}

	// A global admin is always authorized, even without org membership.
	if err = st.Global().Put("users", "root", []byte(`{"username":"root","admin":true}`)); err != nil {
		t.Fatal(err)
	}
	if authorized, err = a.inviterAuthorized(org, "root"); err != nil {
		t.Fatal(err)
	} else if !authorized {
		t.Error("global-admin inviter should be authorized")
	}

	// A non-admin user that is not an org member is not authorized.
	if err = st.Global().Put("users", "alice", []byte(`{"username":"alice"}`)); err != nil {
		t.Fatal(err)
	}
	if authorized, err = a.inviterAuthorized(org, "alice"); err != nil {
		t.Fatal(err)
	} else if authorized {
		t.Error("non-member inviter should not be authorized")
	}

	// Associated, but not in the admins group: still not authorized.
	if err = org.Put(assocColl, "alice", []byte(`{"username":"alice"}`)); err != nil {
		t.Fatal(err)
	}
	if authorized, err = a.inviterAuthorized(org, "alice"); err != nil {
		t.Fatal(err)
	} else if authorized {
		t.Error("inviter outside the admins group should not be authorized")
	}

	// Now an admins-group member: authorized.
	if err = org.Put("groups", "admins", mustEncode(groupDoc("admins", []string{"alice"}, nil, nil))); err != nil {
		t.Fatal(err)
	}
	if authorized, err = a.inviterAuthorized(org, "alice"); err != nil {
		t.Fatal(err)
	} else if !authorized {
		t.Error("admins-group member inviter should be authorized")
	}
}
