package server

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// A user may edit its own record (classifyUsers grants allowSelf), and the
// authentication layer reads "admin" back out of that same record to decide
// whether the actor bypasses every ACL. So a self-update must not be able to
// set it: otherwise any authenticated user is one PUT away from being the
// superuser.
func TestSelfUpdateCannotGrantAdmin(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	acme := srv.URL() + "/organizations/acme"
	key := []byte(createUser(t, srv, `{"name":"mallory"}`))

	if code := statusOf(t, signed(t, srv, "POST", acme+"/nodes", `{"name":"web01"}`)); code != 201 {
		t.Fatalf("admin create node = %d, want 201", code)
	}
	// Baseline: an ordinary user reaches neither the global collection nor
	// another actor's node.
	if code := statusOf(t, signedAs(t, "mallory", key, "GET", srv.URL()+"/users", "")); code != 403 {
		t.Fatalf("baseline list users = %d, want 403", code)
	}

	// The self-update itself is allowed — it is how a user maintains its profile.
	if code := statusOf(t, signedAs(t, "mallory", key, "PUT", srv.URL()+"/users/mallory",
		`{"name":"mallory","admin":true}`)); code != 200 {
		t.Fatalf("self update = %d, want 200", code)
	}

	// ...but it must not have made her the superuser.
	if code := statusOf(t, signedAs(t, "mallory", key, "GET", srv.URL()+"/users", "")); code != 403 {
		t.Errorf("list users after self-granted admin = %d, want 403", code)
	}
	if code := statusOf(t, signedAs(t, "mallory", key, "GET", acme+"/nodes/web01", "")); code != 403 {
		t.Errorf("read foreign node after self-granted admin = %d, want 403", code)
	}
}

// The superuser remains able to grant and revoke admin, so the flag is still
// administrable — it is only self-service that cannot reach it.
func TestSuperuserCanGrantAndRevokeAdmin(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	users := srv.URL() + "/users"
	key := []byte(createUser(t, srv, `{"name":"trent"}`))

	if code := statusOf(t, signed(t, srv, "PUT", users+"/trent", `{"name":"trent","admin":true}`)); code != 200 {
		t.Fatalf("admin grants admin = %d, want 200", code)
	}
	if code := statusOf(t, signedAs(t, "trent", key, "GET", users, "")); code != 200 {
		t.Errorf("promoted user list users = %d, want 200", code)
	}
	if code := statusOf(t, signed(t, srv, "PUT", users+"/trent", `{"name":"trent"}`)); code != 200 {
		t.Fatalf("admin revokes admin = %d, want 200", code)
	}
	if code := statusOf(t, signedAs(t, "trent", key, "GET", users, "")); code != 403 {
		t.Errorf("demoted user list users = %d, want 403", code)
	}
}

// A user's own key rotation must keep working: it goes through the same
// self-service PUT, and locking it out would break ordinary credential
// maintenance.
func TestSelfUpdatePreservesOwnProfileFields(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	key := []byte(createUser(t, srv, `{"name":"nina","email":"nina@example.com"}`))

	req := signedAs(t, "nina", key, "PUT", srv.URL()+"/users/nina",
		`{"name":"nina","email":"nina@example.invalid"}`)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("self update = %d, want 200: %s", resp.StatusCode, body)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got["email"] != "nina@example.invalid" {
		t.Errorf("email = %v, want the updated address", got["email"])
	}
	if _, ok := got["admin"]; ok {
		t.Errorf("a non-admin user's record grew an admin field: %s", body)
	}
	if got["public_key"] == nil || got["public_key"] == "" {
		t.Errorf("self update dropped the user's public_key: %s", body)
	}
}
