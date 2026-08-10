package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tas50/cinc-server-ng/internal/auth"
)

// signedAs builds a request signed as an arbitrary actor (name + PEM key),
// letting tests act as someone other than the bootstrap admin.
func signedAs(t *testing.T, name string, keyPEM []byte, method, url, body string) *http.Request {
	t.Helper()
	key, err := auth.ParsePrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("parse key for %s: %v", name, err)
	}
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Ops-Server-API-Version", "1")
	ts := time.Now().UTC().Format(time.RFC3339)
	if err := auth.SignRequest(req, name, ts, []byte(body), key); err != nil {
		t.Fatalf("sign as %s: %v", name, err)
	}
	return req
}

func statusOf(t *testing.T, req *http.Request) int {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestEnforceACLRequiresAuth(t *testing.T) {
	_, err := New(Options{DisableAuth: true, EnforceACL: true})
	if err == nil {
		t.Fatal("New should reject EnforceACL together with DisableAuth")
	}
}

func TestEnforceACLEndToEnd(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	base := srv.URL() + "/organizations/acme"
	const validator = "acme-validator"
	vkey := srv.ValidatorKey("acme")

	// The admin (pivotal superuser) creates a node — bypasses ACLs.
	if code := statusOf(t, signed(t, srv, "POST", base+"/nodes", `{"name":"web01"}`)); code != 201 {
		t.Fatalf("admin create node = %d, want 201", code)
	}

	// The validator is an ordinary client in no group: it cannot read the node.
	if code := statusOf(t, signedAs(t, validator, vkey, "GET", base+"/nodes/web01", "")); code != 403 {
		t.Fatalf("validator read node = %d, want 403", code)
	}

	// A missing object reports 404 even to the unauthorized validator
	// (existence is checked before authorization).
	if code := statusOf(t, signedAs(t, validator, vkey, "GET", base+"/nodes/ghost", "")); code != 404 {
		t.Fatalf("validator read missing node = %d, want 404", code)
	}

	// The validator was seeded with create on the clients container, so it can
	// register a new client.
	if code := statusOf(t, signedAs(t, validator, vkey, "POST", base+"/clients", `{"name":"node1"}`)); code != 201 {
		t.Fatalf("validator create client = %d, want 201", code)
	}

	// The admin can still read the node.
	if code := statusOf(t, signed(t, srv, "GET", base+"/nodes/web01", "")); code != 200 {
		t.Fatalf("admin read node = %d, want 200", code)
	}
}

// TestEnforceACLGlobalUsers exercises the global /users gating end-to-end with
// real signatures: a non-admin user is denied the collection but may act on its
// own record, while the bootstrap admin (pivotal) may do either.
func TestEnforceACLGlobalUsers(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	users := srv.URL() + "/users"

	// The admin creates a non-admin user and we recover its generated key.
	resp, err := http.DefaultClient.Do(signed(t, srv, "POST", users, `{"name":"alice"}`))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Fatalf("admin create user = %d, want 201: %s", resp.StatusCode, body)
	}
	var created struct {
		ChefKey struct {
			PrivateKey string `json:"private_key"`
		} `json:"chef_key"`
	}
	if err := json.Unmarshal(body, &created); err != nil || created.ChefKey.PrivateKey == "" {
		t.Fatalf("no private key in create response: %s", body)
	}
	aliceKey := []byte(created.ChefKey.PrivateKey)

	// alice (a normal user) cannot list the global users collection...
	if code := statusOf(t, signedAs(t, "alice", aliceKey, "GET", users, "")); code != 403 {
		t.Fatalf("alice list users = %d, want 403", code)
	}
	// ...but may read her own record.
	if code := statusOf(t, signedAs(t, "alice", aliceKey, "GET", users+"/alice", "")); code != 200 {
		t.Fatalf("alice read self = %d, want 200", code)
	}
	// The admin may list the collection.
	if code := statusOf(t, signed(t, srv, "GET", users, "")); code != 200 {
		t.Fatalf("admin list users = %d, want 200", code)
	}
}

func TestEnforceACLOffByDefault(t *testing.T) {
	// With enforcement off (default), the validator — in no group — can still
	// read a node, preserving the permissive default.
	srv := startServer(t, Options{Orgs: []string{"acme"}})
	base := srv.URL() + "/organizations/acme"
	if code := statusOf(t, signed(t, srv, "POST", base+"/nodes", `{"name":"web01"}`)); code != 201 {
		t.Fatalf("admin create node = %d, want 201", code)
	}
	vkey := srv.ValidatorKey("acme")
	if code := statusOf(t, signedAs(t, "acme-validator", vkey, "GET", base+"/nodes/web01", "")); code != 200 {
		t.Fatalf("enforcement off: validator read node = %d, want 200", code)
	}
}
