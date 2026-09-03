package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cinc-project/cinc-server-ng/internal/auth"
)

// webuiSignedAs signs a request with the server's webui key (the admin key by
// default) but attributes it to userID via X-Ops-Userid and marks it
// "X-Ops-Request-Source: web" — the Chef Infra Server mechanism a management
// console uses to act on a user's behalf.
func webuiSignedAs(t *testing.T, srv *Server, userID, method, url, body string) *http.Request {
	t.Helper()
	key, err := auth.ParsePrivateKey(srv.AdminKey())
	if err != nil {
		t.Fatalf("parse webui key: %v", err)
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
	req.Header.Set("X-Ops-Request-Source", "web")
	ts := time.Now().UTC().Format(time.RFC3339)
	if err := auth.SignRequest(req, userID, ts, []byte(body), key); err != nil {
		t.Fatalf("webui sign as %s: %v", userID, err)
	}
	return req
}

// createUser creates a global user as the admin and returns its private key.
func createUser(t *testing.T, srv *Server, body string) string {
	t.Helper()
	resp, err := http.DefaultClient.Do(signed(t, srv, "POST", srv.URL()+"/users", body))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create user = %d: %s", resp.StatusCode, raw)
	}
	var created struct {
		ChefKey struct {
			PrivateKey string `json:"private_key"`
		} `json:"chef_key"`
	}
	json.Unmarshal(raw, &created)
	return created.ChefKey.PrivateKey
}

// A webui-signed request authenticates as the impersonated user even though the
// signature is made with the webui (admin) key, not that user's key.
func TestWebUIImpersonationAuthenticatesAsUser(t *testing.T) {
	srv := startServer(t, Options{})
	createUser(t, srv, `{"name":"bob"}`)

	if got := statusOf(t, webuiSignedAs(t, srv, "bob", "GET",
		srv.URL()+"/organizations/acme/nodes", "")); got != http.StatusOK {
		t.Fatalf("webui-impersonated GET nodes = %d, want 200", got)
	}
}

// The "web" source only confers trust when the signature is made with the webui
// key. A request flagged web but signed with some other key is rejected.
func TestWebUISourceRequiresWebUIKey(t *testing.T) {
	srv := startServer(t, Options{})
	bobKey := createUser(t, srv, `{"name":"bob"}`)

	// Sign as bob's own key but claim web source while impersonating someone
	// else; this must NOT be honored.
	req := signedAs(t, "alice", []byte(bobKey), "GET",
		srv.URL()+"/organizations/acme/nodes", "")
	req.Header.Set("X-Ops-Request-Source", "web")
	if got := statusOf(t, req); got != http.StatusUnauthorized {
		t.Fatalf("web source with non-webui key = %d, want 401", got)
	}
}

// Without the web source header, the admin key cannot impersonate another user:
// the normal path verifies the signature against that user's own key.
func TestAdminKeyCannotImpersonateWithoutWebSource(t *testing.T) {
	srv := startServer(t, Options{})
	createUser(t, srv, `{"name":"bob"}`)

	req := signedAs(t, "bob", srv.AdminKey(), "GET",
		srv.URL()+"/organizations/acme/nodes", "")
	// no X-Ops-Request-Source header
	if got := statusOf(t, req); got != http.StatusUnauthorized {
		t.Fatalf("admin key impersonating bob without web source = %d, want 401", got)
	}
}

// A webui-sourced request may call authenticate_user even though the
// impersonated user is not an admin — the webui is trusted like the superuser
// for credential checks (how a console validates a login).
func TestWebUIImpersonationAllowsAuthenticateUser(t *testing.T) {
	srv := startServer(t, Options{})
	createUser(t, srv, `{"name":"carol","password":"p@ss"}`)

	resp, err := http.DefaultClient.Do(webuiSignedAs(t, srv, "carol", "POST",
		srv.URL()+"/authenticate_user", `{"username":"carol","password":"p@ss"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("webui authenticate_user = %d, want 200", resp.StatusCode)
	}
}
