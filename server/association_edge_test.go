package server

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// createUserKey creates a global user via the admin and returns its generated
// private key (PEM) so the caller can sign requests as that user.
func createUserKey(t *testing.T, srv *Server, name string) []byte {
	t.Helper()
	resp, err := http.DefaultClient.Do(signed(t, srv, "POST", srv.URL()+"/users",
		validUserBody(t, `{"name":"`+name+`"}`)))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create user %s = %d: %s", name, resp.StatusCode, raw)
	}
	var created struct {
		ChefKey struct {
			PrivateKey string `json:"private_key"`
		} `json:"chef_key"`
	}
	json.Unmarshal(raw, &created)
	if created.ChefKey.PrivateKey == "" {
		t.Fatalf("no private key for %s: %s", name, raw)
	}
	return []byte(created.ChefKey.PrivateKey)
}

func respStatus(t *testing.T, req *http.Request) int {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// Only the invited user may accept their own invitation.
func TestInviteAcceptOnlyByInvitee(t *testing.T) {
	srv := startServer(t, Options{})
	bobKey := createUserKey(t, srv, "bob")
	eveKey := createUserKey(t, srv, "eve")

	if s := respStatus(t, signed(t, srv, "POST", srv.URL()+"/organizations/acme/association_requests", `{"user":"bob"}`)); s != http.StatusCreated {
		t.Fatalf("invite bob = %d, want 201", s)
	}
	if s := respStatus(t, signedAs(t, "eve", eveKey, "PUT", srv.URL()+"/users/bob/association_requests/bob-acme", `{"response":"accept"}`)); s != http.StatusForbidden {
		t.Fatalf("eve accepting bob's invite = %d, want 403", s)
	}
	if s := respStatus(t, signedAs(t, "bob", bobKey, "PUT", srv.URL()+"/users/bob/association_requests/bob-acme", `{"response":"accept"}`)); s != http.StatusOK {
		t.Fatalf("bob accepting own invite = %d, want 200", s)
	}
}

// After removal, a user may no longer view the org or themselves (403), while
// an admin sees them as gone (404).
func TestPostRemovalAccess(t *testing.T) {
	srv := startServer(t, Options{})
	bobKey := createUserKey(t, srv, "bob")

	if s := respStatus(t, signed(t, srv, "POST", srv.URL()+"/organizations/acme/users", `{"username":"bob"}`)); s != http.StatusCreated {
		t.Fatalf("associate bob = %d, want 201", s)
	}
	if s := respStatus(t, signedAs(t, "bob", bobKey, "GET", srv.URL()+"/organizations/acme/users", "")); s != http.StatusOK {
		t.Fatalf("member list = %d, want 200", s)
	}
	if s := respStatus(t, signed(t, srv, "DELETE", srv.URL()+"/organizations/acme/users/bob", "")); s != http.StatusOK {
		t.Fatalf("remove bob = %d, want 200", s)
	}
	if s := respStatus(t, signedAs(t, "bob", bobKey, "GET", srv.URL()+"/organizations/acme/users", "")); s != http.StatusForbidden {
		t.Fatalf("removed list = %d, want 403", s)
	}
	if s := respStatus(t, signedAs(t, "bob", bobKey, "GET", srv.URL()+"/organizations/acme/users/bob", "")); s != http.StatusForbidden {
		t.Fatalf("removed self = %d, want 403", s)
	}
	if s := respStatus(t, signed(t, srv, "GET", srv.URL()+"/organizations/acme/users/bob", "")); s != http.StatusNotFound {
		t.Fatalf("admin get removed = %d, want 404", s)
	}
	if s := respStatus(t, signed(t, srv, "DELETE", srv.URL()+"/organizations/acme/users/bob", "")); s != http.StatusNotFound {
		t.Fatalf("admin delete removed = %d, want 404", s)
	}
}
