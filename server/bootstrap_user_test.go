package server

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cinc-project/cinc-server-ng/internal/api"
)

// authenticates reports whether POST /authenticate_user accepts the password.
func authenticates(t *testing.T, srv *Server, user, password string) bool {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": user, "password": password})
	code, resp := doBody(t, signed(t, srv, "POST", srv.URL()+"/authenticate_user", string(body)))
	switch code {
	case http.StatusOK:
		return true
	case http.StatusUnauthorized:
		return false
	}
	t.Fatalf("POST /authenticate_user = %d: %s", code, resp)
	return false
}

// --bootstrap-user creates the first human admin: a password user the console
// can log in, in server-admins, and a member and admin of every --orgs org.
func TestBootstrapUser(t *testing.T) {
	srv := startServer(t, Options{
		Orgs: []string{"acme", "beta"}, EnforceACL: true,
		BootstrapUser: "alice", BootstrapPassword: "s3cret-pw",
	})
	u := srv.URL()
	as := func(method, path, body string) (int, string) {
		return doBody(t, webuiSignedAs(t, srv, "alice", method, u+path, body))
	}

	if !authenticates(t, srv, "alice", "s3cret-pw") {
		t.Fatal("alice cannot authenticate with the bootstrap password")
	}
	if authenticates(t, srv, "alice", "wrong-password") {
		t.Fatal("alice authenticates with a wrong password")
	}
	var user map[string]any
	getJSON(t, srv, u+"/users/alice", &user)
	if user["email"] != "alice@localhost.localdomain" || user["display_name"] != "alice" {
		t.Errorf("alice = %v, want the default email and display name", user)
	}
	if _, ok := user["password"]; ok {
		t.Errorf("alice's record carries its password: %v", user)
	}

	if admins := serverAdmins(t, srv); !slices.Contains(admins, "alice") {
		t.Errorf("server-admins = %v, want alice", admins)
	}
	if code, body := as("POST", "/users", validUserBody(t, `{"name":"bob"}`)); code != http.StatusCreated {
		t.Errorf("alice POST /users = %d, want 201: %s", code, body)
	}

	for _, org := range []string{"acme", "beta"} {
		code, body := as("GET", "/organizations/"+org+"/users", "")
		if code != http.StatusOK || !strings.Contains(body, `"username":"alice"`) {
			t.Errorf("GET %s/users as alice = %d %s, want alice listed", org, code, body)
		}
		for _, g := range []string{"users", "admins"} {
			if users := groupUsers(t, srv, org, g); !slices.Contains(users, "alice") {
				t.Errorf("%s %s group = %v, want alice", org, g, users)
			}
		}
		if code, body := as("POST", "/organizations/"+org+"/nodes", `{"name":"web1","json_class":"Chef::Node","chef_type":"node"}`); code != http.StatusCreated {
			t.Errorf("alice POST %s/nodes = %d, want 201: %s", org, code, body)
		}
		if code, body := as("POST", "/organizations/"+org+"/association_requests", `{"user":"bob"}`); code != http.StatusCreated {
			t.Errorf("alice invites bob to %s = %d, want 201: %s", org, code, body)
		}
	}
}

// Restarting on the same database keeps the user as it is (an operator may
// have rotated the password or edited the profile since) and only ensures its
// memberships, including in an org added to --orgs since.
func TestBootstrapUserRestartKeepsPassword(t *testing.T) {
	db := filepath.Join(t.TempDir(), "x.db")
	opts := Options{
		Orgs: []string{"acme"}, EnforceACL: true, Storage: "sqlite", DB: db,
		BootstrapUser: "alice", BootstrapPassword: "first-pw",
	}
	srv := startServer(t, opts)
	body := validUserBody(t, `{"name":"alice","display_name":"Alice A","email":"alice@example.com","password":"rotated-pw"}`)
	if code, resp := doBody(t, signed(t, srv, "PUT", srv.URL()+"/users/alice", body)); code != http.StatusOK {
		t.Fatalf("PUT /users/alice = %d: %s", code, resp)
	}
	stopServer(t, srv)

	opts.Orgs = []string{"acme", "beta"}
	opts.BootstrapPassword, opts.BootstrapEmail = "second-pw", "other@example.com"
	srv = startServer(t, opts)
	if !authenticates(t, srv, "alice", "rotated-pw") || authenticates(t, srv, "alice", "second-pw") {
		t.Error("restart changed alice's rotated password")
	}
	var user map[string]any
	getJSON(t, srv, srv.URL()+"/users/alice", &user)
	if user["display_name"] != "Alice A" || user["email"] != "alice@example.com" {
		t.Errorf("restart changed alice's profile: %v", user)
	}
	for _, org := range []string{"acme", "beta"} {
		for _, g := range []string{"users", "admins"} {
			if users := groupUsers(t, srv, org, g); !slices.Contains(users, "alice") {
				t.Errorf("%s %s group = %v, want alice", org, g, users)
			}
		}
	}
	if admins := serverAdmins(t, srv); !slices.Contains(admins, "alice") {
		t.Errorf("server-admins = %v, want alice", admins)
	}
}

func TestBootstrapUserOptionErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts Options
		want string
	}{
		{"no password", Options{BootstrapUser: "alice"}, "password"},
		{"password without user", Options{BootstrapPassword: "s3cret-pw"}, "BootstrapUser"},
		{"email without user", Options{BootstrapEmail: "a@example.com"}, "BootstrapUser"},
		{"short password", Options{BootstrapUser: "alice", BootstrapPassword: "abc"}, "at least 6"},
		{"bad name", Options{BootstrapUser: "Alice!", BootstrapPassword: "s3cret-pw"}, "Malformed user name"},
		{"bad email", Options{BootstrapUser: "alice", BootstrapPassword: "s3cret-pw", BootstrapEmail: "nope"}, "email"},
		{"admin name", Options{BootstrapUser: "pivotal", BootstrapPassword: "s3cret-pw"}, "pivotal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.opts)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("New = %v, want an error mentioning %q", err, tc.want)
			}
		})
	}
}

// The bootstrap user's password is stored hashed, the way POST /users stores
// one.
func TestBootstrapUserPasswordIsHashed(t *testing.T) {
	srv := startServer(t, Options{BootstrapUser: "alice", BootstrapPassword: "s3cret-pw"})
	stored, ok, err := srv.store.Global().Get(api.PasswordsCollection, "alice")
	if err != nil || !ok {
		t.Fatalf("stored password: ok=%v err=%v", ok, err)
	}
	if !api.IsPasswordHash(stored) {
		t.Errorf("stored password %q is not a hash", stored)
	}
}
