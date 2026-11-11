package server

import (
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"slices"
	"testing"
)

// doBody sends req and returns its status and body.
func doBody(t *testing.T, req *http.Request) (int, string) {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

// serverAdmins lists the server-admins group through the superuser.
func serverAdmins(t *testing.T, srv *Server) []string {
	t.Helper()
	code, body := doBody(t, signed(t, srv, "GET", srv.URL()+"/_cinc/server_admins", ""))
	if code != http.StatusOK {
		t.Fatalf("GET /_cinc/server_admins = %d: %s", code, body)
	}
	var doc struct {
		Users []string `json:"users"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	return doc.Users
}

// A server-admins member holds what erchef's bootstrap grants the group
// (create, read, update and delete on the users container, inherited by every
// user created after it) and nothing more: no grant, so no user _acl; nothing on
// a superuser, which predates the group; nothing in an organization.
func TestServerAdminManagesUsers(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			opts := Options{Orgs: []string{"acme"}, EnforceACL: true}
			if backend == "sqlite" {
				opts.Storage, opts.DB = "sqlite", filepath.Join(t.TempDir(), "x.db")
			}
			srv := startServer(t, opts)
			u := srv.URL()
			alice := []byte(createUser(t, srv, `{"name":"alice"}`))
			createUser(t, srv, `{"name":"bob"}`)
			as := func(method, path, body string) int {
				return statusOf(t, signedAs(t, "alice", alice, method, u+path, body))
			}

			userOps := []struct{ method, path, body string }{
				{"GET", "/users", ""},
				{"GET", "/users/bob", ""},
				{"PUT", "/users/bob", validUserBody(t, `{"name":"bob","display_name":"Robert"}`)},
				{"GET", "/users/bob/keys", ""},
				{"GET", "/users/bob/keys/default", ""},
			}
			// Baseline: an ordinary user manages no one but itself.
			for _, op := range userOps {
				if got := as(op.method, op.path, op.body); got != http.StatusForbidden {
					t.Fatalf("before server-admins, %s %s = %d, want 403", op.method, op.path, got)
				}
			}
			if got := as("POST", "/users", validUserBody(t, `{"name":"carol"}`)); got != http.StatusForbidden {
				t.Fatalf("before server-admins, POST /users = %d, want 403", got)
			}

			if code, body := doBody(t, signed(t, srv, "PUT", u+"/_cinc/server_admins/alice", "")); code != http.StatusCreated {
				t.Fatalf("add alice to server-admins = %d: %s", code, body)
			}

			for _, op := range userOps {
				if got := as(op.method, op.path, op.body); got != http.StatusOK {
					t.Errorf("server-admin %s %s = %d, want 200", op.method, op.path, got)
				}
			}
			if got := as("POST", "/users", validUserBody(t, `{"name":"carol"}`)); got != http.StatusCreated {
				t.Errorf("server-admin POST /users = %d, want 201", got)
			}
			if got := as("DELETE", "/users/carol", ""); got != http.StatusOK {
				t.Errorf("server-admin DELETE /users/carol = %d, want 200", got)
			}
			if got := as("GET", "/users/ghost", ""); got != http.StatusNotFound {
				t.Errorf("server-admin GET /users/ghost = %d, want 404", got)
			}

			// What the group does not hold.
			for _, op := range []struct{ method, path, body string }{
				{"GET", "/users/pivotal", ""},
				{"PUT", "/users/pivotal", validUserBody(t, `{"name":"pivotal","display_name":"x"}`)},
				{"DELETE", "/users/pivotal", ""},
				{"GET", "/users/pivotal/keys", ""},
				{"POST", "/users/pivotal/keys", `{"name":"k2","public_key":"x","expiration_date":"infinity"}`},
				{"GET", "/users/bob/_acl", ""},
				{"PUT", "/users/bob/_acl/read", `{"read":{"actors":["alice"],"groups":[]}}`},
				{"POST", "/organizations", `{"name":"evil","full_name":"Evil"}`},
				{"GET", "/organizations/acme/nodes", ""},
				{"POST", "/organizations/acme/users", `{"username":"alice"}`},
				{"GET", "/_cinc/server_admins", ""},
				{"PUT", "/_cinc/server_admins/bob", ""},
				{"DELETE", "/_cinc/server_admins/alice", ""},
			} {
				if got := as(op.method, op.path, op.body); got != http.StatusForbidden {
					t.Errorf("server-admin %s %s = %d, want 403", op.method, op.path, got)
				}
			}
		})
	}
}

// The superuser flag is not part of what server-admins may set: a user it
// creates or updates with "admin": true does not become a superuser.
func TestServerAdminCannotMintSuperuser(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	u := srv.URL()
	alice := []byte(createUser(t, srv, `{"name":"alice"}`))
	bobKey := []byte(createUser(t, srv, `{"name":"bob"}`))
	if code, body := doBody(t, signed(t, srv, "PUT", u+"/_cinc/server_admins/alice", "")); code != http.StatusCreated {
		t.Fatalf("add alice = %d: %s", code, body)
	}

	code, body := doBody(t, signedAs(t, "alice", alice, "POST", u+"/users",
		withCreateKey(t, validUserBody(t, `{"name":"dave","admin":true}`))))
	if code != http.StatusCreated {
		t.Fatalf("server-admin POST /users = %d: %s", code, body)
	}
	var created struct {
		ChefKey struct {
			PrivateKey string `json:"private_key"`
		} `json:"chef_key"`
	}
	json.Unmarshal([]byte(body), &created)
	dave := []byte(created.ChefKey.PrivateKey)
	if got := statusOf(t, signedAs(t, "dave", dave, "GET", u+"/organizations/acme/nodes", "")); got != http.StatusForbidden {
		t.Errorf("user created with admin:true by a server-admin reads an org it is not in = %d, want 403", got)
	}

	if got := statusOf(t, signedAs(t, "alice", alice, "PUT", u+"/users/bob",
		validUserBody(t, `{"name":"bob","admin":true}`))); got != http.StatusOK {
		t.Fatalf("server-admin PUT /users/bob = %d", got)
	}
	if got := statusOf(t, signedAs(t, "bob", bobKey, "GET", u+"/organizations/acme/nodes", "")); got != http.StatusForbidden {
		t.Errorf("user updated with admin:true by a server-admin reads an org it is not in = %d, want 403", got)
	}
}

// /_cinc/server_admins is how membership is managed (chef-server-ctl
// grant-server-admin-permissions, remove-server-admin-permissions and
// list-server-admins write bifrost directly; erchef has no route for it).
func TestServerAdminsMembershipEndpoint(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	u := srv.URL() + "/_cinc/server_admins"
	createUser(t, srv, `{"name":"alice"}`)

	// The bootstrap superuser is a member, as chef-server-ctl's bootstrap makes it.
	if got := serverAdmins(t, srv); !slices.Equal(got, []string{"pivotal"}) {
		t.Fatalf("initial server-admins = %v, want [pivotal]", got)
	}
	for _, c := range []struct {
		method, path string
		want         int
	}{
		{"PUT", "/ghost", http.StatusNotFound},
		{"PUT", "/alice", http.StatusCreated},
		{"PUT", "/alice", http.StatusOK},
		{"DELETE", "/pivotal", http.StatusBadRequest},
		{"POST", "", http.StatusMethodNotAllowed},
	} {
		if code, body := doBody(t, signed(t, srv, c.method, u+c.path, "")); code != c.want {
			t.Errorf("%s %s = %d, want %d: %s", c.method, c.path, code, c.want, body)
		}
	}
	if got := serverAdmins(t, srv); !slices.Equal(got, []string{"alice", "pivotal"}) {
		t.Fatalf("server-admins = %v, want [alice pivotal]", got)
	}
	if code, body := doBody(t, signed(t, srv, "DELETE", u+"/alice", "")); code != http.StatusOK {
		t.Fatalf("DELETE alice = %d: %s", code, body)
	}
	if code, _ := doBody(t, signed(t, srv, "DELETE", u+"/alice", "")); code != http.StatusNotFound {
		t.Errorf("DELETE a non-member = %d, want 404", code)
	}
}

// Deleting a user drops its server-admins membership: membership names the
// user by bare name, so a user created later under that name would otherwise
// inherit it.
func TestDeletingAUserRevokesServerAdmin(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	u := srv.URL()
	createUser(t, srv, `{"name":"alice"}`)
	if code, body := doBody(t, signed(t, srv, "PUT", u+"/_cinc/server_admins/alice", "")); code != http.StatusCreated {
		t.Fatalf("add alice = %d: %s", code, body)
	}
	if code, body := doBody(t, signed(t, srv, "DELETE", u+"/users/alice", "")); code != http.StatusOK {
		t.Fatalf("DELETE /users/alice = %d: %s", code, body)
	}
	if got := serverAdmins(t, srv); slices.Contains(got, "alice") {
		t.Fatalf("server-admins after deleting alice = %v", got)
	}
	alice := []byte(createUser(t, srv, `{"name":"alice"}`))
	if got := statusOf(t, signedAs(t, "alice", alice, "GET", u+"/users", "")); got != http.StatusForbidden {
		t.Errorf("a new user under a deleted server-admin's name GET /users = %d, want 403", got)
	}
}
