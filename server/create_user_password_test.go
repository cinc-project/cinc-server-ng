package server

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

// A POST /users naming a user that already exists is refused with 409 and
// changes nothing: in particular not the existing user's password, or a
// server-admin could set the superuser's password (or anyone's) through a
// create it is refused, then log in as that user through authenticate_user.
func TestCreateExistingUserKeepsPassword(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			opts := Options{Orgs: []string{"acme"}, EnforceACL: true}
			if backend == "sqlite" {
				opts.Storage, opts.DB = "sqlite", filepath.Join(t.TempDir(), "x.db")
			}
			srv := startServer(t, opts)
			u := srv.URL()
			alice := []byte(createUser(t, srv, `{"name":"alice"}`))
			createUser(t, srv, `{"name":"bob","password":"bob-old-pw"}`)
			if code, body := doBody(t, signed(t, srv, "PUT", u+"/_cinc/server_admins/alice", "")); code != http.StatusCreated {
				t.Fatalf("add alice to server-admins = %d: %s", code, body)
			}
			login := func(name, pw string) int {
				return statusOf(t, signed(t, srv, "POST", u+"/authenticate_user",
					`{"username":"`+name+`","password":"`+pw+`"}`))
			}

			// Baseline: bob logs in with his own password only, and the
			// superuser has no password "taken-pw".
			if got := login("bob", "bob-old-pw"); got != http.StatusOK {
				t.Fatalf("baseline: bob with his password = %d, want 200", got)
			}
			for _, c := range [][2]string{{"bob", "taken-pw"}, {"pivotal", "taken-pw"}} {
				if got := login(c[0], c[1]); got != http.StatusUnauthorized {
					t.Fatalf("baseline: %s with password %q = %d, want 401", c[0], c[1], got)
				}
			}

			for _, name := range []string{"bob", "pivotal"} {
				code, body := doBody(t, signedAs(t, "alice", alice, "POST", u+"/users",
					validUserBody(t, `{"name":"`+name+`","password":"taken-pw"}`)))
				if code != http.StatusConflict {
					t.Fatalf("server-admin POST /users %s = %d: %s, want 409", name, code, body)
				}
				if want := `{"error":["Object already exists"]}`; strings.TrimSpace(body) != want {
					t.Errorf("POST /users %s 409 body = %s, want %s", name, body, want)
				}
				if got := login(name, "taken-pw"); got != http.StatusUnauthorized {
					t.Errorf("%s with the password from a refused create = %d, want 401", name, got)
				}
			}
			if got := login("bob", "bob-old-pw"); got != http.StatusOK {
				t.Errorf("bob with his own password after the refused create = %d, want 200", got)
			}
		})
	}
}
