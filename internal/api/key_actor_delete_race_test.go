package api

import (
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/cinc-project/cinc-server-ng/internal/auth"
	"github.com/cinc-project/cinc-server-ng/internal/store"
	"github.com/cinc-project/cinc-server-ng/internal/store/sqlite"
)

// A key write checks that its actor exists, may then spend a while generating
// a key pair, and writes. A delete of the actor landing in that window must not
// be undone: the key row would outlive the actor, and a "default" key write
// would re-create the deleted record holding the new key. These tests delete
// the actor from inside key generation, which is exactly that window.

// keyRaceAPI serves an API over st with one org, acme, and returns the API
// too, so a test can replace its key generator.
func keyRaceAPI(t *testing.T, st *store.Store) (*API, *httptest.Server) {
	t.Helper()
	if _, err := st.CreateOrg("acme"); err != nil {
		t.Fatal(err)
	}
	a := New(st)
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(srv.Close)
	return a, srv
}

// deleteDuringKeygen makes a's key generator first delete the resource at
// actorURL, then generate a key as usual.
func deleteDuringKeygen(t *testing.T, a *API, actorURL string) {
	a.generateKey = func() (*rsa.PrivateKey, error) {
		if resp, body := do(t, "DELETE", actorURL, ""); resp.StatusCode != http.StatusOK {
			t.Errorf("DELETE %s during keygen = %d: %s", actorURL, resp.StatusCode, body)
		}
		return auth.GenerateKey()
	}
}

func TestKeyWriteRacingActorDelete(t *testing.T) {
	cases := []struct {
		name string
		// setup runs against the existing client before the race, for a
		// request that needs a key in place or the default key gone.
		setup  func(t *testing.T, base string)
		method string
		path   string
		body   string
	}{
		{
			name:   "add named key",
			method: "POST", path: "/keys",
			body: `{"name":"late","create_key":true,"expiration_date":"infinity"}`,
		},
		{
			name: "add default key",
			setup: func(t *testing.T, base string) {
				mustStatus(t, "DELETE", base+"/keys/default", "", http.StatusOK)
			},
			method: "POST", path: "/keys",
			body: `{"name":"default","create_key":true,"expiration_date":"infinity"}`,
		},
		{
			name:   "regenerate synthetic default key",
			method: "PUT", path: "/keys/default",
			body: `{"create_key":true}`,
		},
		{
			name: "regenerate stored named key",
			setup: func(t *testing.T, base string) {
				mustStatus(t, "POST", base+"/keys", `{"name":"k1","create_key":true,"expiration_date":"infinity"}`, http.StatusCreated)
			},
			method: "PUT", path: "/keys/k1",
			body: `{"create_key":true}`,
		},
		{
			name: "regenerate stored default key",
			setup: func(t *testing.T, base string) {
				mustStatus(t, "PUT", base+"/keys/default", `{"expiration_date":"infinity"}`, http.StatusOK)
			},
			method: "PUT", path: "/keys/default",
			body: `{"create_key":true}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := store.New()
			a, srv := keyRaceAPI(t, st)
			base := srv.URL + "/organizations/acme/clients/web"
			mustStatus(t, "POST", srv.URL+"/organizations/acme/clients", `{"name":"web"}`, http.StatusCreated)
			if tc.setup != nil {
				tc.setup(t, base)
			}
			// Baseline: the request succeeds when nothing deletes the client.
			// The client is then made afresh for the race.
			if resp, body := do(t, tc.method, base+tc.path, tc.body); resp.StatusCode/100 != 2 {
				t.Fatalf("baseline %s %s = %d: %s", tc.method, tc.path, resp.StatusCode, body)
			}
			mustStatus(t, "DELETE", base, "", http.StatusOK)
			mustStatus(t, "POST", srv.URL+"/organizations/acme/clients", `{"name":"web"}`, http.StatusCreated)
			if tc.setup != nil {
				tc.setup(t, base)
			}

			deleteDuringKeygen(t, a, base)
			resp, body := do(t, tc.method, base+tc.path, tc.body)
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("%s %s with the client deleted meanwhile = %d, want 404: %s", tc.method, tc.path, resp.StatusCode, body)
			}
			org, _, err := st.Org("acme")
			if err != nil {
				t.Fatal(err)
			}
			if _, ok, _ := org.Get("clients", "web"); ok {
				t.Error("the deleted client was re-created by the key write")
			}
			if keys, _ := org.Keys(keysColl("clients", "web")); len(keys) != 0 {
				t.Errorf("deleted client still has key rows %v", keys)
			}
		})
	}
}

// The same window for a user, whose keys live in the global scope.
func TestUserDefaultKeyRacingUserDelete(t *testing.T) {
	st := store.New()
	a, srv := keyRaceAPI(t, st)
	base := srv.URL + "/users/bob"
	mustStatus(t, "POST", srv.URL+"/users", userBody(`{"name":"bob"}`), http.StatusCreated)
	mustStatus(t, "DELETE", base+"/keys/default", "", http.StatusOK)

	deleteDuringKeygen(t, a, base)
	resp, body := do(t, "POST", base+"/keys", `{"name":"default","create_key":true,"expiration_date":"infinity"}`)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("POST default key with the user deleted meanwhile = %d, want 404: %s", resp.StatusCode, body)
	}
	if _, ok, _ := st.Global().Get("users", "bob"); ok {
		t.Error("the deleted user was re-created by the key write")
	}
	if keys, _ := st.Global().Keys(keysColl("users", "bob")); len(keys) != 0 {
		t.Errorf("deleted user still has key rows %v", keys)
	}
}

// Key rows left under a name with no actor (by an older version, or a state
// directory) must not pass to an actor created later under that name.
func TestActorCreateClearsLeftoverKeys(t *testing.T) {
	backends := map[string]func(t *testing.T) *store.Store{
		"memory": func(t *testing.T) *store.Store { return store.New() },
		"sqlite": func(t *testing.T) *store.Store {
			be, err := sqlite.Open(filepath.Join(t.TempDir(), "keys.db"))
			if err != nil {
				t.Fatal(err)
			}
			st := store.NewWithBackend(be)
			t.Cleanup(func() { st.Close() })
			return st
		},
	}
	leftover := []byte(`{"name":"stale","public_key":"-----BEGIN PUBLIC KEY-----\nstale\n-----END PUBLIC KEY-----\n","expiration_date":"infinity"}`)
	for backend, open := range backends {
		t.Run(backend, func(t *testing.T) {
			st := open(t)
			_, srv := keyRaceAPI(t, st)
			org, _, err := st.Org("acme")
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range []struct {
				scope         *store.Org
				segment, name string
				create, body  string
			}{
				{org, "clients", "web", srv.URL + "/organizations/acme/clients", `{"name":"web"}`},
				// With a password the create is a transaction; without, one write.
				{st.Global(), "users", "bob", srv.URL + "/users", userBody(`{"name":"bob","password":"hunter2hunter2"}`)},
				{st.Global(), "users", "carol", srv.URL + "/users", userBody(`{"name":"carol"}`)},
			} {
				name := c.name
				coll := keysColl(c.segment, name)
				if err := c.scope.Put(coll, "stale", leftover); err != nil {
					t.Fatal(err)
				}
				// Baseline: the leftover row is there before the create.
				if keys, _ := c.scope.Keys(coll); len(keys) != 1 {
					t.Fatalf("%s/%s: leftover rows = %v, want [stale]", c.segment, name, keys)
				}
				mustStatus(t, "POST", c.create, c.body, http.StatusCreated)
				if keys, _ := c.scope.Keys(coll); len(keys) != 0 {
					t.Errorf("%s/%s: new actor inherited leftover key rows %v", c.segment, name, keys)
				}
			}
		})
	}
}

// A create refused because the actor exists must leave that actor's keys alone.
func TestActorCreateConflictKeepsKeys(t *testing.T) {
	st := store.New()
	_, srv := keyRaceAPI(t, st)
	clients := srv.URL + "/organizations/acme/clients"
	mustStatus(t, "POST", clients, `{"name":"web"}`, http.StatusCreated)
	mustStatus(t, "POST", clients+"/web/keys", `{"name":"k1","create_key":true,"expiration_date":"infinity"}`, http.StatusCreated)
	mustStatus(t, "POST", clients, `{"name":"web"}`, http.StatusConflict)
	org, _, _ := st.Org("acme")
	if keys, _ := org.Keys(keysColl("clients", "web")); len(keys) != 1 {
		t.Errorf("existing client's key rows after a refused create = %v, want [k1]", keys)
	}
}

func mustStatus(t *testing.T, method, url, body string, want int) {
	t.Helper()
	if resp, got := do(t, method, url, body); resp.StatusCode != want {
		t.Fatalf("%s %s = %d, want %d: %s", method, url, resp.StatusCode, want, got)
	}
}

// An actor update that regenerates the default key (API v0's "private_key":
// true, as knife client reregister sends) has the same window, and must not
// re-create an actor deleted in it.
func TestActorRegenerateRacingActorDelete(t *testing.T) {
	st := store.New()
	a, srv := keyRaceAPI(t, st)
	base := srv.URL + "/organizations/acme/clients/web"
	mustStatus(t, "POST", srv.URL+"/organizations/acme/clients", `{"name":"web"}`, http.StatusCreated)
	// Baseline: the regeneration succeeds when nothing deletes the client.
	mustStatus(t, "PUT", base, `{"name":"web","private_key":true}`, http.StatusOK)

	deleteDuringKeygen(t, a, base)
	resp, body := do(t, "PUT", base, `{"name":"web","private_key":true}`)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("PUT with the client deleted meanwhile = %d, want 404: %s", resp.StatusCode, body)
	}
	org, _, _ := st.Org("acme")
	if _, ok, _ := org.Get("clients", "web"); ok {
		t.Error("the deleted client was re-created by the update")
	}
}
