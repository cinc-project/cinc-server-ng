package server

import (
	"encoding/json"
	"net/http"
	"testing"
)

// The superuser flag is the stored record's "admin" member and nothing else.
// A member whose name differs only in case is ordinary profile data: a user
// who writes "Admin" into its own record must not become the superuser.
func TestSelfUpdateCaseVariantAdminIsInert(t *testing.T) {
	for _, field := range []string{"Admin", "ADMIN", "aDmIn"} {
		t.Run(field, func(t *testing.T) {
			srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
			key := []byte(createUser(t, srv, `{"name":"mallory"}`))
			admins := srv.URL() + "/_cinc/server_admins"

			if code := statusOf(t, signedAs(t, "mallory", key, "GET", admins, "")); code != http.StatusForbidden {
				t.Fatalf("baseline server_admins = %d, want 403", code)
			}
			if code := statusOf(t, signedAs(t, "mallory", key, "GET", srv.URL()+"/users", "")); code != http.StatusForbidden {
				t.Fatalf("baseline list users = %d, want 403", code)
			}

			body := validUserBody(t, `{"name":"mallory","`+field+`":true}`)
			if code := statusOf(t, signedAs(t, "mallory", key, "PUT", srv.URL()+"/users/mallory", body)); code != http.StatusOK {
				t.Fatalf("self update = %d, want 200", code)
			}

			if code := statusOf(t, signedAs(t, "mallory", key, "GET", admins, "")); code != http.StatusForbidden {
				t.Errorf("server_admins after %q:true = %d, want 403", field, code)
			}
			if code := statusOf(t, signedAs(t, "mallory", key, "GET", srv.URL()+"/users", "")); code != http.StatusForbidden {
				t.Errorf("list users after %q:true = %d, want 403", field, code)
			}
		})
	}
}

// A server-admin may create users but not superusers, whatever the case of
// the flag's name.
func TestServerAdminCreateCaseVariantAdminIsInert(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	u := srv.URL()
	alice := []byte(createUser(t, srv, `{"name":"alice"}`))
	if code, body := doBody(t, signed(t, srv, "PUT", u+"/_cinc/server_admins/alice", "")); code != http.StatusCreated {
		t.Fatalf("add alice = %d: %s", code, body)
	}

	code, body := doBody(t, signedAs(t, "alice", alice, "POST", u+"/users",
		withCreateKey(t, validUserBody(t, `{"name":"dave","Admin":true}`))))
	if code != http.StatusCreated {
		t.Fatalf("server-admin POST /users = %d: %s", code, body)
	}
	var created struct {
		ChefKey struct {
			PrivateKey string `json:"private_key"`
		} `json:"chef_key"`
	}
	if err := json.Unmarshal([]byte(body), &created); err != nil {
		t.Fatal(err)
	}
	dave := []byte(created.ChefKey.PrivateKey)
	if got := statusOf(t, signedAs(t, "dave", dave, "GET", u+"/organizations/acme/nodes", "")); got != http.StatusForbidden {
		t.Errorf("user created with Admin:true reads an org it is not in = %d, want 403", got)
	}
	if got := statusOf(t, signedAs(t, "dave", dave, "GET", u+"/_cinc/server_admins", "")); got != http.StatusForbidden {
		t.Errorf("user created with Admin:true reads server_admins = %d, want 403", got)
	}
}

// An actor's keys are its "public_key" member and its keys rows. A member
// whose name differs only in case is not a key: it must not authenticate once
// the real default key is gone, or it is a key the keys API never shows and a
// revocation never removes.
func TestCaseVariantPublicKeyDoesNotAuthenticate(t *testing.T) {
	for _, field := range []string{"PUBLIC_KEY", "Public_Key"} {
		t.Run("user/"+field, func(t *testing.T) {
			srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
			key := []byte(createUser(t, srv, `{"name":"mallory"}`))
			planted, plantedPub := newKeyPair(t)
			me := srv.URL() + "/users/mallory"

			if code := statusOf(t, signedAs(t, "mallory", planted, "GET", me, "")); code != http.StatusUnauthorized {
				t.Fatalf("baseline planted key = %d, want 401", code)
			}
			var obj map[string]any
			if err := json.Unmarshal([]byte(validUserBody(t, `{"name":"mallory"}`)), &obj); err != nil {
				t.Fatal(err)
			}
			obj[field] = plantedPub
			body, _ := json.Marshal(obj)
			if code, raw := doBody(t, signedAs(t, "mallory", key, "PUT", me, string(body))); code != http.StatusOK {
				t.Fatalf("self update = %d: %s", code, raw)
			}
			if code, raw := adminDo(t, srv, "DELETE", me+"/keys/default", ""); code != http.StatusOK {
				t.Fatalf("revoke default key = %d: %s", code, raw)
			}
			if code := statusOf(t, signedAs(t, "mallory", key, "GET", me, "")); code != http.StatusUnauthorized {
				t.Fatalf("revoked key = %d, want 401", code)
			}
			if code := statusOf(t, signedAs(t, "mallory", planted, "GET", me, "")); code != http.StatusUnauthorized {
				t.Errorf("planted %q key after revocation = %d, want 401", field, code)
			}
		})
		t.Run("client/"+field, func(t *testing.T) {
			srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
			base := srv.URL() + "/organizations/acme/clients"
			if code, raw := adminDo(t, srv, "POST", base, `{"name":"web01","create_key":true}`); code != http.StatusCreated {
				t.Fatalf("create client = %d: %s", code, raw)
			}
			planted, plantedPub := newKeyPair(t)
			if code := statusOf(t, signedAs(t, "web01", planted, "GET", base+"/web01", "")); code != http.StatusUnauthorized {
				t.Fatalf("baseline planted client key = %d, want 401", code)
			}
			body, _ := json.Marshal(map[string]any{"name": "web01", field: plantedPub})
			if code, raw := adminDo(t, srv, "PUT", base+"/web01", string(body)); code != http.StatusOK {
				t.Fatalf("update client = %d: %s", code, raw)
			}
			if code, raw := adminDo(t, srv, "DELETE", base+"/web01/keys/default", ""); code != http.StatusOK {
				t.Fatalf("revoke default key = %d: %s", code, raw)
			}
			if code := statusOf(t, signedAs(t, "web01", planted, "GET", base+"/web01", "")); code != http.StatusUnauthorized {
				t.Errorf("planted %q client key after revocation = %d, want 401", field, code)
			}
		})
	}
}

// A record that already holds case variants (written before they were
// dropped from request bodies, or by any other path into the store) grants
// nothing: authentication reads "admin" and "public_key" by exact name.
func TestStoredCaseVariantFieldsAreInert(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	key := []byte(createUser(t, srv, `{"name":"mallory"}`))
	me := srv.URL() + "/users/mallory"
	if code := statusOf(t, signedAs(t, "mallory", key, "GET", srv.URL()+"/users", "")); code != http.StatusForbidden {
		t.Fatalf("baseline list users = %d, want 403", code)
	}

	global := srv.store.Global()
	raw, ok, err := global.Get("users", "mallory")
	if err != nil || !ok {
		t.Fatalf("read mallory: ok=%v err=%v", ok, err)
	}
	var rec map[string]any
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	planted, plantedPub := newKeyPair(t)
	rec["Admin"] = true
	rec["PUBLIC_KEY"] = plantedPub
	out, _ := json.Marshal(rec)
	if err := global.Put("users", "mallory", out); err != nil {
		t.Fatal(err)
	}

	if code := statusOf(t, signedAs(t, "mallory", key, "GET", srv.URL()+"/users", "")); code != http.StatusForbidden {
		t.Errorf("list users with a stored Admin:true = %d, want 403", code)
	}
	if code, raw := adminDo(t, srv, "DELETE", me+"/keys/default", ""); code != http.StatusOK {
		t.Fatalf("revoke default key = %d: %s", code, raw)
	}
	if code := statusOf(t, signedAs(t, "mallory", planted, "GET", me, "")); code != http.StatusUnauthorized {
		t.Errorf("stored PUBLIC_KEY after revocation = %d, want 401", code)
	}
}

// A request body's case variants of "admin" and "public_key" are not stored.
func TestCaseVariantFieldsAreNotStored(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	key := []byte(createUser(t, srv, `{"name":"mallory"}`))
	_, plantedPub := newKeyPair(t)
	var obj map[string]any
	if err := json.Unmarshal([]byte(validUserBody(t, `{"name":"mallory","Admin":true}`)), &obj); err != nil {
		t.Fatal(err)
	}
	obj["Public_Key"] = plantedPub
	body, _ := json.Marshal(obj)
	if code, raw := doBody(t, signedAs(t, "mallory", key, "PUT", srv.URL()+"/users/mallory", string(body))); code != http.StatusOK {
		t.Fatalf("self update = %d: %s", code, raw)
	}
	raw, _, err := srv.store.Global().Get("users", "mallory")
	if err != nil {
		t.Fatal(err)
	}
	var rec map[string]any
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"Admin", "Public_Key"} {
		if _, ok := rec[field]; ok {
			t.Errorf("stored record keeps %q: %s", field, raw)
		}
	}
}
