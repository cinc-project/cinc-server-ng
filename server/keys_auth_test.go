package server

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/cinc-project/cinc-server-ng/internal/auth"
)

// Real Chef authenticates an actor with any key in its keys collection that has
// not expired. These tests sign real requests with keys managed through the keys
// API and check which of them the server accepts.

// adminDo sends a request signed by the bootstrap admin and returns the status
// and body, failing the test on a transport error.
func adminDo(t *testing.T, srv *Server, method, url, body string) (int, []byte) {
	t.Helper()
	resp, err := http.DefaultClient.Do(signed(t, srv, method, url, body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

// addKey POSTs body to a keys collection as the admin, requires a 201, and
// returns the private key the server generated (empty when the body supplied
// a public key).
func addKey(t *testing.T, srv *Server, keysURL, body string) []byte {
	t.Helper()
	code, raw := adminDo(t, srv, "POST", keysURL, body)
	if code != http.StatusCreated {
		t.Fatalf("POST %s %s = %d: %s", keysURL, body, code, raw)
	}
	var out struct {
		PrivateKey string `json:"private_key"`
	}
	json.Unmarshal(raw, &out)
	return []byte(out.PrivateKey)
}

// newKeyPair returns a fresh private key PEM and its public key PEM.
func newKeyPair(t *testing.T) (priv []byte, pub string) {
	t.Helper()
	key, err := auth.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err := auth.EncodePublicKeyPEM(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return auth.EncodePrivateKeyPEM(key), string(pubPEM)
}

func wantAuth(t *testing.T, what string, got, want int) {
	t.Helper()
	if got != want {
		t.Fatalf("%s: status = %d, want %d", what, got, want)
	}
}

func TestClientAddedKeysAuthenticate(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}})
	base := srv.URL() + "/organizations/acme"
	defKey := createClientAndKey(t, srv, base, "web01")
	probe := base + "/nodes"
	keys := base + "/clients/web01/keys"

	generated := addKey(t, srv, keys, `{"name":"generated","create_key":true,"expiration_date":"infinity"}`)
	suppliedPriv, suppliedPub := newKeyPair(t)
	body, _ := json.Marshal(map[string]string{"name": "supplied", "public_key": suppliedPub, "expiration_date": "infinity"})
	addKey(t, srv, keys, string(body))
	stranger, _ := newKeyPair(t)

	// Baseline: a key the client does not hold is refused.
	wantAuth(t, "unregistered key", statusOf(t, signedAs(t, "web01", stranger, "GET", probe, "")), 401)

	wantAuth(t, "default key", statusOf(t, signedAs(t, "web01", defKey, "GET", probe, "")), 200)
	wantAuth(t, "generated key", statusOf(t, signedAs(t, "web01", generated, "GET", probe, "")), 200)
	wantAuth(t, "supplied key", statusOf(t, signedAs(t, "web01", suppliedPriv, "GET", probe, "")), 200)

	// A key authenticates only the actor that holds it.
	createClientAndKey(t, srv, base, "web02")
	wantAuth(t, "web01's key signing as web02", statusOf(t, signedAs(t, "web02", generated, "GET", probe, "")), 401)

	// Deleting a key revokes it and leaves the others alone.
	if code, raw := adminDo(t, srv, "DELETE", keys+"/generated", ""); code != 200 {
		t.Fatalf("delete generated = %d: %s", code, raw)
	}
	wantAuth(t, "deleted key", statusOf(t, signedAs(t, "web01", generated, "GET", probe, "")), 401)
	wantAuth(t, "supplied key after delete", statusOf(t, signedAs(t, "web01", suppliedPriv, "GET", probe, "")), 200)
	wantAuth(t, "default key after delete", statusOf(t, signedAs(t, "web01", defKey, "GET", probe, "")), 200)
}

func TestUserAddedKeysAuthenticate(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}})
	createUserKey(t, srv, "alice")
	probe := srv.URL() + "/users/alice"
	keys := srv.URL() + "/users/alice/keys"
	stranger, _ := newKeyPair(t)
	wantAuth(t, "unregistered key", statusOf(t, signedAs(t, "alice", stranger, "GET", probe, "")), 401)

	laptop := addKey(t, srv, keys, `{"name":"laptop","create_key":true,"expiration_date":"infinity"}`)
	wantAuth(t, "added key", statusOf(t, signedAs(t, "alice", laptop, "GET", probe, "")), 200)

	if code, raw := adminDo(t, srv, "DELETE", keys+"/laptop", ""); code != 200 {
		t.Fatalf("delete laptop = %d: %s", code, raw)
	}
	wantAuth(t, "deleted key", statusOf(t, signedAs(t, "alice", laptop, "GET", probe, "")), 401)
}

func TestExpiredKeysDoNotAuthenticate(t *testing.T) {
	t.Run("memory", func(t *testing.T) {
		testExpiredKeysDoNotAuthenticate(t, Options{Orgs: []string{"acme"}})
	})
	t.Run("sqlite", func(t *testing.T) {
		testExpiredKeysDoNotAuthenticate(t, Options{Orgs: []string{"acme"}, Storage: "sqlite", DB: t.TempDir() + "/keys.db"})
	})
}

func testExpiredKeysDoNotAuthenticate(t *testing.T, opts Options) {
	srv := startServer(t, opts)
	base := srv.URL() + "/organizations/acme"
	defKey := createClientAndKey(t, srv, base, "web01")
	probe := base + "/nodes"
	keys := base + "/clients/web01/keys"

	expired := addKey(t, srv, keys, `{"name":"old","create_key":true,"expiration_date":"2020-01-01T00:00:00Z"}`)
	current := addKey(t, srv, keys, `{"name":"new","create_key":true,"expiration_date":"2099-01-01T00:00:00Z"}`)

	wantAuth(t, "expired key", statusOf(t, signedAs(t, "web01", expired, "GET", probe, "")), 401)
	wantAuth(t, "unexpired key", statusOf(t, signedAs(t, "web01", current, "GET", probe, "")), 200)
	wantAuth(t, "default key", statusOf(t, signedAs(t, "web01", defKey, "GET", probe, "")), 200)

	// The key list reports which keys have expired.
	code, raw := adminDo(t, srv, "GET", keys, "")
	if code != 200 {
		t.Fatalf("list keys = %d: %s", code, raw)
	}
	var list []struct {
		Name    string `json:"name"`
		Expired bool   `json:"expired"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, k := range list {
		got[k.Name] = k.Expired
	}
	want := map[string]bool{"default": false, "old": true, "new": false}
	for name, exp := range want {
		if e, ok := got[name]; !ok || e != exp {
			t.Errorf("key %q expired = %v (listed %v), want %v; list: %s", name, e, ok, exp, raw)
		}
	}
}

// A client whose default key is deleted and re-created (what `knife client
// reregister` does under API v1) signs with the new key, not the old one.
func TestRecreatedDefaultKeyAuthenticates(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}})
	base := srv.URL() + "/organizations/acme"
	oldKey := createClientAndKey(t, srv, base, "web01")
	probe := base + "/nodes"
	keys := base + "/clients/web01/keys"

	if code, raw := adminDo(t, srv, "DELETE", keys+"/default", ""); code != 200 {
		t.Fatalf("delete default = %d: %s", code, raw)
	}
	wantAuth(t, "deleted default key", statusOf(t, signedAs(t, "web01", oldKey, "GET", probe, "")), 401)

	newKey := addKey(t, srv, keys, `{"name":"default","create_key":true,"expiration_date":"infinity"}`)
	wantAuth(t, "re-created default key", statusOf(t, signedAs(t, "web01", newKey, "GET", probe, "")), 200)
	wantAuth(t, "old default key", statusOf(t, signedAs(t, "web01", oldKey, "GET", probe, "")), 401)
}

// The default key made with the client expires like any other once a PUT
// gives it an expiration_date, and deleting it afterwards revokes it.
func TestDefaultKeyExpirationIsEnforced(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}})
	base := srv.URL() + "/organizations/acme"
	defKey := createClientAndKey(t, srv, base, "web01")
	probe := base + "/nodes"
	keyURL := base + "/clients/web01/keys/default"
	priv, err := auth.ParsePrivateKey(defKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err := auth.EncodePublicKeyPEM(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	put := func(expiration string) {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"name": "default", "public_key": string(pubPEM), "expiration_date": expiration})
		if code, raw := adminDo(t, srv, "PUT", keyURL, string(body)); code != 200 {
			t.Fatalf("PUT default %s = %d: %s", expiration, code, raw)
		}
	}

	put("2099-01-01T00:00:00Z")
	wantAuth(t, "default key expiring in the future", statusOf(t, signedAs(t, "web01", defKey, "GET", probe, "")), 200)
	put("2020-01-01T00:00:00Z")
	wantAuth(t, "expired default key", statusOf(t, signedAs(t, "web01", defKey, "GET", probe, "")), 401)
	put("infinity")
	wantAuth(t, "default key made non-expiring again", statusOf(t, signedAs(t, "web01", defKey, "GET", probe, "")), 200)

	if code, raw := adminDo(t, srv, "DELETE", keyURL, ""); code != 200 {
		t.Fatalf("delete default = %d: %s", code, raw)
	}
	wantAuth(t, "deleted default key", statusOf(t, signedAs(t, "web01", defKey, "GET", probe, "")), 401)
	if code, raw := adminDo(t, srv, "GET", keyURL, ""); code != 404 {
		t.Fatalf("GET deleted default = %d, want 404: %s", code, raw)
	}
}

// A client update that carries a public_key still rotates the default key
// after the default key has been re-created through the keys API.
func TestActorUpdateRotatesRecreatedDefaultKey(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}})
	base := srv.URL() + "/organizations/acme"
	createClientAndKey(t, srv, base, "web01")
	probe := base + "/nodes"
	keys := base + "/clients/web01/keys"
	if code, raw := adminDo(t, srv, "DELETE", keys+"/default", ""); code != 200 {
		t.Fatalf("delete default = %d: %s", code, raw)
	}
	reregistered := addKey(t, srv, keys, `{"name":"default","create_key":true,"expiration_date":"infinity"}`)

	rotatedPriv, rotatedPub := newKeyPair(t)
	body, _ := json.Marshal(map[string]any{"name": "web01", "public_key": rotatedPub})
	if code, raw := adminDo(t, srv, "PUT", base+"/clients/web01", string(body)); code != 200 {
		t.Fatalf("PUT client = %d: %s", code, raw)
	}
	wantAuth(t, "rotated key", statusOf(t, signedAs(t, "web01", rotatedPriv, "GET", probe, "")), 200)
	wantAuth(t, "replaced key", statusOf(t, signedAs(t, "web01", reregistered, "GET", probe, "")), 401)
}

// Now that added keys authenticate, adding one to another actor would be an
// account takeover. Under enforcement a plain client may not, and the key it
// tried to plant does not sign as the victim.
func TestEnforcedKeyAddCannotTakeOverAnotherActor(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	base := srv.URL() + "/organizations/acme"
	mallory := createClientAndKey(t, srv, base, "mallory")
	createClientAndKey(t, srv, base, "victim")
	createUserKey(t, srv, "alice")
	eve := createUserKey(t, srv, "eve")
	probe := base + "/clients/victim"

	plantedPriv, plantedPub := newKeyPair(t)
	body, _ := json.Marshal(map[string]string{"name": "planted", "public_key": plantedPub, "expiration_date": "infinity"})
	// Baseline: the planted key does not sign as the victim.
	wantAuth(t, "planted key before the attempt", statusOf(t, signedAs(t, "victim", plantedPriv, "GET", probe, "")), 401)

	wantAuth(t, "client adding a key to another client",
		statusOf(t, signedAs(t, "mallory", mallory, "POST", base+"/clients/victim/keys", string(body))), 403)
	wantAuth(t, "user adding a key to another user",
		statusOf(t, signedAs(t, "eve", eve, "POST", srv.URL()+"/users/alice/keys", string(body))), 403)
	wantAuth(t, "planted key as the client", statusOf(t, signedAs(t, "victim", plantedPriv, "GET", probe, "")), 401)
	wantAuth(t, "planted key as the user", statusOf(t, signedAs(t, "alice", plantedPriv, "GET", srv.URL()+"/users/alice", "")), 401)
}

// Deleting an actor must take its keys with it: a later actor registered
// under the same name must not inherit them.
func TestDeletedActorKeysDoNotAuthenticateSuccessor(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}})
	base := srv.URL() + "/organizations/acme"
	createClientAndKey(t, srv, base, "web01")
	probe := base + "/nodes"
	extra := addKey(t, srv, base+"/clients/web01/keys", `{"name":"extra","create_key":true,"expiration_date":"infinity"}`)
	wantAuth(t, "added key", statusOf(t, signedAs(t, "web01", extra, "GET", probe, "")), 200)

	if code, raw := adminDo(t, srv, "DELETE", base+"/clients/web01", ""); code != 200 {
		t.Fatalf("delete client = %d: %s", code, raw)
	}
	wantAuth(t, "key of a deleted client", statusOf(t, signedAs(t, "web01", extra, "GET", probe, "")), 401)
	createClientAndKey(t, srv, base, "web01")
	wantAuth(t, "predecessor's key", statusOf(t, signedAs(t, "web01", extra, "GET", probe, "")), 401)

	// The same holds for users.
	createUserKey(t, srv, "alice")
	laptop := addKey(t, srv, srv.URL()+"/users/alice/keys", `{"name":"laptop","create_key":true,"expiration_date":"infinity"}`)
	if code, raw := adminDo(t, srv, "DELETE", srv.URL()+"/users/alice", ""); code != 200 {
		t.Fatalf("delete user = %d: %s", code, raw)
	}
	createUserKey(t, srv, "alice")
	wantAuth(t, "predecessor user's key", statusOf(t, signedAs(t, "alice", laptop, "GET", srv.URL()+"/users/alice", "")), 401)
}
