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

// signedV0 is signedAs at server API version 0, the version knife pins for
// `knife client reregister` and `knife user reregister`.
func signedV0(t *testing.T, name string, keyPEM []byte, method, url, body string) *http.Request {
	t.Helper()
	key, err := auth.ParsePrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("parse key for %s: %v", name, err)
	}
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Ops-Server-API-Version", "0")
	if err := auth.SignRequest(req, name, time.Now().UTC().Format(time.RFC3339), []byte(body), key); err != nil {
		t.Fatalf("sign as %s: %v", name, err)
	}
	return req
}

// reregister PUTs {"private_key": true} at API v0 and returns the status and
// the private key in the response, if any.
func reregister(t *testing.T, name string, keyPEM []byte, url, body string) (int, []byte) {
	t.Helper()
	resp, err := http.DefaultClient.Do(signedV0(t, name, keyPEM, "PUT", url, body))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var out struct {
		PrivateKey string `json:"private_key"`
	}
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, []byte(out.PrivateKey)
}

// At API v0, Chef Infra Server regenerates an actor's default key when an
// update carries "private_key": true, returning the new private key; the old
// key stops authenticating. That is the whole of `knife client reregister`.
// The update is still authorized as an update: an ordinary client may not
// reregister another.
func TestClientReregisterV0RegeneratesKey(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	base := srv.URL() + "/organizations/acme"
	oldKey := createClientAndKey(t, srv, base, "web01")
	otherKey := createClientAndKey(t, srv, base, "web02")
	probe := base + "/nodes"
	if code := statusOf(t, signedAs(t, "web01", oldKey, "GET", probe, "")); code != 200 {
		t.Fatalf("baseline: web01's key = %d, want 200", code)
	}

	body := `{"name":"web01","admin":false,"validator":false,"private_key":true}`
	if code, _ := reregister(t, "web02", otherKey, base+"/clients/web01", body); code != http.StatusForbidden {
		t.Fatalf("another client reregistering web01 = %d, want 403", code)
	}
	if code := statusOf(t, signedAs(t, "web01", oldKey, "GET", probe, "")); code != 200 {
		t.Fatalf("a refused reregister changed web01's key: %d", code)
	}

	code, newKey := reregister(t, srv.AdminName(), srv.AdminKey(), base+"/clients/web01", body)
	if code != 200 || len(newKey) == 0 {
		t.Fatalf("reregister = %d with private key %q, want 200 and a key", code, newKey)
	}
	if code := statusOf(t, signedAs(t, "web01", newKey, "GET", probe, "")); code != 200 {
		t.Fatalf("reregistered key = %d, want 200", code)
	}
	if code := statusOf(t, signedAs(t, "web01", oldKey, "GET", probe, "")); code != 401 {
		t.Fatalf("replaced key = %d, want 401", code)
	}
}

func TestUserReregisterV0RegeneratesKey(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	bobKey := createUserKey(t, srv, "bob")
	malloryKey := createUserKey(t, srv, "mallory")
	probe := srv.URL() + "/users/bob"
	if code := statusOf(t, signedAs(t, "bob", bobKey, "GET", probe, "")); code != 200 {
		t.Fatalf("baseline: bob's key = %d, want 200", code)
	}

	body := `{"username":"bob","display_name":"Bob","email":"bob@example.test","private_key":true}`
	if code, _ := reregister(t, "mallory", malloryKey, probe, body); code != http.StatusForbidden {
		t.Fatalf("mallory reregistering bob = %d, want 403", code)
	}
	if code := statusOf(t, signedAs(t, "bob", bobKey, "GET", probe, "")); code != 200 {
		t.Fatalf("a refused reregister changed bob's key: %d", code)
	}

	code, newKey := reregister(t, "bob", bobKey, probe, body)
	if code != 200 || len(newKey) == 0 {
		t.Fatalf("self reregister = %d with private key %q, want 200 and a key", code, newKey)
	}
	if code := statusOf(t, signedAs(t, "bob", newKey, "GET", probe, "")); code != 200 {
		t.Fatalf("reregistered key = %d, want 200", code)
	}
	if code := statusOf(t, signedAs(t, "bob", bobKey, "GET", probe, "")); code != 401 {
		t.Fatalf("replaced key = %d, want 401", code)
	}
}
