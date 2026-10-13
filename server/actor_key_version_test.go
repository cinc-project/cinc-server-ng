package server

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// signedAtBody sends a request signed as the admin at an API version and
// returns the status and body.
func signedAtBody(t *testing.T, srv *Server, version, method, url, body string) (int, []byte) {
	t.Helper()
	resp, err := http.DefaultClient.Do(signedAt(t, srv, version, method, url, body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

// What a node with only the validator key sees: at API v1 a client registered
// without create_key has no key (as on erchef), so nothing can sign as it; with
// create_key, the returned key signs.
func TestValidatorRegisteredClientKeyByAPIVersion(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	base := srv.URL() + "/organizations/acme"
	probe := base + "/nodes"

	// Baseline: the create_key registration (what chef-client sends) works.
	keyed := createClientAndKey(t, srv, base, "keyed")
	if code := statusOf(t, signedAs(t, "keyed", keyed, "GET", probe, "")); code != 200 {
		t.Fatalf("client registered with create_key = %d, want 200", code)
	}

	resp, err := http.DefaultClient.Do(signedAs(t, "acme-validator", srv.ValidatorKey("acme"),
		"POST", base+"/clients", `{"name":"keyless"}`))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register keyless = %d: %s", resp.StatusCode, raw)
	}
	var created map[string]any
	_ = json.Unmarshal(raw, &created)
	if _, ok := created["chef_key"]; ok {
		t.Fatalf("v1 create without create_key returned a key: %s", raw)
	}
	if code, raw := adminDo(t, srv, "GET", base+"/clients/keyless/keys/default", ""); code != 404 {
		t.Fatalf("GET keyless default key = %d, want 404: %s", code, raw)
	}
	// Any key, even the validator's, fails to sign as the keyless client.
	if code := statusOf(t, signedAs(t, "keyless", srv.ValidatorKey("acme"), "GET", probe, "")); code != 401 {
		t.Fatalf("signing as keyless client = %d, want 401", code)
	}
}

// From API v1 on, an actor update cannot touch its keys: the request is
// refused and the old key keeps working. API v0 still replaces the key.
func TestActorUpdateKeyFieldsByAPIVersion(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}})
	base := srv.URL() + "/organizations/acme"
	probe := base + "/nodes"
	original := createClientAndKey(t, srv, base, "web01")

	newPriv, newPub := newKeyPair(t)
	body, _ := json.Marshal(map[string]any{"name": "web01", "public_key": newPub})
	if code, raw := signedAtBody(t, srv, "1", "PUT", base+"/clients/web01", string(body)); code != 400 {
		t.Fatalf("v1 PUT with public_key = %d, want 400: %s", code, raw)
	}
	if code, raw := signedAtBody(t, srv, "1", "PUT", base+"/clients/web01", `{"name":"web01","create_key":true}`); code != 400 {
		t.Fatalf("v1 PUT with create_key = %d, want 400: %s", code, raw)
	}
	if code := statusOf(t, signedAs(t, "web01", original, "GET", probe, "")); code != 200 {
		t.Fatalf("original key after refused updates = %d, want 200", code)
	}
	if code := statusOf(t, signedAs(t, "web01", newPriv, "GET", probe, "")); code != 401 {
		t.Fatalf("refused key = %d, want 401", code)
	}

	if code, raw := signedAtBody(t, srv, "0", "PUT", base+"/clients/web01", string(body)); code != 200 {
		t.Fatalf("v0 PUT with public_key = %d, want 200: %s", code, raw)
	}
	if code := statusOf(t, signedAs(t, "web01", newPriv, "GET", probe, "")); code != 200 {
		t.Fatalf("key set at v0 = %d, want 200", code)
	}
	if code := statusOf(t, signedAs(t, "web01", original, "GET", probe, "")); code != 401 {
		t.Fatalf("replaced key = %d, want 401", code)
	}
}
