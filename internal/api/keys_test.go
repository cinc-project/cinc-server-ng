package api

import (
	"encoding/json"
	"strings"
	"testing"
)

type keyListEntry struct {
	Name string `json:"name"`
	URI  string `json:"uri"`
}

func TestClientKeyLifecycle(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"

	// Creating a client generates its default key pair.
	resp, body := do(t, "POST", base+"/clients", `{"name":"web01"}`)
	if resp.StatusCode != 201 {
		t.Fatalf("create client = %d: %s", resp.StatusCode, body)
	}

	// The default key is listed.
	_, body = do(t, "GET", base+"/clients/web01/keys", "")
	var list []keyListEntry
	json.Unmarshal([]byte(body), &list)
	if !hasKey(list, "default") {
		t.Fatalf("keys list missing default: %s", body)
	}

	// The default key exposes the client's public key.
	_, body = do(t, "GET", base+"/clients/web01/keys/default", "")
	var def map[string]any
	json.Unmarshal([]byte(body), &def)
	if pk, _ := def["public_key"].(string); !strings.Contains(pk, "PUBLIC KEY") {
		t.Fatalf("default key missing public_key: %s", body)
	}

	// Add a second key with no public_key; the server generates one and returns
	// the private key exactly once.
	resp, body = do(t, "POST", base+"/clients/web01/keys", `{"name":"key2","expiration_date":"infinity"}`)
	if resp.StatusCode != 201 {
		t.Fatalf("add key = %d: %s", resp.StatusCode, body)
	}
	var added map[string]any
	json.Unmarshal([]byte(body), &added)
	if pk, _ := added["private_key"].(string); !strings.Contains(pk, "PRIVATE KEY") {
		t.Fatalf("generated key did not return a private_key: %s", body)
	}

	// Both keys are now listed.
	_, body = do(t, "GET", base+"/clients/web01/keys", "")
	json.Unmarshal([]byte(body), &list)
	if !hasKey(list, "default") || !hasKey(list, "key2") {
		t.Fatalf("keys list = %s", body)
	}

	// Fetch the named key.
	resp, body = do(t, "GET", base+"/clients/web01/keys/key2", "")
	if resp.StatusCode != 200 {
		t.Fatalf("get key2 = %d: %s", resp.StatusCode, body)
	}

	// Delete it.
	resp, _ = do(t, "DELETE", base+"/clients/web01/keys/key2", "")
	if resp.StatusCode != 200 {
		t.Fatalf("delete key2 = %d", resp.StatusCode)
	}
	resp, _ = do(t, "GET", base+"/clients/web01/keys/key2", "")
	if resp.StatusCode != 404 {
		t.Fatalf("get deleted key2 = %d", resp.StatusCode)
	}
}

func TestClientKeyAddDuplicate(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	do(t, "POST", base+"/clients", `{"name":"web01"}`)
	do(t, "POST", base+"/clients/web01/keys", `{"name":"key2"}`)
	resp, _ := do(t, "POST", base+"/clients/web01/keys", `{"name":"key2"}`)
	if resp.StatusCode != 409 {
		t.Fatalf("duplicate key = %d, want 409", resp.StatusCode)
	}
}

func TestKeysForMissingActor404(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	resp, _ := do(t, "GET", base+"/clients/ghost/keys", "")
	if resp.StatusCode != 404 {
		t.Fatalf("keys for missing client = %d, want 404", resp.StatusCode)
	}
}

func TestUserKeyLifecycle(t *testing.T) {
	srv, _ := newTestAPI(t)

	resp, body := do(t, "POST", srv.URL+"/users", userBody(`{"name":"alice"}`))
	if resp.StatusCode != 201 {
		t.Fatalf("create user = %d: %s", resp.StatusCode, body)
	}
	// Users are global; their keys live under /users/{name}/keys.
	_, body = do(t, "GET", srv.URL+"/users/alice/keys", "")
	var list []keyListEntry
	json.Unmarshal([]byte(body), &list)
	if !hasKey(list, "default") {
		t.Fatalf("user keys list missing default: %s", body)
	}
}

func hasKey(list []keyListEntry, name string) bool {
	for _, k := range list {
		if k.Name == name {
			return true
		}
	}
	return false
}
