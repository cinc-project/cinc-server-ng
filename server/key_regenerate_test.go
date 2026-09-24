package server

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// PUT on a client's default key with {"create_key": true} (what
// `knife client key edit --create-key` sends) regenerates it: the private key
// the server returns signs, and the old one no longer does.
func TestKeyPutCreateKeyRegeneratedKeySigns(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}})
	base := srv.URL() + "/organizations/acme"
	oldKey := createClientAndKey(t, srv, base, "web01")
	probe := base + "/nodes"
	if code := statusOf(t, signedAs(t, "web01", oldKey, "GET", probe, "")); code != 200 {
		t.Fatalf("original key = %d, want 200", code)
	}

	resp, err := http.DefaultClient.Do(signed(t, srv, "PUT", base+"/clients/web01/keys/default",
		`{"name":"default","create_key":true}`))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("PUT create_key = %d: %s", resp.StatusCode, raw)
	}
	var out struct {
		PrivateKey string `json:"private_key"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.PrivateKey == "" {
		t.Fatalf("no private_key in the PUT response: %s", raw)
	}

	if code := statusOf(t, signedAs(t, "web01", []byte(out.PrivateKey), "GET", probe, "")); code != 200 {
		t.Fatalf("regenerated key = %d, want 200", code)
	}
	if code := statusOf(t, signedAs(t, "web01", oldKey, "GET", probe, "")); code != 401 {
		t.Fatalf("replaced key = %d, want 401", code)
	}
}
