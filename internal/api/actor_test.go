package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cinc-project/cinc-server-ng/internal/auth"
	"github.com/cinc-project/cinc-server-ng/internal/store"
)

func TestClientCreateGeneratesKey(t *testing.T) {
	srv, st := newTestAPI(t)
	base := srv.URL + "/organizations/acme"

	resp, body := do(t, "POST", base+"/clients", `{"name":"node1"}`)
	if resp.StatusCode != 201 {
		t.Fatalf("create client status %d: %s", resp.StatusCode, body)
	}
	var out map[string]any
	json.Unmarshal([]byte(body), &out)

	// A usable private key must be returned exactly once, on creation.
	priv := privateKeyFrom(t, out)
	if priv == "" {
		t.Fatalf("no private key in create response: %s", body)
	}
	if _, err := auth.ParsePrivateKey([]byte(priv)); err != nil {
		t.Fatalf("returned private key is not valid: %v", err)
	}

	// The stored client retains the public key but never the private key.
	org, _, err := st.Org("acme")
	if err != nil {
		t.Fatal(err)
	}
	raw, ok, err := org.Get("clients", "node1")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("client not stored")
	}
	var stored map[string]any
	json.Unmarshal(raw, &stored)
	if _, has := stored["public_key"]; !has {
		t.Fatalf("stored client missing public_key: %s", raw)
	}
	if _, has := stored["private_key"]; has {
		t.Fatal("private key must not be persisted")
	}
}

func TestClientCreateAcceptsProvidedKey(t *testing.T) {
	srv, st := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	key, _ := auth.GenerateKey()
	pub, _ := auth.EncodePublicKeyPEM(&key.PublicKey)
	reqBody, _ := json.Marshal(map[string]any{"name": "node2", "public_key": string(pub)})

	resp, body := do(t, "POST", base+"/clients", string(reqBody))
	if resp.StatusCode != 201 {
		t.Fatalf("create status %d: %s", resp.StatusCode, body)
	}
	org, _, err := st.Org("acme")
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := org.Get("clients", "node2")
	if err != nil {
		t.Fatal(err)
	}
	var stored map[string]any
	json.Unmarshal(raw, &stored)
	if stored["public_key"] != string(pub) {
		t.Fatal("provided public key not preserved")
	}
}

// TestClientCreateAcceptsNestedPublicKey accepts a BYO public key nested under
// "chef_key" (the shape knife/cinc send): the server must use it verbatim and
// not generate — and so must not return a private key.
func TestClientCreateAcceptsNestedPublicKey(t *testing.T) {
	srv, st := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	key, _ := auth.GenerateKey()
	pub, _ := auth.EncodePublicKeyPEM(&key.PublicKey)
	reqBody, _ := json.Marshal(map[string]any{
		"name":     "byo",
		"chef_key": map[string]any{"public_key": string(pub)},
	})

	resp, body := do(t, "POST", base+"/clients", string(reqBody))
	if resp.StatusCode != 201 {
		t.Fatalf("create status %d: %s", resp.StatusCode, body)
	}
	var out map[string]any
	json.Unmarshal([]byte(body), &out)
	if privateKeyFrom(t, out) != "" {
		t.Fatalf("server generated a key despite a supplied public key: %s", body)
	}
	org, _, err := st.Org("acme")
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := org.Get("clients", "byo")
	if err != nil {
		t.Fatal(err)
	}
	var stored map[string]any
	json.Unmarshal(raw, &stored)
	if stored["public_key"] != string(pub) {
		t.Fatalf("nested public key not preserved: %s", raw)
	}
}

func TestUserCreateIsGlobal(t *testing.T) {
	st := store.New()
	srv := httptest.NewServer(New(st).Handler())
	defer srv.Close()

	resp, body := do(t, "POST", srv.URL+"/users", `{"name":"alice"}`)
	if resp.StatusCode != 201 {
		t.Fatalf("create user status %d: %s", resp.StatusCode, body)
	}
	_, ok, err := st.Global().Get("users", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("user not stored in global space")
	}
	// Listing users does not require an org.
	resp, body = do(t, "GET", srv.URL+"/users", "")
	if resp.StatusCode != 200 || !strings.Contains(body, "alice") {
		t.Fatalf("user list = %d %s", resp.StatusCode, body)
	}
}

func privateKeyFrom(t *testing.T, out map[string]any) string {
	t.Helper()
	if pk, ok := out["private_key"].(string); ok {
		return pk
	}
	if ck, ok := out["chef_key"].(map[string]any); ok {
		if pk, ok := ck["private_key"].(string); ok {
			return pk
		}
	}
	return ""
}
