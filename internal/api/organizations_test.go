package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tas50/cinc-server-ng/internal/auth"
	"github.com/tas50/cinc-server-ng/internal/store"
)

func TestOrganizationManagement(t *testing.T) {
	st := store.New()
	srv := httptest.NewServer(New(st).Handler())
	defer srv.Close()

	// Create an org; the response includes a usable validator private key.
	resp, body := do(t, "POST", srv.URL+"/organizations", `{"name":"acme","full_name":"ACME Inc"}`)
	if resp.StatusCode != 201 {
		t.Fatalf("create org = %d: %s", resp.StatusCode, body)
	}
	var created map[string]any
	json.Unmarshal([]byte(body), &created)
	if created["clientname"] != "acme-validator" {
		t.Fatalf("validator name = %v", created["clientname"])
	}
	priv, _ := created["private_key"].(string)
	if _, err := auth.ParsePrivateKey([]byte(priv)); err != nil {
		t.Fatalf("validator private key invalid: %v", err)
	}

	// Duplicate -> 409.
	resp, _ = do(t, "POST", srv.URL+"/organizations", `{"name":"acme"}`)
	if resp.StatusCode != 409 {
		t.Fatalf("duplicate org = %d, want 409", resp.StatusCode)
	}

	// List shows it.
	_, body = do(t, "GET", srv.URL+"/organizations", "")
	var list map[string]string
	json.Unmarshal([]byte(body), &list)
	if !strings.HasSuffix(list["acme"], "/organizations/acme") {
		t.Fatalf("org list = %s", body)
	}

	// Get returns name/full_name/guid.
	resp, body = do(t, "GET", srv.URL+"/organizations/acme", "")
	if resp.StatusCode != 200 {
		t.Fatalf("get org = %d", resp.StatusCode)
	}
	var meta map[string]any
	json.Unmarshal([]byte(body), &meta)
	if meta["name"] != "acme" || meta["full_name"] != "ACME Inc" || meta["guid"] == "" {
		t.Fatalf("org meta = %s", body)
	}

	// The org is immediately usable: a node can be created in it.
	resp, _ = do(t, "POST", srv.URL+"/organizations/acme/nodes", `{"name":"web01"}`)
	if resp.StatusCode != 201 {
		t.Fatalf("node in new org = %d", resp.StatusCode)
	}

	// The _default environment was seeded.
	resp, _ = do(t, "GET", srv.URL+"/organizations/acme/environments/_default", "")
	if resp.StatusCode != 200 {
		t.Fatalf("seeded _default missing = %d", resp.StatusCode)
	}

	// Update full_name.
	resp, body = do(t, "PUT", srv.URL+"/organizations/acme", `{"name":"acme","full_name":"ACME Corp"}`)
	if resp.StatusCode != 200 {
		t.Fatalf("put org = %d", resp.StatusCode)
	}
	json.Unmarshal([]byte(body), &meta)
	if meta["full_name"] != "ACME Corp" {
		t.Fatalf("update full_name = %s", body)
	}

	// Delete.
	resp, _ = do(t, "DELETE", srv.URL+"/organizations/acme", "")
	if resp.StatusCode != 200 {
		t.Fatalf("delete org = %d", resp.StatusCode)
	}
	resp, _ = do(t, "GET", srv.URL+"/organizations/acme", "")
	if resp.StatusCode != 404 {
		t.Fatalf("get deleted org = %d", resp.StatusCode)
	}
	if _, ok, err := st.Org("acme"); err != nil {
		t.Fatal(err)
	} else if ok {
		t.Fatal("org not removed from store")
	}
}

func TestCreateOrganizationHelper(t *testing.T) {
	st := store.New()
	priv, err := CreateOrganization(st, "beta", "Beta Org")
	if err != nil {
		t.Fatal(err)
	}
	if len(priv) == 0 {
		t.Fatal("no validator key returned")
	}
	org, ok, err := st.Org("beta")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("org not created")
	}
	if _, ok, err := org.Get("clients", "beta-validator"); err != nil {
		t.Fatal(err)
	} else if !ok {
		t.Fatal("validator client not created")
	}
	if _, err := CreateOrganization(st, "beta", ""); err == nil {
		t.Fatal("expected conflict on duplicate org")
	}
}

// TestCreateOrganizationWithKeyUsesProvidedKey verifies the injected-key variant
// provisions the org with the caller's key rather than generating a fresh one —
// the contract that lets the server bootstrap generate keys in parallel and then
// seed serially.
func TestCreateOrganizationWithKeyUsesProvidedKey(t *testing.T) {
	st := store.New()
	key, err := auth.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	priv, err := CreateOrganizationWithKey(st, "gamma", "Gamma Org", key)
	if err != nil {
		t.Fatal(err)
	}
	if string(priv) != string(auth.EncodePrivateKeyPEM(key)) {
		t.Fatal("returned private key does not match the provided key")
	}

	org, ok, err := st.Org("gamma")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("org not created")
	}
	raw, ok, err := org.Get("clients", "gamma-validator")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("validator client not created")
	}
	var client struct {
		PublicKey string `json:"public_key"`
		Validator bool   `json:"validator"`
	}
	if err := json.Unmarshal(raw, &client); err != nil {
		t.Fatal(err)
	}
	wantPub, err := auth.EncodePublicKeyPEM(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if client.PublicKey != string(wantPub) {
		t.Fatal("validator public key does not match the provided key")
	}
	if !client.Validator {
		t.Fatal("validator client not marked as validator")
	}
}
