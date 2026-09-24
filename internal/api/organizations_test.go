package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cinc-project/cinc-server-ng/internal/auth"
	"github.com/cinc-project/cinc-server-ng/internal/store"
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
	resp, _ = do(t, "POST", srv.URL+"/organizations", `{"name":"acme","full_name":"ACME Inc"}`)
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

// A stored organization document that will not unmarshal into a map must
// produce a 500, not a panic. putOrganization decodes the stored doc into a
// map and then writes the request's fields into it; while the unmarshal error
// went unchecked, a failure left the map nil and the next assignment panicked
// on a nil map. Unreachable through the API (the store holds canonical JSON
// the server itself wrote), but the handler should not depend on that.
func TestUpdateOrganizationWithUndecodableStoredDocument(t *testing.T) {
	srv, st := newTestAPI(t)
	if err := st.Global().Put(orgsColl, "acme", []byte(`"not an object"`)); err != nil {
		t.Fatal(err)
	}
	resp, body := do(t, "PUT", srv.URL+"/organizations/acme", `{"full_name":"Acme Corp"}`)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", resp.StatusCode, body)
	}
}

// erchef (oc_chef_organization:validation_constraints/1) requires an org's
// name to match ^[a-z0-9][a-z0-9_-]{0,254}$ and its full_name to match
// ^\S.{0,1022}$, answering 400 and creating nothing otherwise.
func TestCreateOrganizationRejectsInvalidNames(t *testing.T) {
	srv, _ := newTestAPI(t)
	cases := []struct {
		body, want string
	}{
		{`{"name":"T-Org-1","full_name":"Bad Name Inc"}`, "Field 'name' invalid"},
		{`{"name":"t_org 1","full_name":"Bad Name Inc"}`, "Field 'name' invalid"},
		{`{"name":"-t-org-1","full_name":"Bad Name Inc"}`, "Field 'name' invalid"},
		{`{"name":"_t-org-1","full_name":"Bad Name Inc"}`, "Field 'name' invalid"},
		{`{"name":"t.org","full_name":"Bad Name Inc"}`, "Field 'name' invalid"},
		{`{"name":"` + strings.Repeat("a", 256) + `","full_name":"Too Long"}`, "Field 'name' invalid"},
		{`{"name":"t-org-2"}`, "Field 'full_name' missing"},
		{`{"name":"t-org-3","full_name":" leading space"}`, "Field 'full_name' invalid"},
		{`{"name":"t-org-4","full_name":""}`, "Field 'full_name' invalid"},
		{`{"name":"t-org-5","full_name":"two\nlines"}`, "Field 'full_name' invalid"},
		{`{"name":"t-org-6","full_name":"` + strings.Repeat("x", 1024) + `"}`, "Field 'full_name' invalid"},
	}
	for _, c := range cases {
		resp, body := do(t, "POST", srv.URL+"/organizations", c.body)
		if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, c.want) {
			t.Errorf("POST %s = %d %s, want 400 %q", c.body, resp.StatusCode, body, c.want)
		}
	}
	_, body := do(t, "GET", srv.URL+"/organizations", "")
	var orgs map[string]string
	json.Unmarshal([]byte(body), &orgs)
	for name := range orgs {
		if name != "acme" {
			t.Errorf("a refused org was created: %q", name)
		}
	}

	for _, name := range []string{"0rg", "t-org_7", strings.Repeat("a", 255)} {
		body := `{"name":"` + name + `","full_name":"Good ` + name + `"}`
		if resp, out := do(t, "POST", srv.URL+"/organizations", body); resp.StatusCode != http.StatusCreated {
			t.Errorf("POST %s = %d %s, want 201", body, resp.StatusCode, out)
		}
	}
}

// On update, erchef requires name to equal the existing org's name and
// full_name to match the same rule as on create.
func TestUpdateOrganizationRejectsInvalidFields(t *testing.T) {
	srv, _ := newTestAPI(t)
	if resp, out := do(t, "POST", srv.URL+"/organizations", `{"name":"beta","full_name":"BETA Inc"}`); resp.StatusCode != http.StatusCreated {
		t.Fatalf("create org = %d %s", resp.StatusCode, out)
	}
	for _, body := range []string{
		`{"name":"other","full_name":"BETA Corp"}`,
		`{"name":"beta","full_name":" BETA"}`,
		`{"name":"beta","full_name":""}`,
	} {
		resp, out := do(t, "PUT", srv.URL+"/organizations/beta", body)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("PUT %s = %d %s, want 400", body, resp.StatusCode, out)
		}
	}
	_, out := do(t, "GET", srv.URL+"/organizations/beta", "")
	var meta map[string]any
	json.Unmarshal([]byte(out), &meta)
	if meta["name"] != "beta" || meta["full_name"] == "BETA Corp" || meta["full_name"] == " BETA" || meta["full_name"] == "" {
		t.Errorf("a refused update was applied: %s", out)
	}
}
