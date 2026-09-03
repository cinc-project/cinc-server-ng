package api

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/cinc-project/cinc-server-ng/internal/store"
)

func TestSeedOrgCreatesDefaultEnvironment(t *testing.T) {
	st := store.New()
	org, _ := st.CreateOrg("acme")
	SeedOrg(org)
	api := New(st)
	srv := httptest.NewServer(api.Handler())
	defer srv.Close()
	base := srv.URL + "/organizations/acme"

	resp, body := do(t, "GET", base+"/environments/_default", "")
	if resp.StatusCode != 200 {
		t.Fatalf("_default status %d: %s", resp.StatusCode, body)
	}
	var env map[string]any
	json.Unmarshal([]byte(body), &env)
	if env["name"] != "_default" {
		t.Fatalf("_default env = %s", body)
	}
}

func TestDefaultEnvironmentImmutable(t *testing.T) {
	st := store.New()
	org, _ := st.CreateOrg("acme")
	SeedOrg(org)
	srv := httptest.NewServer(New(st).Handler())
	defer srv.Close()
	base := srv.URL + "/organizations/acme"

	resp, _ := do(t, "PUT", base+"/environments/_default", `{"name":"_default"}`)
	if resp.StatusCode != 405 {
		t.Fatalf("PUT _default status %d, want 405", resp.StatusCode)
	}
	resp, _ = do(t, "DELETE", base+"/environments/_default", "")
	if resp.StatusCode != 405 {
		t.Fatalf("DELETE _default status %d, want 405", resp.StatusCode)
	}
}

func TestRoleCRUD(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"

	resp, body := do(t, "POST", base+"/roles", `{"name":"web","run_list":["recipe[nginx]"]}`)
	if resp.StatusCode != 201 {
		t.Fatalf("create role status %d: %s", resp.StatusCode, body)
	}
	resp, body = do(t, "GET", base+"/roles/web", "")
	if resp.StatusCode != 200 {
		t.Fatalf("get role status %d", resp.StatusCode)
	}
	var role map[string]any
	json.Unmarshal([]byte(body), &role)
	if role["name"] != "web" {
		t.Fatalf("role = %s", body)
	}
}

func TestCustomEnvironmentCRUD(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	resp, _ := do(t, "POST", base+"/environments", `{"name":"production"}`)
	if resp.StatusCode != 201 {
		t.Fatalf("create env status %d", resp.StatusCode)
	}
	resp, _ = do(t, "DELETE", base+"/environments/production", "")
	if resp.StatusCode != 200 {
		t.Fatalf("delete custom env status %d", resp.StatusCode)
	}
}
