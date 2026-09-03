package api

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/cinc-project/cinc-server-ng/internal/store"
)

func seededServer(t *testing.T) *httptest.Server {
	t.Helper()
	st := store.New()
	org, _ := st.CreateOrg("acme")
	SeedOrg(org)
	srv := httptest.NewServer(New(st).Handler())
	t.Cleanup(srv.Close)
	return srv
}

func TestDefaultGroupsSeeded(t *testing.T) {
	srv := seededServer(t)
	base := srv.URL + "/organizations/acme"

	_, body := do(t, "GET", base+"/groups", "")
	var groups map[string]string
	json.Unmarshal([]byte(body), &groups)
	for _, want := range []string{"admins", "clients", "users"} {
		if _, ok := groups[want]; !ok {
			t.Fatalf("default group %q missing: %s", want, body)
		}
	}
}

func TestGroupCRUD(t *testing.T) {
	srv := seededServer(t)
	base := srv.URL + "/organizations/acme"

	resp, _ := do(t, "POST", base+"/groups", `{"name":"ops","groupname":"ops"}`)
	if resp.StatusCode != 201 {
		t.Fatalf("create group = %d", resp.StatusCode)
	}
	resp, _ = do(t, "PUT", base+"/groups/ops", `{"name":"ops","actors":{"users":["alice"],"clients":[],"groups":[]}}`)
	if resp.StatusCode != 200 {
		t.Fatalf("update group = %d", resp.StatusCode)
	}
	resp, body := do(t, "GET", base+"/groups/ops", "")
	if resp.StatusCode != 200 {
		t.Fatalf("get group = %d", resp.StatusCode)
	}
	if !json.Valid([]byte(body)) {
		t.Fatalf("group doc invalid: %s", body)
	}
}

// TestGroupCreateByGroupname accepts the {"groupname": ...} body that real
// Chef clients (knife, cinc) POST to /groups — the "name" field is absent, and
// chef-zero keyed the group off "groupname".
func TestGroupCreateByGroupname(t *testing.T) {
	srv := seededServer(t)
	base := srv.URL + "/organizations/acme"

	resp, body := do(t, "POST", base+"/groups", `{"groupname":"devs"}`)
	if resp.StatusCode != 201 {
		t.Fatalf("create group by groupname = %d: %s", resp.StatusCode, body)
	}

	_, list := do(t, "GET", base+"/groups", "")
	var groups map[string]string
	json.Unmarshal([]byte(list), &groups)
	if _, ok := groups["devs"]; !ok {
		t.Fatalf("group devs missing after create: %s", list)
	}
}

// TestGroupMembershipRoundTrip stores members supplied in Chef's update shape
// (nested under "actors") and returns them as the top-level users/clients/groups
// arrays clients read back.
func TestGroupMembershipRoundTrip(t *testing.T) {
	srv := seededServer(t)
	base := srv.URL + "/organizations/acme"

	if resp, body := do(t, "POST", base+"/groups", `{"groupname":"devs"}`); resp.StatusCode != 201 {
		t.Fatalf("create group = %d: %s", resp.StatusCode, body)
	}
	if resp, body := do(t, "PUT", base+"/groups/devs",
		`{"groupname":"devs","actors":{"users":["anna","ben"],"clients":[],"groups":[]}}`); resp.StatusCode != 200 {
		t.Fatalf("update group = %d: %s", resp.StatusCode, body)
	}

	_, body := do(t, "GET", base+"/groups/devs", "")
	var g struct {
		Users  []string `json:"users"`
		Actors []string `json:"actors"`
	}
	if err := json.Unmarshal([]byte(body), &g); err != nil {
		t.Fatalf("group doc invalid: %v\n%s", err, body)
	}
	if len(g.Users) != 2 || g.Users[0] != "anna" || g.Users[1] != "ben" {
		t.Fatalf("group users = %v, want [anna ben]; body: %s", g.Users, body)
	}
	if len(g.Actors) != 2 {
		t.Fatalf("group actors = %v, want anna+ben flattened", g.Actors)
	}
}

func TestDefaultContainersSeeded(t *testing.T) {
	srv := seededServer(t)
	base := srv.URL + "/organizations/acme"

	_, body := do(t, "GET", base+"/containers", "")
	var containers map[string]string
	json.Unmarshal([]byte(body), &containers)
	for _, want := range []string{"nodes", "roles", "environments", "cookbooks", "data"} {
		if _, ok := containers[want]; !ok {
			t.Fatalf("default container %q missing: %s", want, body)
		}
	}
}

func TestContainerGet(t *testing.T) {
	srv := seededServer(t)
	base := srv.URL + "/organizations/acme"
	resp, body := do(t, "GET", base+"/containers/nodes", "")
	if resp.StatusCode != 200 {
		t.Fatalf("get container = %d", resp.StatusCode)
	}
	var c map[string]any
	json.Unmarshal([]byte(body), &c)
	if c["containername"] != "nodes" {
		t.Fatalf("container doc = %s", body)
	}
}
