package api

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
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

	do(t, "POST", srv.URL+"/users", `{"name":"anna"}`)
	do(t, "POST", srv.URL+"/users", `{"name":"ben"}`)
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

// TestGroupUpdateDropsUnknownMembers covers erchef's group update, which
// resolves every member name and keeps only the ones it finds: users are
// global, clients and groups belong to the org. Unknown names are dropped
// without an error, so they are neither listed nor a latent membership for
// whatever is created under the name later.
func TestGroupUpdateDropsUnknownMembers(t *testing.T) {
	srv := seededServer(t)
	base := srv.URL + "/organizations/acme"
	do(t, "POST", srv.URL+"/users", `{"name":"anna"}`)
	do(t, "POST", base+"/clients", `{"name":"web01"}`)
	for _, g := range []string{"devs", "ops"} {
		if resp, body := do(t, "POST", base+"/groups", `{"groupname":"`+g+`"}`); resp.StatusCode != 201 {
			t.Fatalf("create group %s = %d: %s", g, resp.StatusCode, body)
		}
	}

	resp, body := do(t, "PUT", base+"/groups/devs",
		`{"groupname":"devs","actors":{"users":["anna","ghost-user"],"clients":["web01","ghost-client"],"groups":["ops","ghost-group"]}}`)
	if resp.StatusCode != 200 {
		t.Fatalf("update group = %d: %s", resp.StatusCode, body)
	}

	_, body = do(t, "GET", base+"/groups/devs", "")
	var g struct {
		Users, Clients, Groups, Actors []string
	}
	if err := json.Unmarshal([]byte(body), &g); err != nil {
		t.Fatalf("group doc invalid: %v\n%s", err, body)
	}
	if !slices.Equal(g.Users, []string{"anna"}) || !slices.Equal(g.Clients, []string{"web01"}) ||
		!slices.Equal(g.Groups, []string{"ops"}) || !slices.Equal(g.Actors, []string{"anna", "web01", "ops"}) {
		t.Fatalf("group members = %+v, want only the known anna, web01 and ops; body %s", g, body)
	}

	// A client created later under a dropped name does not join the group.
	do(t, "POST", base+"/clients", `{"name":"ghost-client"}`)
	_, body = do(t, "GET", base+"/groups/devs", "")
	if strings.Contains(body, "ghost-client") {
		t.Fatalf("a client created after the update inherited the dropped membership: %s", body)
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

// erchef (oc_chef_wm_groups) matches a new group's name against
// ^[a-z0-9\-_]+$ and answers 400 "Invalid group name." for anything else,
// creating nothing.
func TestCreateGroupRejectsInvalidName(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme/groups"
	for _, name := range []string{"bad name!", "t group 1a2b", "Upper", "a.b", "a:b", "a/b"} {
		body, _ := json.Marshal(map[string]string{"groupname": name})
		resp, out := do(t, "POST", base, string(body))
		if resp.StatusCode != 400 || !strings.Contains(out, "Invalid group name.") {
			t.Errorf("create group %q = %d %s, want 400 Invalid group name.", name, resp.StatusCode, out)
		}
		if resp, _ := do(t, "GET", base+"/"+url.PathEscape(name), ""); resp.StatusCode != 404 {
			t.Errorf("refused group %q was stored: GET = %d", name, resp.StatusCode)
		}
	}
	for _, name := range []string{"ops", "ops-team_2"} {
		body, _ := json.Marshal(map[string]string{"groupname": name})
		if resp, out := do(t, "POST", base, string(body)); resp.StatusCode != 201 {
			t.Errorf("create group %q = %d %s, want 201", name, resp.StatusCode, out)
		}
	}
}
