package api

import (
	"strings"
	"testing"
)

// erchef normalizes node and role run lists on save
// (chef_object_base:normalize_run_list): bare items are qualified as recipes
// and exact duplicates dropped, first occurrence kept. The stored document,
// the PUT response (erchef echoes the normalized body) and search all see the
// normalized list.
func TestNodeRunListNormalizedOnSave(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"

	resp, body := do(t, "POST", base+"/nodes",
		`{"name":"web","run_list":["nginx","recipe[nginx]","base","base"]}`)
	if resp.StatusCode != 201 {
		t.Fatalf("create: %d %s", resp.StatusCode, body)
	}
	if _, body = do(t, "GET", base+"/nodes/web", ""); body != `{"name":"web","run_list":["recipe[nginx]","recipe[base]"]}` {
		t.Fatalf("stored after create = %s", body)
	}

	resp, body = do(t, "PUT", base+"/nodes/web", `{"name":"web","run_list":["x","x","recipe[y]"]}`)
	want := `{"name":"web","run_list":["recipe[x]","recipe[y]"]}`
	if resp.StatusCode != 200 || body != want {
		t.Fatalf("update: %d %s, want %s", resp.StatusCode, body, want)
	}
	if _, body = do(t, "GET", base+"/nodes/web", ""); body != want {
		t.Fatalf("stored after update = %s", body)
	}

	_, body = do(t, "GET", base+"/search/node?q=run_list:recipe%5C%5Bx%5C%5D", "")
	if !strings.Contains(body, `"total":1`) {
		t.Fatalf("search on the normalized run list: %s", body)
	}
}

func TestRoleRunListsNormalizedOnSave(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"

	resp, body := do(t, "POST", base+"/roles",
		`{"name":"web","run_list":["nginx","nginx"],"env_run_lists":{"prod":["a","recipe[a]","role[b]"]}}`)
	if resp.StatusCode != 201 {
		t.Fatalf("create: %d %s", resp.StatusCode, body)
	}
	want := `{"name":"web","run_list":["recipe[nginx]"],"env_run_lists":{"prod":["recipe[a]","role[b]"]}}`
	if _, body = do(t, "GET", base+"/roles/web", ""); body != want {
		t.Fatalf("stored after create = %s, want %s", body, want)
	}

	resp, body = do(t, "PUT", base+"/roles/web", `{"name":"web","run_list":["c","recipe[c]"],"env_run_lists":{}}`)
	want = `{"name":"web","run_list":["recipe[c]"],"env_run_lists":{}}`
	if resp.StatusCode != 200 || body != want {
		t.Fatalf("update: %d %s, want %s", resp.StatusCode, body, want)
	}
	if _, body = do(t, "GET", base+"/roles/web", ""); body != want {
		t.Fatalf("stored after update = %s", body)
	}
}

// Environments carry no run list in erchef and are stored as sent.
func TestEnvironmentNotRunListNormalized(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	doc := `{"name":"prod","run_list":["a","a"]}`
	if resp, body := do(t, "POST", base+"/environments", doc); resp.StatusCode != 201 {
		t.Fatalf("create: %d %s", resp.StatusCode, body)
	}
	if _, body := do(t, "GET", base+"/environments/prod", ""); body != doc {
		t.Fatalf("stored = %s", body)
	}
}
