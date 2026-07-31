package server

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// Search must not become a side door around object ACLs: the direct read route
// returns 403, so the same object must not come back in a search body.

// searchIDs runs a search as the given actor and returns the ids of the rows it
// got back, so a test can assert on exactly which documents were disclosed.
func searchIDs(t *testing.T, req *http.Request, idField string) []string {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("search = %d: %s", resp.StatusCode, raw)
	}
	var body struct {
		Total int              `json:"total"`
		Rows  []map[string]any `json:"rows"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decode search body: %v: %s", err, raw)
	}
	if body.Total != len(body.Rows) {
		t.Errorf("total %d disagrees with %d rows returned", body.Total, len(body.Rows))
	}
	ids := make([]string, 0, len(body.Rows))
	for _, row := range body.Rows {
		id, _ := row[idField].(string)
		ids = append(ids, id)
	}
	return ids
}

// restrictRead narrows an object's read ACL to the bootstrap admin.
func restrictRead(t *testing.T, srv *Server, aclURL string) {
	t.Helper()
	body := `{"read":{"actors":["` + srv.AdminName() + `"],"groups":["admins"]}}`
	if code := statusOf(t, signed(t, srv, "PUT", aclURL, body)); code != http.StatusOK {
		t.Fatalf("restrict %s = %d, want 200", aclURL, code)
	}
}

func TestSearchRespectsDataBagACL(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	base := srv.URL() + "/organizations/acme"
	nodeKey := createActor(t, srv, base+"/clients", `{"name":"node1"}`)

	if code := statusOf(t, signed(t, srv, "POST", base+"/data", `{"name":"secrets"}`)); code != 201 {
		t.Fatalf("create bag = %d, want 201", code)
	}
	if code := statusOf(t, signed(t, srv, "POST", base+"/data/secrets",
		`{"id":"creds","password":"hunter2"}`)); code != 201 {
		t.Fatalf("create item = %d, want 201", code)
	}
	restrictRead(t, srv, base+"/data/secrets/_acl/read")

	// The direct route already refuses.
	if code := statusOf(t, signedAs(t, "node1", nodeKey, "GET", base+"/data/secrets/creds", "")); code != http.StatusForbidden {
		t.Fatalf("node1 direct read = %d, want 403", code)
	}
	// Search must refuse the same content.
	got := searchIDs(t, signedAs(t, "node1", nodeKey, "GET", base+"/search/secrets?q=*:*", ""), "id")
	if len(got) != 0 {
		t.Fatalf("node1 search disclosed %v, want no rows", got)
	}
	// The admin still sees it.
	got = searchIDs(t, signed(t, srv, "GET", base+"/search/secrets?q=*:*", ""), "id")
	if len(got) != 1 || got[0] != "creds" {
		t.Fatalf("admin search = %v, want [creds]", got)
	}
}

func TestSearchFiltersPerObjectACL(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	base := srv.URL() + "/organizations/acme"
	nodeKey := createActor(t, srv, base+"/clients", `{"name":"node1"}`)

	for _, name := range []string{"open01", "secret01"} {
		if code := statusOf(t, signed(t, srv, "POST", base+"/nodes", `{"name":"`+name+`"}`)); code != 201 {
			t.Fatalf("create node %s = %d, want 201", name, code)
		}
	}
	restrictRead(t, srv, base+"/nodes/secret01/_acl/read")

	got := searchIDs(t, signedAs(t, "node1", nodeKey, "GET", base+"/search/node?q=*:*", ""), "name")
	if len(got) != 1 || got[0] != "open01" {
		t.Fatalf("node1 search = %v, want [open01] only", got)
	}
	// A targeted query must not leak it either.
	got = searchIDs(t, signedAs(t, "node1", nodeKey, "GET", base+"/search/node?q=name:secret01", ""), "name")
	if len(got) != 0 {
		t.Fatalf("node1 targeted search = %v, want no rows", got)
	}
}

// The read filter memoizes parsed ACLs to keep a scan from re-parsing every
// ACL document per request. An ACL change must still take effect on the very
// next search, or the cache would serve stale authorization.
func TestSearchReflectsACLChangeImmediately(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	base := srv.URL() + "/organizations/acme"
	nodeKey := createActor(t, srv, base+"/clients", `{"name":"node1"}`)

	if code := statusOf(t, signed(t, srv, "POST", base+"/nodes", `{"name":"web01"}`)); code != 201 {
		t.Fatalf("create node = %d, want 201", code)
	}
	search := signedAs(t, "node1", nodeKey, "GET", base+"/search/node?q=*:*", "")
	if got := searchIDs(t, search, "name"); len(got) != 1 {
		t.Fatalf("before restriction: %v, want [web01]", got)
	}

	// Revoke, then search again: the tightened ACL must apply at once.
	restrictRead(t, srv, base+"/nodes/web01/_acl/read")
	if got := searchIDs(t, signedAs(t, "node1", nodeKey, "GET", base+"/search/node?q=*:*", ""), "name"); len(got) != 0 {
		t.Fatalf("after restriction: %v, want no rows", got)
	}

	// And re-granting must apply at once too, so the cache is not merely
	// latching on the first answer it computed.
	grant := `{"read":{"actors":[],"groups":["admins","users","clients"]}}`
	if code := statusOf(t, signed(t, srv, "PUT", base+"/nodes/web01/_acl/read", grant)); code != 200 {
		t.Fatalf("re-grant = %d, want 200", code)
	}
	if got := searchIDs(t, signedAs(t, "node1", nodeKey, "GET", base+"/search/node?q=*:*", ""), "name"); len(got) != 1 {
		t.Fatalf("after re-grant: %v, want [web01]", got)
	}
}

// Group membership is likewise resolved per request; a membership change must
// take effect on the next search.
func TestSearchReflectsGroupChangeImmediately(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	base := srv.URL() + "/organizations/acme"
	nodeKey := createActor(t, srv, base+"/clients", `{"name":"node1"}`)

	if code := statusOf(t, signed(t, srv, "POST", base+"/nodes", `{"name":"web01"}`)); code != 201 {
		t.Fatalf("create node = %d, want 201", code)
	}
	// Grant read only to a group node1 is not yet in.
	grant := `{"read":{"actors":[],"groups":["auditors"]}}`
	if code := statusOf(t, signed(t, srv, "PUT", base+"/nodes/web01/_acl/read", grant)); code != 200 {
		t.Fatalf("grant to auditors = %d, want 200", code)
	}
	if got := searchIDs(t, signedAs(t, "node1", nodeKey, "GET", base+"/search/node?q=*:*", ""), "name"); len(got) != 0 {
		t.Fatalf("before joining auditors: %v, want no rows", got)
	}

	if code := statusOf(t, signed(t, srv, "POST", base+"/groups", `{"name":"auditors"}`)); code != 201 {
		t.Fatalf("create group = %d, want 201", code)
	}
	if code := statusOf(t, signed(t, srv, "PUT", base+"/groups/auditors",
		`{"actors":{"users":[],"clients":["node1"],"groups":[]}}`)); code != 200 {
		t.Fatalf("add node1 to auditors = %d, want 200", code)
	}
	if got := searchIDs(t, signedAs(t, "node1", nodeKey, "GET", base+"/search/node?q=*:*", ""), "name"); len(got) != 1 {
		t.Fatalf("after joining auditors: %v, want [web01]", got)
	}
}

// With enforcement off (the permissive default) search keeps returning
// everything, so existing test pipelines are unaffected.
func TestSearchUnfilteredWhenEnforcementOff(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}})
	base := srv.URL() + "/organizations/acme"
	nodeKey := createActor(t, srv, base+"/clients", `{"name":"node1"}`)

	if code := statusOf(t, signed(t, srv, "POST", base+"/nodes", `{"name":"web01"}`)); code != 201 {
		t.Fatalf("create node = %d, want 201", code)
	}
	restrictRead(t, srv, base+"/nodes/web01/_acl/read")

	got := searchIDs(t, signedAs(t, "node1", nodeKey, "GET", base+"/search/node?q=*:*", ""), "name")
	if len(got) != 1 || got[0] != "web01" {
		t.Fatalf("enforcement off: search = %v, want [web01]", got)
	}
}
