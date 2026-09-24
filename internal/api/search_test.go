package api

import (
	"encoding/json"
	"strings"
	"testing"
)

// seedNode stores a node with the given name, environment, and a normal
// attribute foo.bar so search can exercise nested-attribute matching.
func seedNode(t *testing.T, base, name, env, bar string) {
	t.Helper()
	resp, b := do(t, "POST", base+"/nodes", searchNodeBody(name, env, bar))
	if resp.StatusCode != 201 {
		t.Fatalf("seed node %s = %d: %s", name, resp.StatusCode, b)
	}
}

// updateNode rewrites an existing node seeded by seedNode.
func updateNode(t *testing.T, base, name, env, bar string) {
	t.Helper()
	resp, b := do(t, "PUT", base+"/nodes/"+name, searchNodeBody(name, env, bar))
	if resp.StatusCode != 200 {
		t.Fatalf("update node %s = %d: %s", name, resp.StatusCode, b)
	}
}

func searchNodeBody(name, env, bar string) string {
	return `{"name":"` + name + `","chef_environment":"` + env + `","json_class":"Chef::Node",` +
		`"normal":{"foo":{"bar":"` + bar + `"}},"run_list":["recipe[nginx]"]}`
}

type searchResult struct {
	Total int               `json:"total"`
	Start int               `json:"start"`
	Rows  []json.RawMessage `json:"rows"`
}

func TestSearchNodes(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	seedNode(t, base, "web01", "production", "alpha")
	seedNode(t, base, "web02", "production", "beta")
	seedNode(t, base, "db01", "staging", "alpha")

	// Match all.
	var res searchResult
	_, body := do(t, "GET", base+"/search/node?q=*:*", "")
	json.Unmarshal([]byte(body), &res)
	if res.Total != 3 {
		t.Fatalf("q=*:* total = %d, want 3: %s", res.Total, body)
	}

	// Field match on a top-level attribute.
	_, body = do(t, "GET", base+"/search/node?q=chef_environment:production", "")
	json.Unmarshal([]byte(body), &res)
	if res.Total != 2 {
		t.Fatalf("env:production total = %d, want 2", res.Total)
	}

	// Nested attribute via deepest suffix key.
	_, body = do(t, "GET", base+"/search/node?q=foo_bar:alpha", "")
	json.Unmarshal([]byte(body), &res)
	if res.Total != 2 {
		t.Fatalf("foo_bar:alpha total = %d, want 2: %s", res.Total, body)
	}

	// Boolean AND.
	_, body = do(t, "GET", base+"/search/node?q=chef_environment:production+AND+foo_bar:alpha", "")
	json.Unmarshal([]byte(body), &res)
	if res.Total != 1 {
		t.Fatalf("AND query total = %d, want 1: %s", res.Total, body)
	}
}

// TestSearchReflectsUpdatesEndToEnd guards the flatten cache: a re-indexed node
// must be found by its new attribute value and no longer by its old one.
func TestSearchReflectsUpdatesEndToEnd(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	seedNode(t, base, "web01", "production", "alpha")

	var res searchResult
	_, body := do(t, "GET", base+"/search/node?q=foo_bar:alpha", "")
	json.Unmarshal([]byte(body), &res)
	if res.Total != 1 {
		t.Fatalf("before update foo_bar:alpha total = %d, want 1: %s", res.Total, body)
	}

	// Re-index the node with a new attribute value.
	updateNode(t, base, "web01", "production", "omega")

	_, body = do(t, "GET", base+"/search/node?q=foo_bar:alpha", "")
	json.Unmarshal([]byte(body), &res)
	if res.Total != 0 {
		t.Fatalf("after update foo_bar:alpha total = %d, want 0 (stale cache): %s", res.Total, body)
	}
	_, body = do(t, "GET", base+"/search/node?q=foo_bar:omega", "")
	json.Unmarshal([]byte(body), &res)
	if res.Total != 1 {
		t.Fatalf("after update foo_bar:omega total = %d, want 1: %s", res.Total, body)
	}
}

// TestSearchEscapedRunListItem: the Lucene-escaped form of a run list item,
// the one knife's documentation uses, matches roles and nodes with it.
func TestSearchEscapedRunListItem(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	seedNode(t, base, "web01", "production", "alpha")
	resp, b := do(t, "POST", base+"/roles", `{"name":"web","json_class":"Chef::Role","run_list":["recipe[base]"]}`)
	if resp.StatusCode != 201 {
		t.Fatalf("create role = %d: %s", resp.StatusCode, b)
	}
	do(t, "POST", base+"/roles", `{"name":"db","json_class":"Chef::Role","run_list":["recipe[postgres]"]}`)

	for _, c := range []struct {
		index, q string
		want     int
	}{
		{"role", `name:web+AND+run_list:recipe\[base\]`, 1},
		{"role", `run_list:recipe\[base\]`, 1},
		{"node", `run_list:recipe\[nginx\]`, 1},
		{"node", `run_list:recipe\[base\]`, 0},
	} {
		resp, body := do(t, "GET", base+"/search/"+c.index+"?q="+strings.ReplaceAll(strings.ReplaceAll(c.q, `\`, "%5C"), "[", "%5B"), "")
		if resp.StatusCode != 200 {
			t.Errorf("%s q=%s = %d: %s", c.index, c.q, resp.StatusCode, body)
			continue
		}
		var res searchResult
		json.Unmarshal([]byte(body), &res)
		if res.Total != c.want {
			t.Errorf("%s q=%s total = %d, want %d: %s", c.index, c.q, res.Total, c.want, body)
		}
	}
}

func TestSearchPagination(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	for _, n := range []string{"a", "b", "c", "d"} {
		seedNode(t, base, n, "production", "x")
	}

	var res searchResult
	_, body := do(t, "GET", base+"/search/node?q=*:*&start=1&rows=2", "")
	json.Unmarshal([]byte(body), &res)
	if res.Total != 4 || len(res.Rows) != 2 || res.Start != 1 {
		t.Fatalf("pagination = total %d start %d rows %d: %s", res.Total, res.Start, len(res.Rows), body)
	}
}

func TestSearchDataBag(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	do(t, "POST", base+"/data", `{"name":"users"}`)
	do(t, "POST", base+"/data/users", `{"id":"alice","admin":true}`)
	do(t, "POST", base+"/data/users", `{"id":"bob","admin":false}`)

	// The data bag appears as a search index.
	_, body := do(t, "GET", base+"/search", "")
	var indexes map[string]string
	json.Unmarshal([]byte(body), &indexes)
	if _, ok := indexes["users"]; !ok {
		t.Fatalf("data bag index missing: %s", body)
	}

	var res searchResult
	_, body = do(t, "GET", base+"/search/users?q=admin:true", "")
	json.Unmarshal([]byte(body), &res)
	if res.Total != 1 {
		t.Fatalf("data bag search total = %d, want 1: %s", res.Total, body)
	}
}

func TestPartialSearch(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	seedNode(t, base, "web01", "production", "alpha")

	// Project chef_environment and the nested foo.bar attribute.
	_, body := do(t, "POST", base+"/search/node?q=name:web01",
		`{"env":["chef_environment"],"bar":["foo","bar"]}`)
	var res struct {
		Total int `json:"total"`
		Rows  []struct {
			URL  string         `json:"url"`
			Data map[string]any `json:"data"`
		} `json:"rows"`
	}
	json.Unmarshal([]byte(body), &res)
	if res.Total != 1 || len(res.Rows) != 1 {
		t.Fatalf("partial search total = %d: %s", res.Total, body)
	}
	row := res.Rows[0]
	if row.Data["env"] != "production" || row.Data["bar"] != "alpha" {
		t.Fatalf("partial data = %+v", row.Data)
	}
	if !strings.HasSuffix(row.URL, "/nodes/web01") {
		t.Fatalf("partial url = %s", row.URL)
	}
}

func TestSearchUnknownIndex404(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	resp, _ := do(t, "GET", base+"/search/nonexistent", "")
	if resp.StatusCode != 404 {
		t.Fatalf("unknown index = %d, want 404", resp.StatusCode)
	}
}

func TestSearchBadQuery400(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	resp, _ := do(t, "GET", base+"/search/node?q=%28unclosed", "")
	if resp.StatusCode != 400 {
		t.Fatalf("bad query = %d, want 400", resp.StatusCode)
	}
}

func TestPartialSearchEmptyAndMissingPaths(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	// A node with an automatic attribute (ipaddress) and a nested normal one.
	do(t, "POST", base+"/nodes",
		`{"name":"web01","chef_environment":"production","automatic":{"ipaddress":"10.0.0.5"},"normal":{"foo":{"bar":"alpha"}}}`)

	_, body := do(t, "POST", base+"/search/node?q=name:web01",
		`{"name":["name"],"ip":["ipaddress"],"missing":["does","not","exist"],"whole":[]}`)
	var res struct {
		Total int `json:"total"`
		Rows  []struct {
			Data map[string]any `json:"data"`
		} `json:"rows"`
	}
	json.Unmarshal([]byte(body), &res)
	if res.Total != 1 || len(res.Rows) != 1 {
		t.Fatalf("partial total = %d: %s", res.Total, body)
	}
	d := res.Rows[0].Data
	// Top-level field and a merged automatic attribute resolve (node precedence).
	if d["name"] != "web01" || d["ip"] != "10.0.0.5" {
		t.Fatalf("resolved fields = %+v", d)
	}
	// A non-resolving path yields no value, not an error.
	if d["missing"] != nil {
		t.Fatalf("missing path should be null, got %v", d["missing"])
	}
	// An empty projection yields no value for that key — NOT the whole document.
	if d["whole"] != nil {
		t.Fatalf("empty projection should yield no value, got %v", d["whole"])
	}
}

func TestPartialSearchNonNodeNestedPath(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	// Roles carry attributes under default_attributes (no node-style merge).
	do(t, "POST", base+"/roles",
		`{"name":"web","default_attributes":{"top":{"middle":{"bottom":"deep"}}}}`)

	_, body := do(t, "POST", base+"/search/role?q=name:web",
		`{"nested":["default_attributes","top","middle","bottom"],"empty":[]}`)
	var res struct {
		Rows []struct {
			URL  string         `json:"url"`
			Data map[string]any `json:"data"`
		} `json:"rows"`
	}
	json.Unmarshal([]byte(body), &res)
	if len(res.Rows) != 1 {
		t.Fatalf("expected 1 role row: %s", body)
	}
	d := res.Rows[0].Data
	if d["nested"] != "deep" {
		t.Fatalf("nested path = %v, want deep", d["nested"])
	}
	if d["empty"] != nil {
		t.Fatalf("empty projection should yield no value, got %v", d["empty"])
	}
	if !strings.HasSuffix(res.Rows[0].URL, "/roles/web") {
		t.Fatalf("role row url = %s", res.Rows[0].URL)
	}
}

func TestPartialSearchEmptyPostBodyIsFullSearch(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	seedNode(t, base, "web01", "production", "alpha")
	// A POST with no body is a plain search (not a 400), returning whole docs.
	resp, body := do(t, "POST", base+"/search/node?q=name:web01", "")
	if resp.StatusCode != 200 {
		t.Fatalf("empty-body POST search = %d: %s", resp.StatusCode, body)
	}
	var res searchResult
	json.Unmarshal([]byte(body), &res)
	if res.Total != 1 || len(res.Rows) != 1 {
		t.Fatalf("empty-body POST total = %d: %s", res.Total, body)
	}
	// Whole-object row (not a {url,data} projection).
	if !strings.Contains(string(res.Rows[0]), `"web01"`) || strings.Contains(string(res.Rows[0]), `"data"`) {
		t.Fatalf("expected whole-object row, got %s", res.Rows[0])
	}
}
