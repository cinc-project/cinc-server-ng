package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// newTestAPI returns an API backed by a store containing a single org "acme",
// wrapped in an httptest server. Auth is not part of the API layer.
func newTestAPI(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	st := store.New()
	if _, err := st.CreateOrg("acme"); err != nil {
		t.Fatal(err)
	}
	api := New(st)
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)
	return srv, st
}

func do(t *testing.T, method, url, body string) (*http.Response, string) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, r)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func TestNodeCreateListGetDelete(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"

	// Empty list.
	resp, body := do(t, "GET", base+"/nodes", "")
	if resp.StatusCode != 200 {
		t.Fatalf("list status %d: %s", resp.StatusCode, body)
	}
	if strings.TrimSpace(body) != "{}" {
		t.Fatalf("empty list = %s", body)
	}

	// Create.
	resp, body = do(t, "POST", base+"/nodes", `{"name":"web01","chef_environment":"_default"}`)
	if resp.StatusCode != 201 {
		t.Fatalf("create status %d: %s", resp.StatusCode, body)
	}
	var created map[string]string
	json.Unmarshal([]byte(body), &created)
	if !strings.HasSuffix(created["uri"], "/organizations/acme/nodes/web01") {
		t.Fatalf("create uri = %q", created["uri"])
	}

	// Duplicate create -> 409.
	resp, _ = do(t, "POST", base+"/nodes", `{"name":"web01"}`)
	if resp.StatusCode != 409 {
		t.Fatalf("duplicate create status = %d, want 409", resp.StatusCode)
	}

	// List shows it as name->url.
	resp, body = do(t, "GET", base+"/nodes", "")
	var list map[string]string
	json.Unmarshal([]byte(body), &list)
	if !strings.HasSuffix(list["web01"], "/organizations/acme/nodes/web01") {
		t.Fatalf("list = %s", body)
	}

	// Get.
	resp, body = do(t, "GET", base+"/nodes/web01", "")
	if resp.StatusCode != 200 {
		t.Fatalf("get status %d", resp.StatusCode)
	}
	var node map[string]any
	json.Unmarshal([]byte(body), &node)
	if node["name"] != "web01" {
		t.Fatalf("get returned %s", body)
	}

	// Delete returns the object.
	resp, body = do(t, "DELETE", base+"/nodes/web01", "")
	if resp.StatusCode != 200 {
		t.Fatalf("delete status %d", resp.StatusCode)
	}
	json.Unmarshal([]byte(body), &node)
	if node["name"] != "web01" {
		t.Fatalf("delete returned %s", body)
	}

	// Get after delete -> 404 with Chef error shape.
	resp, body = do(t, "GET", base+"/nodes/web01", "")
	if resp.StatusCode != 404 {
		t.Fatalf("get-after-delete status %d", resp.StatusCode)
	}
	var errObj struct {
		Error []string `json:"error"`
	}
	json.Unmarshal([]byte(body), &errObj)
	if len(errObj.Error) == 0 {
		t.Fatalf("expected Chef error array, got %s", body)
	}
}

func TestNodePutUpdates(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	do(t, "POST", base+"/nodes", `{"name":"web01"}`)

	resp, body := do(t, "PUT", base+"/nodes/web01", `{"name":"web01","run_list":["recipe[nginx]"]}`)
	if resp.StatusCode != 200 {
		t.Fatalf("put status %d: %s", resp.StatusCode, body)
	}
	var node map[string]any
	json.Unmarshal([]byte(body), &node)
	rl, _ := node["run_list"].([]any)
	if len(rl) != 1 || rl[0] != "recipe[nginx]" {
		t.Fatalf("put did not persist run_list: %s", body)
	}
}

func TestNodeHead(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	do(t, "POST", base+"/nodes", `{"name":"web01"}`)

	resp, _ := do(t, "HEAD", base+"/nodes/web01", "")
	if resp.StatusCode != 200 {
		t.Fatalf("HEAD existing = %d", resp.StatusCode)
	}
	resp, _ = do(t, "HEAD", base+"/nodes/ghost", "")
	if resp.StatusCode != 404 {
		t.Fatalf("HEAD missing = %d", resp.StatusCode)
	}
}

func TestUnknownOrg404(t *testing.T) {
	srv, _ := newTestAPI(t)
	resp, _ := do(t, "GET", srv.URL+"/organizations/ghost/nodes", "")
	if resp.StatusCode != 404 {
		t.Fatalf("unknown org status = %d", resp.StatusCode)
	}
}
