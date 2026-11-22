package api

import (
	"net/http"
	"testing"
)

// TestNodeNameValidation holds node create to erchef's chef_node validation:
// the name must match chef_regex's node_name (^[.[:alnum:]_:-]+$), and a
// failure renders as chef_wm_malformed's string_match message.
func TestNodeNameValidation(t *testing.T) {
	cases := []struct{ name, body, want string }{
		{"slash", `{"name":"sec/ret"}`, "Field 'name' invalid"},
		{"space and markup", `{"name":"a b<>\""}`, "Field 'name' invalid"},
		{"bang", `{"name":"web!"}`, "Field 'name' invalid"},
		{"empty", `{"name":""}`, "Field 'name' invalid"},
		{"not a string", `{"name":12}`, "Field 'name' invalid"},
		{"missing", `{"run_list":[]}`, "Field 'name' missing"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv, _ := newTestAPI(t)
			base := srv.URL + "/organizations/acme"
			resp, body := do(t, "POST", base+"/nodes", c.body)
			wantError(t, "POST /nodes", resp, body, c.want)
			if _, body := do(t, "GET", base+"/nodes", ""); body != "{}" {
				t.Errorf("nodes after a refused create = %s, want none", body)
			}
		})
	}
}

// TestNodeNameValidationAccepts: every character node_name allows is still
// accepted, ".." included (it is all dots, which the pattern permits).
func TestNodeNameValidationAccepts(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	for _, name := range []string{"ABCxyz0189-_:.", "..", "web01.example.com"} {
		if resp, body := do(t, "POST", base+"/nodes", `{"name":"`+name+`"}`); resp.StatusCode != http.StatusCreated {
			t.Errorf("create node %q = %d: %s", name, resp.StatusCode, body)
		}
	}
}

// TestNodeUpdateName: a node PUT may omit the name (the URL supplies it), but
// one naming a different node is refused (chef_node:validate_json_node).
func TestNodeUpdateName(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	if resp, body := do(t, "POST", base+"/nodes", `{"name":"web"}`); resp.StatusCode != http.StatusCreated {
		t.Fatalf("create = %d: %s", resp.StatusCode, body)
	}
	resp, body := do(t, "PUT", base+"/nodes/web", `{"name":"db"}`)
	wantError(t, "PUT with another name", resp, body, "Node name mismatch.")
	if resp, body := do(t, "PUT", base+"/nodes/web", `{"run_list":[]}`); resp.StatusCode != http.StatusOK {
		t.Errorf("PUT without a name = %d: %s", resp.StatusCode, body)
	}
}

// TestContainerNameValidation holds container create to erchef's
// oc_chef_container:parse_binary_json: the name ("id" if given, else
// "containername") must match ^[.[:alnum:]_-]+$ (no ':'), and a failure is a
// bad_object_name, which chef_wm_malformed renders with the message in place
// of the pattern.
func TestContainerNameValidation(t *testing.T) {
	const msg = "' using regex: 'Malformed container name. Must only contain A-Z, a-z, 0-9, _, -, or .'."
	cases := []struct{ name, body, want string }{
		{"slash", `{"containername":"x/y"}`, "Invalid name 'x/y" + msg},
		{"colon", `{"containername":"a:b"}`, "Invalid name 'a:b" + msg},
		{"space", `{"containername":"a b"}`, "Invalid name 'a b" + msg},
		{"empty", `{"containername":""}`, "Invalid name '" + msg},
		{"id wins", `{"id":"x/y","containername":"fine"}`, "Invalid name 'x/y" + msg},
		{"missing", `{"containerpath":"p"}`, "Field 'containername' missing"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv, st := newTestAPI(t)
			base := srv.URL + "/organizations/acme"
			resp, body := do(t, "POST", base+"/containers", c.body)
			wantError(t, "POST /containers", resp, body, c.want)
			org, _, _ := st.Org("acme")
			if keys, _ := org.Keys("containers"); len(keys) != 0 {
				t.Errorf("containers after a refused create = %v, want none", keys)
			}
		})
	}
}

// TestContainerCreateLikeErchef: "id" names the container when both fields are given,
// the stored document is erchef's {containername, containerpath}, and a second
// create of the same name is a 409 rather than an overwrite.
func TestContainerCreateLikeErchef(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	resp, body := do(t, "POST", base+"/containers", `{"id":"a.b_c-1","containername":"other","extra":true}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create = %d: %s", resp.StatusCode, body)
	}
	if _, body := do(t, "GET", base+"/containers/a.b_c-1", ""); !sameJSON(body, `{"containername":"a.b_c-1","containerpath":"a.b_c-1"}`) {
		t.Errorf("stored container = %s", body)
	}
	resp, body = do(t, "POST", base+"/containers", `{"containername":"a.b_c-1"}`)
	if resp.StatusCode != http.StatusConflict || !sameJSON(body, `{"error":["Container already exists"]}`) {
		t.Errorf("duplicate create = %d %s, want 409 Container already exists", resp.StatusCode, body)
	}
}

// TestClassifyRequestSplitsLikeTheRouter: classification takes the escaped
// path and splits it as http.ServeMux does, so an encoded slash stays inside
// its segment and the check names the object the handler will serve.
func TestClassifyRequestSplitsLikeTheRouter(t *testing.T) {
	got, ok := classifyRequest(http.MethodGet, "/organizations/acme/nodes/sec%2Fret")
	if !ok || got.aclType != "nodes" || got.aclName != "sec/ret" || got.perm != "read" || got.existKey != "sec/ret" {
		t.Fatalf("classify GET nodes/sec%%2Fret = %+v, %v; want read on nodes/sec/ret", got, ok)
	}
	got, ok = classifyRequest(http.MethodGet, "/organizations/acme/data/bag/it%2Fem")
	if !ok || got.aclType != "data" || got.aclName != "bag" {
		t.Fatalf("classify GET data/bag/it%%2Fem = %+v, %v; want read on data/bag", got, ok)
	}
	// An escaped slash does not turn one segment into an open-write prefix.
	if reason := openWriteReason(http.MethodPost, "/organizations/acme/environments%2Fx"); reason != "" {
		t.Errorf("POST environments%%2Fx is an open write (%q); it is a single segment", reason)
	}
	if got := PathSegments("/organizations/acme/nodes/%2E%2E/a%ZZ"); len(got) != 5 || got[3] != ".." || got[4] != "a%ZZ" {
		t.Errorf("PathSegments = %q", got)
	}
}
