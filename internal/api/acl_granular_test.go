package api

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
)

type granularPerm struct {
	Actors  []string `json:"actors"`
	Groups  []string `json:"groups"`
	Users   []string `json:"users"`
	Clients []string `json:"clients"`
}

func granularACLOf(t *testing.T, url string) map[string]granularPerm {
	t.Helper()
	resp, body := do(t, "GET", url+"?detail=granular", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s?detail=granular = %d: %s", url, resp.StatusCode, body)
	}
	var acl map[string]granularPerm
	if err := json.Unmarshal([]byte(body), &acl); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	return acl
}

// erchef's ?detail=granular (oc_chef_wm_acl to_json, oc_chef_authz_acl
// part_with_actors) splits each permission's actors into users and clients
// and reports actors as [].
func TestACLDetailGranularSplitsActors(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	do(t, "POST", base+"/nodes", `{"name":"web01"}`)
	do(t, "POST", srv.URL+"/users", userBody(`{"name":"alice"}`))
	do(t, "POST", base+"/clients", `{"name":"web-client"}`)
	if resp, body := do(t, "PUT", base+"/nodes/web01/_acl/read",
		`{"read":{"actors":["alice","web-client"],"groups":[]}}`); resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT read = %d: %s", resp.StatusCode, body)
	}

	// Baseline: without detail=granular, only the merged actors list.
	_, body := do(t, "GET", base+"/nodes/web01/_acl", "")
	var plain map[string]map[string]any
	json.Unmarshal([]byte(body), &plain)
	for perm, ace := range plain {
		if _, ok := ace["users"]; ok {
			t.Fatalf("plain _acl %s reports users: %s", perm, body)
		}
		if _, ok := ace["clients"]; ok {
			t.Fatalf("plain _acl %s reports clients: %s", perm, body)
		}
	}

	acl := granularACLOf(t, base+"/nodes/web01/_acl")
	for _, perm := range aclPerms {
		p := acl[perm]
		if p.Actors == nil || len(p.Actors) != 0 || p.Users == nil || p.Clients == nil || p.Groups == nil {
			t.Errorf("%s = %+v, want actors [] and users, clients and groups arrays", perm, p)
		}
	}
	if r := acl["read"]; !slices.Equal(r.Users, []string{"alice"}) || !slices.Equal(r.Clients, []string{"web-client"}) {
		t.Errorf("read = %+v, want users [alice] and clients [web-client]", r)
	}

	// The org's own ACL and a global user's ACL take the parameter too.
	granularACLOf(t, base+"/organizations/_acl")
	if u := granularACLOf(t, srv.URL+"/users/alice/_acl")["read"]; len(u.Clients) != 0 {
		t.Errorf("a global user's ACL lists clients: %+v", u)
	}
}

// erchef's PUT takes {"actors":[],"users":[...],"clients":[...]} as well as
// the merged actors form (oc_chef_authz_acl acl_spec and
// validate_actors_clients_users).
func TestACLPutSplitForm(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	url := base + "/nodes/web01/_acl/read"
	do(t, "POST", base+"/nodes", `{"name":"web01"}`)
	do(t, "POST", srv.URL+"/users", userBody(`{"name":"alice"}`))
	do(t, "POST", base+"/clients", `{"name":"web-client"}`)

	resp, body := do(t, "PUT", url, `{"read":{"actors":[],"users":["alice"],"clients":["web-client"],"groups":[]}}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("split-form PUT = %d: %s", resp.StatusCode, body)
	}
	_, body = do(t, "GET", base+"/nodes/web01/_acl", "")
	var acl map[string]aclPerm
	json.Unmarshal([]byte(body), &acl)
	// The merged view lists clients, then users, as erchef's does.
	if got := acl["read"].Actors; !slices.Equal(got, []string{"web-client", "alice"}) {
		t.Fatalf("split-form PUT stored actors %v, want [web-client alice]: %s", got, body)
	}
	if r := granularACLOf(t, base+"/nodes/web01/_acl")["read"]; !slices.Equal(r.Users, []string{"alice"}) ||
		!slices.Equal(r.Clients, []string{"web-client"}) {
		t.Errorf("granular read after split PUT = %+v", r)
	}

	_, before := do(t, "GET", base+"/nodes/web01/_acl", "")
	for _, c := range []struct{ body, want string }{
		{`{"read":{"actors":["alice"],"users":["alice"],"clients":[],"groups":[]}}`,
			"When providing 'users' and 'clients' fields, the 'actors' field must have a value of []."},
		{`{"read":{"actors":[],"users":["alice"],"groups":[]}}`,
			"You provided 'users' with your request. Including this field also requires that you provide 'clients'"},
		{`{"read":{"actors":[],"clients":["web-client"],"groups":[]}}`,
			"You provided 'clients' with your request. Including this field also requires that you provide 'users'"},
		{`{"read":{"actors":[],"users":["ghost"],"clients":[],"groups":[]}}`,
			"The user(s) ghost do not exist in this organization."},
		// A user is not a client, even though it is a valid actor.
		{`{"read":{"actors":[],"users":[],"clients":["alice"],"groups":[]}}`,
			"The client(s) alice do not exist in this organization."},
	} {
		resp, body := do(t, "PUT", url, c.body)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("PUT %s = %d, want 400: %s", c.body, resp.StatusCode, body)
			continue
		}
		if want := `{"error":["` + c.want + `"]}`; strings.TrimSpace(body) != want {
			t.Errorf("PUT %s body = %s, want %s", c.body, body, want)
		}
	}
	if _, after := do(t, "GET", base+"/nodes/web01/_acl", ""); after != before {
		t.Errorf("a refused PUT changed the ACL:\nbefore %s\nafter  %s", before, after)
	}

	// A global user's ACL holds no clients.
	resp, body = do(t, "PUT", srv.URL+"/users/alice/_acl/read",
		`{"read":{"actors":[],"users":["alice"],"clients":["web-client"],"groups":[]}}`)
	if want := `{"error":["Clients can not be added to global ACL entries."]}`; resp.StatusCode != http.StatusBadRequest ||
		strings.TrimSpace(body) != want {
		t.Errorf("global split PUT with a client = %d %s, want 400 %s", resp.StatusCode, body, want)
	}
}

// A name that is both a client and a member user is ambiguous in the merged
// form: erchef answers 422 (oc_chef_wm_acl_permission ambiguous_actor), and
// the split form names one of them.
func TestACLPutAmbiguousActor(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	url := base + "/nodes/web01/_acl/read"
	do(t, "POST", base+"/nodes", `{"name":"web01"}`)
	for _, c := range []struct{ url, body string }{
		{srv.URL + "/users", userBody(`{"name":"dual"}`)},
		{base + "/clients", `{"name":"dual"}`},
	} {
		if resp, body := do(t, "POST", c.url, c.body); resp.StatusCode != http.StatusCreated {
			t.Fatalf("POST %s = %d: %s", c.url, resp.StatusCode, body)
		}
	}

	// Baseline: the user is no member yet, so "dual" names only the client.
	if resp, body := do(t, "PUT", url, `{"read":{"actors":["dual"],"groups":[]}}`); resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT before membership = %d: %s", resp.StatusCode, body)
	}
	if r := granularACLOf(t, base+"/nodes/web01/_acl")["read"]; !slices.Equal(r.Clients, []string{"dual"}) || len(r.Users) != 0 {
		t.Fatalf("read = %+v, want the client only", r)
	}

	if resp, body := do(t, "POST", base+"/users", `{"username":"dual"}`); resp.StatusCode != http.StatusCreated {
		t.Fatalf("associate dual = %d: %s", resp.StatusCode, body)
	}
	resp, body := do(t, "PUT", url, `{"read":{"actors":["dual"],"groups":[]}}`)
	const want = `{"error":["The following actor(s) exist as both clients and users within this organization: dual. ` +
		`To perform this update, supply separate 'clients' and 'users' fields in your request, and use an empty array for the value of 'actors'."]}`
	if resp.StatusCode != http.StatusUnprocessableEntity || strings.TrimSpace(body) != want {
		t.Fatalf("ambiguous actor PUT = %d %s, want 422 %s", resp.StatusCode, body, want)
	}

	if resp, body := do(t, "PUT", url, `{"read":{"actors":[],"users":["dual"],"clients":[],"groups":[]}}`); resp.StatusCode != http.StatusOK {
		t.Fatalf("split-form PUT naming the user = %d: %s", resp.StatusCode, body)
	}
	if r := granularACLOf(t, base+"/nodes/web01/_acl")["read"]; !slices.Equal(r.Users, []string{"dual"}) || len(r.Clients) != 0 {
		t.Errorf("read = %+v, want the user only", r)
	}
}
