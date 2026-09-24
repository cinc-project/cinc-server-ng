package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// These tests pin behavior that previously regressed. Each corresponds to a
// confirmed bug fixed in the same change; the comment names the symptom so a
// future regression is easy to trace back.

// TestSearchPaginationOverflowNoPanic guards against an integer overflow in the
// search result window. A caller-supplied start near math.MaxInt made
// start+rows wrap negative, producing an invalid (low > high) slice that
// panicked the handler. A huge start must instead yield an empty window.
func TestSearchPaginationOverflowNoPanic(t *testing.T) {
	srv, st := newTestAPI(t)
	org, _, err := st.Org("acme")
	if err != nil {
		t.Fatal(err)
	}
	if err := org.Put("nodes", "n1", []byte(`{"name":"n1"}`)); err != nil {
		t.Fatal(err)
	}

	resp, body := do(t, "GET",
		srv.URL+"/organizations/acme/search/node?q=*:*&start=9223372036854775807&rows=1000", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("overflowing start = %d, want 200; body %s", resp.StatusCode, body)
	}
	var res struct {
		Total int               `json:"total"`
		Rows  []json.RawMessage `json:"rows"`
	}
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		t.Fatalf("decode search response: %v (%s)", err, body)
	}
	if res.Total != 1 {
		t.Errorf("total = %d, want 1", res.Total)
	}
	if len(res.Rows) != 0 {
		t.Errorf("rows = %d, want 0 (start past the end)", len(res.Rows))
	}
}

// TestSearchPaginationWindow checks ordinary start/rows windowing still works,
// so the overflow guard did not change the happy path.
func TestSearchPaginationWindow(t *testing.T) {
	srv, st := newTestAPI(t)
	org, _, err := st.Org("acme")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "b", "c", "d"} {
		if err := org.Put("nodes", id, []byte(`{"name":"`+id+`"}`)); err != nil {
			t.Fatal(err)
		}
	}
	_, body := do(t, "GET", srv.URL+"/organizations/acme/search/node?q=*:*&start=1&rows=2", "")
	var res struct {
		Total int `json:"total"`
		Start int `json:"start"`
		Rows  []struct {
			Name string `json:"name"`
		} `json:"rows"`
	}
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		t.Fatalf("decode: %v (%s)", err, body)
	}
	if res.Total != 4 {
		t.Errorf("total = %d, want 4", res.Total)
	}
	if len(res.Rows) != 2 || res.Rows[0].Name != "b" || res.Rows[1].Name != "c" {
		t.Errorf("window = %+v, want [b c]", res.Rows)
	}
}

// TestGlobalUserURIShape pins that global users (which are not org-scoped) are
// addressed at the top level. The URI builder previously prefixed every object
// with /organizations/{org}/, producing the malformed /organizations//users/...
// for the empty org of a global user.
func TestGlobalUserURIShape(t *testing.T) {
	srv, _ := newTestAPI(t)

	resp, body := do(t, "POST", srv.URL+"/users", `{"name":"alice"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create user = %d: %s", resp.StatusCode, body)
	}
	var created struct {
		URI string `json:"uri"`
	}
	json.Unmarshal([]byte(body), &created)
	if !strings.HasSuffix(created.URI, "/users/alice") || strings.Contains(created.URI, "/organizations/") {
		t.Errorf("create uri = %q, want it to end in /users/alice with no /organizations/ segment", created.URI)
	}

	_, body = do(t, "GET", srv.URL+"/users", "")
	var list map[string]string
	if err := json.Unmarshal([]byte(body), &list); err != nil {
		t.Fatalf("decode user list: %v (%s)", err, body)
	}
	if got := list["alice"]; !strings.HasSuffix(got, "/users/alice") || strings.Contains(got, "/organizations/") {
		t.Errorf("list uri = %q, want it to end in /users/alice with no /organizations/ segment", got)
	}
}

// TestGlobalUserKeyURIShape pins the same top-level addressing for a global
// user's key URIs, which are derived from the same builder.
func TestGlobalUserKeyURIShape(t *testing.T) {
	srv, _ := newTestAPI(t)
	if resp, body := do(t, "POST", srv.URL+"/users", `{"name":"alice"}`); resp.StatusCode != http.StatusCreated {
		t.Fatalf("create user = %d: %s", resp.StatusCode, body)
	}
	_, body := do(t, "GET", srv.URL+"/users/alice/keys", "")
	var list []keyListEntry
	if err := json.Unmarshal([]byte(body), &list); err != nil {
		t.Fatalf("decode key list: %v (%s)", err, body)
	}
	for _, k := range list {
		if strings.Contains(k.URI, "/organizations/") || !strings.Contains(k.URI, "/users/alice/keys/") {
			t.Errorf("key %q uri = %q, want a top-level /users/alice/keys/... URL", k.Name, k.URI)
		}
	}
}

// TestAssociateUserJoinsUsersGroup pins that direct association
// (POST /organizations/{org}/users) makes the user an org member by adding them
// to the org's "users" group — the same effect invite acceptance has. Without
// it, directly-associated users lacked group-based permissions under ACL
// enforcement.
func TestAssociateUserJoinsUsersGroup(t *testing.T) {
	srv, st := newTestAPI(t)
	org, _, err := st.Org("acme")
	if err != nil {
		t.Fatal(err)
	}
	seedAuthz(org)
	if err := st.Global().Put("users", "alice", []byte(`{"username":"alice"}`)); err != nil {
		t.Fatal(err)
	}

	if resp, body := do(t, "POST", srv.URL+"/organizations/acme/users", `{"username":"alice"}`); resp.StatusCode != http.StatusCreated {
		t.Fatalf("associate = %d: %s", resp.StatusCode, body)
	}

	_, body := do(t, "GET", srv.URL+"/organizations/acme/groups/users", "")
	var g struct {
		Users []string `json:"users"`
	}
	if err := json.Unmarshal([]byte(body), &g); err != nil {
		t.Fatalf("decode users group: %v (%s)", err, body)
	}
	found := false
	for _, u := range g.Users {
		if u == "alice" {
			found = true
		}
	}
	if !found {
		t.Errorf("users group = %v, want it to contain alice", g.Users)
	}
}

// TestActorPutPreservesPublicKey pins that updating a client/user with a body
// that omits the public key keeps the stored key instead of dropping it — a
// dropped key would break that actor's authentication.
func TestActorPutPreservesPublicKey(t *testing.T) {
	for _, tc := range []struct{ kind, base string }{
		{"client", "/organizations/acme/clients"},
		{"user", "/users"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			srv, _ := newTestAPI(t)

			if resp, body := do(t, "POST", srv.URL+tc.base, `{"name":"web01"}`); resp.StatusCode != http.StatusCreated {
				t.Fatalf("create %s = %d: %s", tc.kind, resp.StatusCode, body)
			}
			_, body := do(t, "GET", srv.URL+tc.base+"/web01", "")
			var before map[string]any
			json.Unmarshal([]byte(body), &before)
			key, _ := before["public_key"].(string)
			if key == "" {
				t.Fatalf("created %s has no public_key: %s", tc.kind, body)
			}

			// An update that does not re-send the key must not clear it.
			if resp, b := do(t, "PUT", srv.URL+tc.base+"/web01", `{"name":"web01","validator":false}`); resp.StatusCode != http.StatusOK {
				t.Fatalf("put %s = %d: %s", tc.kind, resp.StatusCode, b)
			}
			_, body = do(t, "GET", srv.URL+tc.base+"/web01", "")
			var after map[string]any
			json.Unmarshal([]byte(body), &after)
			if got, _ := after["public_key"].(string); got != key {
				t.Errorf("%s public_key after PUT = %q, want preserved %q", tc.kind, got, key)
			}
		})
	}
}

// TestActorPutReplacesPublicKeyWhenProvided pins that a PUT carrying a new key
// (top-level or nested under chef_key) still replaces the stored one.
func TestActorPutReplacesPublicKeyWhenProvided(t *testing.T) {
	srv, _ := newTestAPI(t)
	do(t, "POST", srv.URL+"/organizations/acme/clients", `{"name":"web01"}`)

	const newKey = "-----BEGIN PUBLIC KEY-----\nREPLACED\n-----END PUBLIC KEY-----\n"
	body, _ := json.Marshal(map[string]any{"name": "web01", "public_key": newKey})
	if resp, b := do(t, "PUT", srv.URL+"/organizations/acme/clients/web01", string(body)); resp.StatusCode != http.StatusOK {
		t.Fatalf("put = %d: %s", resp.StatusCode, b)
	}
	_, got := do(t, "GET", srv.URL+"/organizations/acme/clients/web01", "")
	var after map[string]any
	json.Unmarshal([]byte(got), &after)
	if after["public_key"] != newKey {
		t.Errorf("public_key = %v, want the provided replacement", after["public_key"])
	}
}

// TestCreateDataBagStoresCanonicalJSON pins that a bag name is stored as
// canonical JSON. The name was previously concatenated into a JSON string
// literal, so a name containing a double quote produced a malformed,
// unparseable stored value. Such a name is now refused outright (erchef's
// data_bag_name rule), so it must not be stored at all.
func TestCreateDataBagStoresCanonicalJSON(t *testing.T) {
	srv, st := newTestAPI(t)
	org, _, err := st.Org("acme")
	if err != nil {
		t.Fatal(err)
	}

	if resp, body := do(t, "POST", srv.URL+"/organizations/acme/data", `{"name":"a\"b"}`); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("create data bag with a quote = %d: %s, want 400", resp.StatusCode, body)
	}
	if _, ok, _ := org.Get(dataBagsColl, `a"b`); ok {
		t.Fatal("a refused data bag was stored")
	}

	const name = "a.b"
	if resp, body := do(t, "POST", srv.URL+"/organizations/acme/data", `{"name":"a.b"}`); resp.StatusCode != http.StatusCreated {
		t.Fatalf("create data bag = %d: %s", resp.StatusCode, body)
	}

	raw, ok, err := org.Get(dataBagsColl, name)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatalf("data bag %q not stored", name)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("stored data bag is not valid JSON: %v (%s)", err, raw)
	}
	if doc["name"] != name {
		t.Errorf("stored name = %v, want %q", doc["name"], name)
	}
}
