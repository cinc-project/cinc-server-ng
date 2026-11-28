package api

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
)

// nameList is a JSON array of n names made by name(i).
func nameList(n int, name func(i int) string) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = `"` + name(i) + `"`
	}
	return "[" + strings.Join(parts, ",") + "]"
}

// A group listed more than once is one grant: erchef resolves the names to
// authz ids in one query and bifrost keys an ACE's rows by member, so the
// entry it stores names each group once.
func TestACLPutStoresRepeatedGroupsOnce(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	do(t, "POST", base+"/nodes", `{"name":"web01"}`)
	do(t, "POST", base+"/groups", `{"groupname":"admins"}`)
	do(t, "POST", base+"/groups", `{"groupname":"ops"}`)
	do(t, "POST", base+"/clients", `{"name":"web-client"}`)

	if resp, body := do(t, "PUT", base+"/nodes/web01/_acl/read",
		`{"read":{"actors":["web-client","web-client"],"groups":["admins","ops","admins","ops","admins"]}}`); resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT read = %d: %s", resp.StatusCode, body)
	}
	read := granularACLOf(t, base+"/nodes/web01/_acl")["read"]
	if !slices.Equal(read.Groups, []string{"admins", "ops"}) {
		t.Fatalf("groups = %v, want [admins ops]", read.Groups)
	}
	if !slices.Equal(read.Clients, []string{"web-client"}) {
		t.Fatalf("clients = %v, want [web-client]", read.Clients)
	}
}

// What a PUT reads from the store is bounded by the store, not by how many
// names the body lists: a repeated name is looked up once, and a long list of
// distinct names is checked against the collection's keys rather than read
// name by name. The refusal still names every unknown entry as listed.
func TestACLPutStoreReadsDoNotScaleWithListedNames(t *testing.T) {
	const n = 5000
	cases := []struct {
		name string
		body string
		want string
	}{
		{"repeated actor", `{"actors":` + nameList(n, func(int) string { return "ghost" }) + `,"groups":[]}`,
			"The actor(s) ghost, ghost"},
		{"distinct actors", `{"actors":` + nameList(n, func(i int) string { return fmt.Sprintf("g%d", i) }) + `,"groups":[]}`,
			"The actor(s) g0, g1, g2"},
		{"repeated group", `{"actors":[],"groups":` + nameList(n, func(int) string { return "nogroup" }) + `}`,
			"The group(s) nogroup, nogroup"},
		{"distinct groups", `{"actors":[],"groups":` + nameList(n, func(i int) string { return fmt.Sprintf("g%d", i) }) + `}`,
			"The group(s) g0, g1, g2"},
		{"distinct users", `{"actors":[],"users":` + nameList(n, func(i int) string { return fmt.Sprintf("g%d", i) }) + `,"clients":[],"groups":[]}`,
			"The user(s) g0, g1, g2"},
		{"distinct clients", `{"actors":[],"users":[],"clients":` + nameList(n, func(i int) string { return fmt.Sprintf("g%d", i) }) + `,"groups":[]}`,
			"The client(s) g0, g1, g2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, st := newTestAPI(t)
			base := srv.URL + "/organizations/acme"
			do(t, "POST", base+"/nodes", `{"name":"web01"}`)

			before := st.Counts().Reads.Load()
			resp, body := do(t, "PUT", base+"/nodes/web01/_acl/read", tc.body)
			reads := st.Counts().Reads.Load() - before
			if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, tc.want) {
				t.Fatalf("PUT = %d, want 400 naming %q: %.200s", resp.StatusCode, tc.want, body)
			}
			if reads > 100 {
				t.Fatalf("PUT listing %d names made %d store reads", n, reads)
			}
		})
	}
}

// The bounded lookup still resolves what exists: a long list of distinct
// names that are all real is stored, typed, each once.
func TestACLPutResolvesLongListsOfRealNames(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	do(t, "POST", base+"/nodes", `{"name":"web01"}`)
	do(t, "POST", srv.URL+"/users", userBody(`{"name":"alice"}`))
	var clients, groups []string
	for i := range 80 {
		c, g := fmt.Sprintf("client%02d", i), fmt.Sprintf("group%02d", i)
		do(t, "POST", base+"/clients", `{"name":"`+c+`"}`)
		do(t, "POST", base+"/groups", `{"groupname":"`+g+`"}`)
		clients, groups = append(clients, c), append(groups, g)
	}
	actors := nameList(len(clients), func(i int) string { return clients[i] })
	actors = strings.Replace(actors, "[", `["alice",`, 1)
	grp := nameList(len(groups), func(i int) string { return groups[i] })
	if resp, body := do(t, "PUT", base+"/nodes/web01/_acl/read",
		`{"actors":`+actors+`,"groups":`+grp+`}`); resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT read = %d: %s", resp.StatusCode, body)
	}
	read := granularACLOf(t, base+"/nodes/web01/_acl")["read"]
	if !slices.Equal(read.Users, []string{"alice"}) || !slices.Equal(read.Clients, clients) || !slices.Equal(read.Groups, groups) {
		t.Fatalf("read = %+v", read)
	}
}
