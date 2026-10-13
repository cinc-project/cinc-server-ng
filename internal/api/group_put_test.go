package api

import (
	"encoding/json"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// groupPutFixture is a seeded org whose group "devs" holds members of every
// kind in both halves of its membership: anna, web01 and ops in the document,
// ben, web02 and qa as incremental rows.
func groupPutFixture(t *testing.T) (*httptest.Server, *store.Org) {
	t.Helper()
	st := store.New()
	org, err := st.CreateOrg("acme")
	if err != nil {
		t.Fatal(err)
	}
	if err := SeedOrg(org); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(st).Handler())
	t.Cleanup(srv.Close)
	base := srv.URL + "/organizations/acme"
	for _, u := range []string{"anna", "ben", "cara"} {
		do(t, "POST", srv.URL+"/users", userBody(`{"name":"`+u+`"}`))
	}
	for _, c := range []string{"web01", "web02", "web03"} {
		do(t, "POST", base+"/clients", `{"name":"`+c+`"}`)
	}
	for _, g := range []string{"devs", "ops", "qa", "sec"} {
		if resp, body := do(t, "POST", base+"/groups", `{"groupname":"`+g+`"}`); resp.StatusCode != 201 {
			t.Fatalf("create group %s = %d: %s", g, resp.StatusCode, body)
		}
	}
	if resp, body := do(t, "PUT", base+"/groups/devs",
		`{"groupname":"devs","actors":{"users":["anna"],"clients":["web01"],"groups":["ops"]}}`); resp.StatusCode != 200 {
		t.Fatalf("seed devs = %d: %s", resp.StatusCode, body)
	}
	for _, m := range [][2]string{{memberUsers, "ben"}, {memberClients, "web02"}, {memberGroups, "qa"}} {
		if err := addMember(org, "devs", m[0], m[1]); err != nil {
			t.Fatal(err)
		}
	}
	return srv, org
}

type groupView struct {
	Users, Clients, Groups, Actors []string
}

func getGroupView(t *testing.T, srv *httptest.Server, name string) groupView {
	t.Helper()
	resp, body := do(t, "GET", srv.URL+"/organizations/acme/groups/"+name, "")
	if resp.StatusCode != 200 {
		t.Fatalf("GET group %s = %d: %s", name, resp.StatusCode, body)
	}
	var g groupView
	if err := json.Unmarshal([]byte(body), &g); err != nil {
		t.Fatalf("group doc invalid: %v\n%s", err, body)
	}
	slices.Sort(g.Users)
	slices.Sort(g.Clients)
	slices.Sort(g.Groups)
	return g
}

// TestGroupPutKeepsOmittedKinds pins erchef's oc_chef_group:update_from_ejson,
// which reads each of actors.users, actors.clients and actors.groups with the
// group's current members as the default: a kind the body leaves out keeps its
// members, a kind it names (even as []) is replaced. "Current members" is the
// effective membership, rows included, and a replaced kind loses both halves.
func TestGroupPutKeepsOmittedKinds(t *testing.T) {
	all := groupView{
		Users:   []string{"anna", "ben"},
		Clients: []string{"web01", "web02"},
		Groups:  []string{"ops", "qa"},
	}
	cases := []struct {
		name string
		body string
		want groupView
	}{
		{"users only", `{"groupname":"devs","actors":{"users":["cara"]}}`,
			groupView{Users: []string{"cara"}, Clients: all.Clients, Groups: all.Groups}},
		{"clients only", `{"actors":{"clients":["web03"]}}`,
			groupView{Users: all.Users, Clients: []string{"web03"}, Groups: all.Groups}},
		{"groups only", `{"actors":{"groups":["sec"]}}`,
			groupView{Users: all.Users, Clients: all.Clients, Groups: []string{"sec"}}},
		{"explicit empty users", `{"actors":{"users":[]}}`,
			groupView{Users: []string{}, Clients: all.Clients, Groups: all.Groups}},
		{"actors absent", `{"groupname":"devs"}`, all},
		{"actors empty object", `{"actors":{}}`, all},
		{"actors null", `{"actors":null}`, all},
		// ej:get of a key path through an array finds nothing, so erchef
		// keeps every kind for the flat form GET returns.
		{"flat actors array", `{"actors":["anna","web01"]}`, all},
		{"flat empty actors array", `{"actors":[]}`, all},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv, _ := groupPutFixture(t)
			// Baseline: the fixture holds every member in both halves.
			if got := getGroupView(t, srv, "devs"); !sameMembers(got, all) {
				t.Fatalf("fixture members = %+v, want %+v", got, all)
			}
			if resp, body := do(t, "PUT", srv.URL+"/organizations/acme/groups/devs", c.body); resp.StatusCode != 200 {
				t.Fatalf("PUT = %d: %s", resp.StatusCode, body)
			}
			if got := getGroupView(t, srv, "devs"); !sameMembers(got, c.want) {
				t.Fatalf("members after PUT %s = %+v, want %+v", c.body, got, c.want)
			}
		})
	}
}

// TestGroupPutReplacesBothHalves pins that a replaced kind loses its rows as
// well as its document entries: a removed row member is not left behind to be
// folded back in.
func TestGroupPutReplacesBothHalves(t *testing.T) {
	srv, org := groupPutFixture(t)
	if resp, body := do(t, "PUT", srv.URL+"/organizations/acme/groups/devs",
		`{"actors":{"clients":[]}}`); resp.StatusCode != 200 {
		t.Fatalf("PUT = %d: %s", resp.StatusCode, body)
	}
	_, clients, _, err := groupMembership(org, "devs")
	if err != nil {
		t.Fatal(err)
	}
	if len(clients) != 0 {
		t.Fatalf("clients after replacing with [] = %v, want none (document or rows)", clients)
	}
	// A later incremental add must not resurrect web02.
	if err := addMember(org, "devs", memberClients, "web03"); err != nil {
		t.Fatal(err)
	}
	if got := getGroupView(t, srv, "devs"); !slices.Equal(got.Clients, []string{"web03"}) {
		t.Fatalf("clients = %v, want [web03]", got.Clients)
	}
}

// TestGroupPutTopLevelKinds keeps the GET-shaped body (top-level users,
// clients, groups beside a flat actors array) working: cinc-console saves a
// group that way. erchef ignores those members, so this is a deliberate
// leniency; it still follows erchef's rule that an omitted kind is kept.
func TestGroupPutTopLevelKinds(t *testing.T) {
	srv, _ := groupPutFixture(t)
	if resp, body := do(t, "PUT", srv.URL+"/organizations/acme/groups/devs",
		`{"name":"devs","actors":["anna","web01"],"users":["cara"]}`); resp.StatusCode != 200 {
		t.Fatalf("PUT = %d: %s", resp.StatusCode, body)
	}
	want := groupView{Users: []string{"cara"}, Clients: []string{"web01", "web02"}, Groups: []string{"ops", "qa"}}
	if got := getGroupView(t, srv, "devs"); !sameMembers(got, want) {
		t.Fatalf("members = %+v, want %+v", got, want)
	}
}

// TestGroupPutEchoesBody pins erchef's update_from_json, which answers a PUT
// with the request body as it was sent (re-encoded by jiffy), not the stored
// group: the nested actors shape, unknown names included.
func TestGroupPutEchoesBody(t *testing.T) {
	srv, _ := groupPutFixture(t)
	body := `{"groupname":"devs","actors":{"users":["anna","ghost"],"clients":[]}}`
	resp, got := do(t, "PUT", srv.URL+"/organizations/acme/groups/devs", body)
	if resp.StatusCode != 200 {
		t.Fatalf("PUT = %d: %s", resp.StatusCode, got)
	}
	if got != body {
		t.Fatalf("PUT response = %s, want the request body echoed: %s", got, body)
	}
}

// TestGroupGetShape pins oc_chef_group:assemble_group_ejson: "actors" is the
// clients followed by the users (nested groups are not actors), and members
// come in erchef's order.
func TestGroupGetShape(t *testing.T) {
	srv, _ := groupPutFixture(t)
	if resp, body := do(t, "PUT", srv.URL+"/organizations/acme/groups/devs",
		`{"actors":{"users":["anna"],"clients":["web01"],"groups":["ops"]}}`); resp.StatusCode != 200 {
		t.Fatalf("PUT = %d: %s", resp.StatusCode, body)
	}
	_, body := do(t, "GET", srv.URL+"/organizations/acme/groups/devs", "")
	want := `{"actors":["web01","anna"],"users":["anna"],"clients":["web01"],"groups":["ops"],` +
		`"orgname":"acme","name":"devs","groupname":"devs"}`
	if body != want {
		t.Fatalf("GET group = %s\nwant          %s", body, want)
	}
}

// TestGroupPutDropsVanishedKeptMembers pins that erchef resolves the kinds a
// PUT keeps as well as those it replaces: a kept member whose actor no longer
// exists is dropped rather than written back into the document.
func TestGroupPutDropsVanishedKeptMembers(t *testing.T) {
	srv, org := groupPutFixture(t)
	if err := addMember(org, "devs", memberClients, "ghost-client"); err != nil {
		t.Fatal(err)
	}
	// Baseline: the stale row shows up as a member.
	if got := getGroupView(t, srv, "devs"); !slices.Contains(got.Clients, "ghost-client") {
		t.Fatalf("baseline clients = %v, want ghost-client present", got.Clients)
	}
	if resp, body := do(t, "PUT", srv.URL+"/organizations/acme/groups/devs",
		`{"actors":{"users":["anna"]}}`); resp.StatusCode != 200 {
		t.Fatalf("PUT = %d: %s", resp.StatusCode, body)
	}
	if got := getGroupView(t, srv, "devs"); !slices.Equal(got.Clients, []string{"web01", "web02"}) {
		t.Fatalf("clients = %v, want [web01 web02] without the vanished ghost-client", got.Clients)
	}
}

func sameMembers(a, b groupView) bool {
	return slices.Equal(a.Users, b.Users) && slices.Equal(a.Clients, b.Clients) && slices.Equal(a.Groups, b.Groups)
}
