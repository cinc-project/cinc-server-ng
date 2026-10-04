//go:build conformance

package conformance

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// knife acl and knife group are how an operator manages authorization, so each
// test here proves a change has its real effect: an identity is refused, the
// command under test changes an ACL or a group, and the same identity's next
// knife call is allowed (or the reverse). Checking only that the ACL document
// changed would pass against a server that stores ACLs and enforces none.

// authzMember creates a global user through knife as the superuser, associates
// it with the org (as a plain member, or an admin), and returns a config for it.
func authzMember(t *testing.T, h *harness, name string, admin bool) string {
	t.Helper()
	pem := filepath.Join(h.dir, name+".pem")
	h.runAs(t, h.superRB, "user", "create", name, "--email", name+"@example.com",
		"--password", "correct-horse-battery", "--first-name", name, "--last-name", "Member",
		"--file", pem)
	args := []string{"org", "user", "add", orgName, name}
	if admin {
		args = append(args, "--admin")
	}
	h.runAs(t, h.superRB, args...)
	return h.writeConfig(t, name+".rb", name, pem)
}

// authzClient registers a non-admin client and returns a config for it.
func authzClient(t *testing.T, h *harness, name string) string {
	t.Helper()
	return h.writeConfig(t, name+".rb", name, h.createClient(t, name))
}

// authzAllowed fails unless knife, run under cfg, succeeds.
func authzAllowed(t *testing.T, h *harness, who, cfg string, args ...string) {
	t.Helper()
	if out, err := h.tryAs(cfg, args...); err != nil {
		t.Fatalf("%s should be allowed to knife %s: %v\n%s", who, strings.Join(args, " "), err, out)
	}
}

// authzDenied fails unless knife, run under cfg, is refused for authorization.
func authzDenied(t *testing.T, h *harness, who, cfg string, args ...string) {
	t.Helper()
	out, err := h.tryAs(cfg, args...)
	if err == nil {
		t.Fatalf("%s should be refused knife %s, but it succeeded:\n%s", who, strings.Join(args, " "), out)
	}
	if !deniedForAuthorization(out) {
		t.Fatalf("%s: knife %s failed, but not as an authorization refusal:\n%s", who, strings.Join(args, " "), out)
	}
}

// authzACE returns one permission's ACE from knife acl show, as alice.
func authzACE(t *testing.T, h *harness, typ, name, perm string) (actors, groups []string) {
	t.Helper()
	return authzACEOf(t, h.showJSON(t, "acl", "show", typ, name), perm)
}

// authzACEOf splits one permission's ACE of a decoded ACL into actors and groups.
func authzACEOf(t *testing.T, acl map[string]any, perm string) (actors, groups []string) {
	t.Helper()
	ace, ok := field(t, acl, perm).(map[string]any)
	if !ok {
		t.Fatalf("ACL: %s is not an object: %v", perm, acl[perm])
	}
	strs := func(v any) []string {
		var out []string
		for _, e := range asSlice(v) {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	// knife drops "actors" when the server splits it into users and clients.
	actors = append(strs(ace["actors"]), append(strs(ace["users"]), strs(ace["clients"])...)...)
	return actors, strs(ace["groups"])
}

func asSlice(v any) []any {
	s, _ := v.([]any)
	return s
}

// authzNode creates a node as alice.
func authzNode(t *testing.T, h *harness, name string) {
	t.Helper()
	path := filepath.Join(h.dir, name+".json")
	write(t, path, `{"name":"`+name+`","chef_environment":"_default","json_class":"Chef::Node","chef_type":"node"}`)
	h.run(t, "node", "from", "file", path)
}

// knife acl show must report the five-permission ACL for every object type it
// accepts, and only to someone holding grant on the object.
func TestKnifeACLShow(t *testing.T) {
	t.Parallel()
	h := setup(t)

	authzNode(t, h, "web01")
	write(t, filepath.Join(h.dir, "web.json"),
		`{"name":"web","json_class":"Chef::Role","chef_type":"role","run_list":[]}`)
	h.run(t, "role", "from", "file", filepath.Join(h.dir, "web.json"))
	write(t, filepath.Join(h.dir, "staging.json"),
		`{"name":"staging","json_class":"Chef::Environment","chef_type":"environment"}`)
	h.run(t, "environment", "from", "file", filepath.Join(h.dir, "staging.json"))
	clientCfg := authzClient(t, h, "reader")
	h.run(t, "group", "create", "ops")
	h.run(t, "data", "bag", "create", "secrets")
	h.run(t, "cookbook", "upload", "mycook")
	write(t, filepath.Join(h.dir, "base.json"), `{"name":"base","revision_id":"`+
		strings.Repeat("b", 40)+`","run_list":["recipe[mycook::default]"],"cookbook_locks":{}}`)
	h.run(t, "raw", "-m", "PUT", "/policy_groups/prod/policies/base", "-i", filepath.Join(h.dir, "base.json"))
	ident := strings.Repeat("c", 40)
	write(t, filepath.Join(h.dir, "artifact.json"), `{"name":"mycook","cookbook_name":"mycook","version":"0.1.0",`+
		`"identifier":"`+ident+`","metadata":{"name":"mycook","version":"0.1.0"},"all_files":[]}`)
	h.run(t, "raw", "-m", "PUT", "/cookbook_artifacts/mycook/"+ident, "-i", filepath.Join(h.dir, "artifact.json"))

	for _, obj := range [][2]string{
		{"nodes", "web01"}, {"roles", "web"}, {"environments", "staging"},
		{"clients", "reader"}, {"groups", "ops"}, {"containers", "nodes"},
		{"data", "secrets"}, {"cookbooks", "mycook"}, {"policies", "base"},
		{"policy_groups", "prod"}, {"cookbook_artifacts", "mycook"},
	} {
		acl := h.showJSON(t, "acl", "show", obj[0], obj[1])
		for _, perm := range []string{"create", "read", "update", "delete", "grant"} {
			if _, groups := authzACEOf(t, acl, perm); !slices.Contains(groups, "admins") {
				t.Errorf("acl show %s %s: %s groups = %v, want admins among them", obj[0], obj[1], perm, groups)
			}
		}
	}

	// Reading an ACL takes grant on the object, which a client does not have:
	// it may read the node, but not see who else may.
	authzAllowed(t, h, "client reader", clientCfg, "node", "show", "web01")
	authzDenied(t, h, "client reader", clientCfg, "acl", "show", "nodes", "web01")

	// The ACL of an object that does not exist is a 404, not a default.
	if out, err := h.tryAs(h.knifeRB, "acl", "show", "nodes", "nosuch"); err == nil {
		t.Errorf("acl show of a missing node succeeded:\n%s", out)
	}
}

// knife acl add and remove change who may do what: adding a client to an ACE
// lets it act, removing it refuses it again, and the group grants every client
// inherits can be withdrawn the same way.
func TestKnifeACLAddRemove(t *testing.T) {
	t.Parallel()
	h := setup(t)

	authzNode(t, h, "web01")
	cfg := authzClient(t, h, "agent")
	show := []string{"node", "show", "web01"}
	write(t, filepath.Join(h.dir, "web01-update.json"),
		`{"name":"web01","chef_environment":"_default","json_class":"Chef::Node","chef_type":"node","normal":{"tier":"web"}}`)
	update := []string{"node", "from", "file", filepath.Join(h.dir, "web01-update.json")}

	// Baseline: the clients group grants read on a node, not update.
	authzAllowed(t, h, "client agent", cfg, show...)
	authzDenied(t, h, "client agent", cfg, update...)

	// Withdrawing read from the clients group refuses the client.
	h.run(t, "acl", "remove", "group", "clients", "nodes", "web01", "read")
	if _, groups := authzACE(t, h, "nodes", "web01", "read"); slices.Contains(groups, "clients") {
		t.Fatalf("read ACE still lists the clients group: %v", groups)
	}
	authzDenied(t, h, "client agent", cfg, show...)

	// Granting the client itself read and update lets it do both.
	h.run(t, "acl", "add", "client", "agent", "nodes", "web01", "read,update")
	if actors, _ := authzACE(t, h, "nodes", "web01", "update"); !slices.Contains(actors, "agent") {
		t.Fatalf("update ACE does not list agent: %v", actors)
	}
	authzAllowed(t, h, "client agent", cfg, show...)
	authzAllowed(t, h, "client agent", cfg, update...)
	if got := field(t, h.showJSON(t, "node", "show", "web01", "--long"), "normal", "tier"); got != "web" {
		t.Errorf("the client's update did not land: normal.tier = %v", got)
	}

	// Removing update alone leaves read in place.
	h.run(t, "acl", "remove", "client", "agent", "nodes", "web01", "update")
	authzDenied(t, h, "client agent", cfg, update...)
	authzAllowed(t, h, "client agent", cfg, show...)

	// And removing read refuses it again.
	h.run(t, "acl", "remove", "client", "agent", "nodes", "web01", "read")
	authzDenied(t, h, "client agent", cfg, show...)

	// Restoring the group grant restores the client's access through it.
	h.run(t, "acl", "add", "group", "clients", "nodes", "web01", "read")
	authzAllowed(t, h, "client agent", cfg, show...)

	// Delete and grant, on a data bag: neither held, then each granted.
	h.run(t, "data", "bag", "create", "scratch")
	authzDenied(t, h, "client agent", cfg, "acl", "show", "data", "scratch")
	h.run(t, "acl", "add", "client", "agent", "data", "scratch", "grant")
	authzAllowed(t, h, "client agent", cfg, "acl", "show", "data", "scratch")
	authzDenied(t, h, "client agent", cfg, "data", "bag", "delete", "scratch", "--yes")
	h.run(t, "acl", "add", "client", "agent", "data", "scratch", "delete")
	authzAllowed(t, h, "client agent", cfg, "data", "bag", "delete", "scratch", "--yes")

	// Changing an ACL takes grant, which an ordinary member does not hold:
	// otherwise any member could hand itself anything.
	bob := authzMember(t, h, "bob", false)
	authzDenied(t, h, "member bob", bob, "acl", "add", "group", "users", "nodes", "web01", "grant")
	authzDenied(t, h, "member bob", bob, "acl", "remove", "group", "clients", "nodes", "web01", "read")
	authzAllowed(t, h, "client agent", cfg, show...)
}

// knife acl bulk add and remove change the ACL of every object whose name
// matches the expression, and of no other.
func TestKnifeACLBulk(t *testing.T) {
	t.Parallel()
	h := setup(t)

	for _, n := range []string{"app01", "app02", "db01"} {
		authzNode(t, h, n)
	}
	cfg := authzClient(t, h, "agent")
	for _, n := range []string{"app01", "app02", "db01"} {
		authzAllowed(t, h, "client agent", cfg, "node", "show", n)
	}

	h.run(t, "acl", "bulk", "remove", "group", "clients", "nodes", "^app", "read", "--yes")
	authzDenied(t, h, "client agent", cfg, "node", "show", "app01")
	authzDenied(t, h, "client agent", cfg, "node", "show", "app02")
	authzAllowed(t, h, "client agent", cfg, "node", "show", "db01")
	if _, groups := authzACE(t, h, "nodes", "db01", "read"); !slices.Contains(groups, "clients") {
		t.Errorf("bulk remove changed db01, which does not match: read groups = %v", groups)
	}

	h.run(t, "acl", "bulk", "add", "client", "agent", "nodes", "^app0[12]$", "read", "--yes")
	authzAllowed(t, h, "client agent", cfg, "node", "show", "app01")
	authzAllowed(t, h, "client agent", cfg, "node", "show", "app02")
	if actors, _ := authzACE(t, h, "nodes", "db01", "read"); slices.Contains(actors, "agent") {
		t.Errorf("bulk add changed db01, which does not match: read actors = %v", actors)
	}

	// A bulk change to a group's grants, and its undo.
	h.run(t, "acl", "bulk", "remove", "group", "clients", "nodes", "^db", "read", "--yes")
	authzDenied(t, h, "client agent", cfg, "node", "show", "db01")
	h.run(t, "acl", "bulk", "add", "group", "clients", "nodes", "^db", "read", "--yes")
	authzAllowed(t, h, "client agent", cfg, "node", "show", "db01")

	h.run(t, "acl", "bulk", "remove", "client", "agent", "nodes", "^app", "read", "--yes")
	authzDenied(t, h, "client agent", cfg, "node", "show", "app01")
	authzDenied(t, h, "client agent", cfg, "node", "show", "app02")
	authzAllowed(t, h, "client agent", cfg, "node", "show", "db01")
}

// authzLockBag creates a data bag that neither the users nor the clients group
// may read, so access to it has to come from somewhere else.
func authzLockBag(t *testing.T, h *harness, bag string) {
	t.Helper()
	h.run(t, "data", "bag", "create", bag)
	h.run(t, "acl", "remove", "group", "users", "data", bag, "read")
	h.run(t, "acl", "remove", "group", "clients", "data", bag, "read")
}

// knife group manages membership, and membership is permission: a client and a
// user in a group, and a group nested in a group, each gain what the outer
// group is granted, and lose it when removed.
func TestKnifeGroupsMembership(t *testing.T) {
	t.Parallel()
	h := setup(t)

	bob := authzMember(t, h, "bob", false)
	agent := authzClient(t, h, "agent")
	authzLockBag(t, h, "vault")
	read := []string{"data", "bag", "show", "vault"}

	// Baseline: neither can read the bag.
	authzDenied(t, h, "member bob", bob, read...)
	authzDenied(t, h, "client agent", agent, read...)

	h.run(t, "group", "create", "inner")
	h.run(t, "group", "create", "outer")
	list := h.run(t, "group", "list")
	for _, g := range []string{"inner", "outer", "admins", "clients", "users"} {
		if !slices.Contains(strings.Fields(list), g) {
			t.Errorf("group list lacks %s:\n%s", g, list)
		}
	}

	h.run(t, "group", "add", "user", "bob", "inner")
	h.run(t, "group", "add", "client", "agent", "inner")
	h.run(t, "group", "add", "group", "inner", "outer")
	inner := h.showJSON(t, "group", "show", "inner")
	if users := asSlice(field(t, inner, "users")); !slices.Contains(users, any("bob")) {
		t.Errorf("group show inner: users = %v, want bob", users)
	}
	if clients := asSlice(field(t, inner, "clients")); !slices.Contains(clients, any("agent")) {
		t.Errorf("group show inner: clients = %v, want agent", clients)
	}
	if groups := asSlice(field(t, h.showJSON(t, "group", "show", "outer"), "groups")); !slices.Contains(groups, any("inner")) {
		t.Errorf("group show outer: groups = %v, want inner", groups)
	}

	// Membership alone grants nothing until a group is in an ACL.
	authzDenied(t, h, "member bob", bob, read...)

	// outer is granted read; inner's members get it through the nesting.
	h.run(t, "acl", "add", "group", "outer", "data", "vault", "read")
	authzAllowed(t, h, "member bob", bob, read...)
	authzAllowed(t, h, "client agent", agent, read...)

	// Cutting the nesting revokes both.
	h.run(t, "group", "remove", "group", "inner", "outer")
	authzDenied(t, h, "member bob", bob, read...)
	authzDenied(t, h, "client agent", agent, read...)

	// Restore it, then remove the members one at a time.
	h.run(t, "group", "add", "group", "inner", "outer")
	authzAllowed(t, h, "client agent", agent, read...)
	h.run(t, "group", "remove", "client", "agent", "inner")
	authzDenied(t, h, "client agent", agent, read...)
	authzAllowed(t, h, "member bob", bob, read...)
	h.run(t, "group", "remove", "user", "bob", "inner")
	authzDenied(t, h, "member bob", bob, read...)
	inner = h.showJSON(t, "group", "show", "inner")
	if len(asSlice(field(t, inner, "users")))+len(asSlice(field(t, inner, "clients"))) != 0 {
		t.Errorf("group show inner after removals still has members: %v", inner)
	}
}

// Removing a client from the org's clients group must revoke what that group
// grants, even though registration put the client there incrementally rather
// than by rewriting the group: membership is the union of both, and revocation
// has to clear both.
func TestKnifeGroupsRemoveFromClientsGroup(t *testing.T) {
	t.Parallel()
	h := setup(t)

	authzNode(t, h, "web01")
	agent := authzClient(t, h, "agent")
	authzAllowed(t, h, "client agent", agent, "node", "show", "web01")

	clients := asSlice(field(t, h.showJSON(t, "group", "show", "clients"), "clients"))
	if !slices.Contains(clients, any("agent")) {
		t.Fatalf("a registered client is not in the clients group: %v", clients)
	}

	h.run(t, "group", "remove", "client", "agent", "clients")
	authzDenied(t, h, "client agent", agent, "node", "show", "web01")

	h.run(t, "group", "add", "client", "agent", "clients")
	authzAllowed(t, h, "client agent", agent, "node", "show", "web01")
}

// knife group destroy removes a group, and with it every grant it carried.
func TestKnifeGroupsDestroy(t *testing.T) {
	t.Parallel()
	h := setup(t)

	agent := authzClient(t, h, "agent")
	authzLockBag(t, h, "vault")
	read := []string{"data", "bag", "show", "vault"}

	h.run(t, "group", "create", "readers")
	h.run(t, "group", "add", "client", "agent", "readers")
	h.run(t, "acl", "add", "group", "readers", "data", "vault", "read")
	authzAllowed(t, h, "client agent", agent, read...)

	h.run(t, "group", "destroy", "readers")
	authzDenied(t, h, "client agent", agent, read...)
	if out := h.run(t, "group", "list"); slices.Contains(strings.Fields(out), "readers") {
		t.Errorf("group list still has the destroyed group:\n%s", out)
	}
	if out, err := h.tryAs(h.knifeRB, "group", "show", "readers"); err == nil {
		t.Errorf("group show of a destroyed group succeeded:\n%s", out)
	}

	// The grant went with the group: one created later under the same name is
	// a different group, as in Chef, where an ACL names a group's authz id.
	if _, groups := authzACE(t, h, "data", "vault", "read"); slices.Contains(groups, "readers") {
		t.Errorf("vault's read ACE still names the destroyed group: %v", groups)
	}
	other := authzClient(t, h, "other")
	h.run(t, "group", "create", "readers")
	h.run(t, "group", "add", "client", "other", "readers")
	authzDenied(t, h, "client other", other, read...)
}

// Managing groups is an admin's job. An ordinary member may not create one,
// nor add itself to one an admin made, which would otherwise hand it whatever
// that group is granted.
func TestKnifeGroupsMemberCannotManage(t *testing.T) {
	t.Parallel()
	h := setup(t)

	bob := authzMember(t, h, "bob", false)
	authzLockBag(t, h, "vault")
	h.run(t, "group", "create", "readers")
	h.run(t, "acl", "add", "group", "readers", "data", "vault", "read")
	authzDenied(t, h, "member bob", bob, "data", "bag", "show", "vault")

	// A member may read groups, as Chef's users group may.
	authzAllowed(t, h, "member bob", bob, "group", "show", "readers")
	authzAllowed(t, h, "member bob", bob, "group", "list")

	authzDenied(t, h, "member bob", bob, "group", "add", "user", "bob", "readers")
	authzDenied(t, h, "member bob", bob, "data", "bag", "show", "vault")
	authzDenied(t, h, "member bob", bob, "group", "create", "bobs")
	authzDenied(t, h, "member bob", bob, "group", "destroy", "readers")
	authzDenied(t, h, "member bob", bob, "group", "add", "user", "bob", "admins")
}
