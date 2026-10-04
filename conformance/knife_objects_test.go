//go:build conformance

package conformance

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The tests in this file cover the knife commands that manage nodes, roles,
// environments and tags, and the commands built on searching them. Each one
// reads the object back after the command ran, so what is asserted is the
// effect on the server, not merely that knife exited zero.

// objectsNode uploads a node document through `knife node from file`.
func objectsNode(t *testing.T, h *harness, name, doc string) {
	t.Helper()
	path := filepath.Join(h.dir, "node-"+name+".json")
	write(t, path, doc)
	h.run(t, "node", "from", "file", path)
}

// objectsStrings converts a decoded JSON array to strings, failing if the
// value is not an array of strings.
func objectsStrings(t *testing.T, v any) []string {
	t.Helper()
	arr, ok := v.([]any)
	if !ok {
		t.Fatalf("not an array: %#v", v)
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		s, ok := e.(string)
		if !ok {
			t.Fatalf("array element is not a string: %#v", e)
		}
		out = append(out, s)
	}
	return out
}

func objectsWantList(t *testing.T, what string, got any, want ...string) {
	t.Helper()
	if want == nil {
		want = []string{}
	}
	if g := objectsStrings(t, got); !reflect.DeepEqual(g, want) {
		t.Errorf("%s = %q, want %q", what, g, want)
	}
}

// objectsLines splits command output into trimmed, non-empty lines.
func objectsLines(out string) []string {
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

func TestKnifeNodesCreateEditDelete(t *testing.T) {
	t.Parallel()
	h := setup(t)

	h.run(t, "node", "create", "web01", "--disable-editing")
	node := h.raw(t, "/nodes/web01")
	if got := field(t, node, "name"); got != "web01" {
		t.Errorf("created node name = %v, want web01", got)
	}
	if got := field(t, node, "chef_environment"); got != "_default" {
		t.Errorf("created node chef_environment = %v, want _default", got)
	}

	h.edit(t, `doc["normal"]["tier"] = "frontend"; doc["run_list"] = ["recipe[mycook]"]`,
		"node", "edit", "web01")
	node = h.raw(t, "/nodes/web01")
	if got := field(t, node, "normal", "tier"); got != "frontend" {
		t.Errorf("edited normal.tier = %v, want frontend", got)
	}
	objectsWantList(t, "edited run_list", field(t, node, "run_list"), "recipe[mycook]")

	h.run(t, "node", "delete", "web01", "--yes")
	if _, ok := h.raw(t, "/nodes")["web01"]; ok {
		t.Errorf("web01 still listed after node delete")
	}
	if out, err := h.tryAs(h.knifeRB, "raw", "/nodes/web01"); err == nil || !strings.Contains(out, "404") {
		t.Errorf("deleted node is still readable (err=%v):\n%s", err, out)
	}
}

func TestKnifeNodesEnvironmentAndRunList(t *testing.T) {
	t.Parallel()
	h := setup(t)

	h.run(t, "environment", "create", "staging", "--disable-editing")
	objectsNode(t, h, "web01", `{"name":"web01","chef_environment":"_default","json_class":"Chef::Node",`+
		`"chef_type":"node","run_list":["recipe[base]"]}`)

	h.run(t, "node", "environment", "set", "web01", "staging")
	if got := field(t, h.raw(t, "/nodes/web01"), "chef_environment"); got != "staging" {
		t.Errorf("chef_environment = %v, want staging", got)
	}

	h.run(t, "node", "run_list", "add", "web01", "recipe[app],role[web]")
	objectsWantList(t, "run_list after add", field(t, h.raw(t, "/nodes/web01"), "run_list"),
		"recipe[base]", "recipe[app]", "role[web]")

	h.run(t, "node", "run_list", "add", "web01", "recipe[first]", "--before", "recipe[base]")
	objectsWantList(t, "run_list after add --before", field(t, h.raw(t, "/nodes/web01"), "run_list"),
		"recipe[first]", "recipe[base]", "recipe[app]", "role[web]")

	h.run(t, "node", "run_list", "remove", "web01", "recipe[app]")
	objectsWantList(t, "run_list after remove", field(t, h.raw(t, "/nodes/web01"), "run_list"),
		"recipe[first]", "recipe[base]", "role[web]")

	h.run(t, "node", "run_list", "set", "web01", "recipe[only],role[db]")
	objectsWantList(t, "run_list after set", field(t, h.raw(t, "/nodes/web01"), "run_list"),
		"recipe[only]", "role[db]")
}

func TestKnifeNodesBulkDelete(t *testing.T) {
	t.Parallel()
	h := setup(t)

	for _, n := range []string{"web01", "web02", "db01"} {
		objectsNode(t, h, n, `{"name":"`+n+`","chef_environment":"_default","json_class":"Chef::Node","chef_type":"node"}`)
	}
	h.run(t, "node", "bulk", "delete", "^web", "--yes")

	nodes := h.raw(t, "/nodes")
	for _, gone := range []string{"web01", "web02"} {
		if _, ok := nodes[gone]; ok {
			t.Errorf("%s survived a bulk delete matching it: %v", gone, nodes)
		}
	}
	if _, ok := nodes["db01"]; !ok {
		t.Errorf("db01 was deleted although it does not match ^web: %v", nodes)
	}
}

func TestKnifeRolesLifecycle(t *testing.T) {
	t.Parallel()
	h := setup(t)

	h.run(t, "role", "create", "web", "--description", "web servers", "--disable-editing")
	role := h.showJSON(t, "role", "show", "web")
	if got := field(t, role, "name"); got != "web" {
		t.Errorf("role name = %v, want web", got)
	}
	if got := field(t, role, "description"); got != "web servers" {
		t.Errorf("role description = %v, want %q", got, "web servers")
	}
	if got := field(t, role, "chef_type"); got != "role" {
		t.Errorf("role chef_type = %v, want role", got)
	}

	h.edit(t, `doc["description"] = "edited"; doc["default_attributes"] = {"port" => 8080}`,
		"role", "edit", "web")
	role = h.raw(t, "/roles/web")
	if got := field(t, role, "description"); got != "edited" {
		t.Errorf("edited description = %v, want edited", got)
	}
	if got := field(t, role, "default_attributes", "port"); got != float64(8080) {
		t.Errorf("edited default_attributes.port = %v, want 8080", got)
	}

	path := filepath.Join(h.dir, "db.json")
	write(t, path, `{"name":"db","description":"databases","json_class":"Chef::Role","chef_type":"role",`+
		`"default_attributes":{},"override_attributes":{"engine":"pg"},"run_list":["recipe[pg]"],"env_run_lists":{}}`)
	h.run(t, "role", "from", "file", path)
	db := h.raw(t, "/roles/db")
	if got := field(t, db, "override_attributes", "engine"); got != "pg" {
		t.Errorf("role from file override_attributes.engine = %v, want pg", got)
	}
	objectsWantList(t, "role from file run_list", field(t, db, "run_list"), "recipe[pg]")

	out := h.run(t, "role", "list")
	if got := objectsLines(out); !reflect.DeepEqual(got, []string{"db", "web"}) {
		t.Errorf("role list = %q, want [db web]", got)
	}

	h.run(t, "role", "delete", "web", "--yes")
	roles := h.raw(t, "/roles")
	if _, ok := roles["web"]; ok {
		t.Errorf("web still listed after role delete: %v", roles)
	}
	if _, ok := roles["db"]; !ok {
		t.Errorf("role delete web also removed db: %v", roles)
	}
}

func TestKnifeRolesRunLists(t *testing.T) {
	t.Parallel()
	h := setup(t)

	h.run(t, "role", "create", "web", "--disable-editing")
	runList := func() any { return field(t, h.raw(t, "/roles/web"), "run_list") }

	h.run(t, "role", "run_list", "add", "web", "recipe[a],recipe[b]")
	objectsWantList(t, "run_list after add", runList(), "recipe[a]", "recipe[b]")

	h.run(t, "role", "run_list", "replace", "web", "recipe[a]", "recipe[z]")
	objectsWantList(t, "run_list after replace", runList(), "recipe[z]", "recipe[b]")

	h.run(t, "role", "run_list", "remove", "web", "recipe[b]")
	objectsWantList(t, "run_list after remove", runList(), "recipe[z]")

	h.run(t, "role", "run_list", "set", "web", "role[base]", "recipe[c]")
	objectsWantList(t, "run_list after set", runList(), "role[base]", "recipe[c]")

	h.run(t, "role", "run_list", "clear", "web")
	objectsWantList(t, "run_list after clear", runList())
}

func TestKnifeRolesEnvRunLists(t *testing.T) {
	t.Parallel()
	h := setup(t)

	h.run(t, "environment", "create", "prod", "--disable-editing")
	h.run(t, "role", "create", "web", "--disable-editing")
	envRunList := func() any {
		return field(t, h.raw(t, "/roles/web"), "env_run_lists", "prod")
	}

	h.run(t, "role", "env_run_list", "add", "web", "prod", "recipe[a],recipe[b]")
	objectsWantList(t, "env run_list after add", envRunList(), "recipe[a]", "recipe[b]")
	// The environment-specific list is served by its own endpoint as well.
	if out := h.run(t, "raw", "/roles/web/environments/prod"); !strings.Contains(out, "recipe[b]") {
		t.Errorf("/roles/web/environments/prod does not carry the env run list:\n%s", out)
	}

	h.run(t, "role", "env_run_list", "replace", "web", "prod", "recipe[a]", "recipe[z]")
	objectsWantList(t, "env run_list after replace", envRunList(), "recipe[z]", "recipe[b]")

	h.run(t, "role", "env_run_list", "remove", "web", "prod", "recipe[b]")
	objectsWantList(t, "env run_list after remove", envRunList(), "recipe[z]")

	h.run(t, "role", "env_run_list", "set", "web", "prod", "role[base]", "recipe[c]")
	objectsWantList(t, "env run_list after set", envRunList(), "role[base]", "recipe[c]")

	h.run(t, "role", "env_run_list", "clear", "web", "prod")
	objectsWantList(t, "env run_list after clear", envRunList())

	// The role's main run list is untouched by any of it.
	objectsWantList(t, "role run_list", field(t, h.raw(t, "/roles/web"), "run_list"))
}

func TestKnifeRolesBulkDelete(t *testing.T) {
	t.Parallel()
	h := setup(t)

	for _, r := range []string{"web-a", "web-b", "db"} {
		h.run(t, "role", "create", r, "--disable-editing")
	}
	h.run(t, "role", "bulk", "delete", "^web-", "--yes")

	roles := h.raw(t, "/roles")
	for _, gone := range []string{"web-a", "web-b"} {
		if _, ok := roles[gone]; ok {
			t.Errorf("%s survived a bulk delete matching it: %v", gone, roles)
		}
	}
	if _, ok := roles["db"]; !ok {
		t.Errorf("db was deleted although it does not match ^web-: %v", roles)
	}
}

func TestKnifeEnvironmentsLifecycle(t *testing.T) {
	t.Parallel()
	h := setup(t)

	h.run(t, "environment", "create", "staging", "--description", "pre-production", "--disable-editing")
	env := h.raw(t, "/environments/staging")
	if got := field(t, env, "description"); got != "pre-production" {
		t.Errorf("environment description = %v, want pre-production", got)
	}
	if got := field(t, env, "chef_type"); got != "environment" {
		t.Errorf("environment chef_type = %v, want environment", got)
	}

	h.edit(t, `doc["description"] = "edited"; doc["cookbook_versions"] = {"mycook" => "~> 0.1"}`,
		"environment", "edit", "staging")
	env = h.raw(t, "/environments/staging")
	if got := field(t, env, "description"); got != "edited" {
		t.Errorf("edited description = %v, want edited", got)
	}
	if got := field(t, env, "cookbook_versions", "mycook"); got != "~> 0.1" {
		t.Errorf("edited cookbook_versions.mycook = %v, want ~> 0.1", got)
	}

	path := filepath.Join(h.dir, "prod.json")
	write(t, path, `{"name":"prod","description":"production","json_class":"Chef::Environment",`+
		`"chef_type":"environment","cookbook_versions":{"mycook":"= 0.1.0"},`+
		`"default_attributes":{"tier":"live"},"override_attributes":{}}`)
	h.run(t, "environment", "from", "file", path)
	prod := h.raw(t, "/environments/prod")
	if got := field(t, prod, "default_attributes", "tier"); got != "live" {
		t.Errorf("environment from file default_attributes.tier = %v, want live", got)
	}
	if got := field(t, prod, "cookbook_versions", "mycook"); got != "= 0.1.0" {
		t.Errorf("environment from file cookbook_versions.mycook = %v, want = 0.1.0", got)
	}

	out := h.run(t, "environment", "list")
	if got := objectsLines(out); !reflect.DeepEqual(got, []string{"_default", "prod", "staging"}) {
		t.Errorf("environment list = %q, want [_default prod staging]", got)
	}

	h.run(t, "environment", "delete", "staging", "--yes")
	envs := h.raw(t, "/environments")
	if _, ok := envs["staging"]; ok {
		t.Errorf("staging still listed after environment delete: %v", envs)
	}
	if _, ok := envs["prod"]; !ok {
		t.Errorf("environment delete staging also removed prod: %v", envs)
	}
}

func TestKnifeEnvironmentsCompare(t *testing.T) {
	t.Parallel()
	h := setup(t)

	h.run(t, "cookbook", "upload", "mycook")
	for name, constraint := range map[string]string{"dev": "= 0.1.0", "prod": "< 0.1.0"} {
		path := filepath.Join(h.dir, name+".json")
		write(t, path, `{"name":"`+name+`","json_class":"Chef::Environment","chef_type":"environment",`+
			`"cookbook_versions":{"mycook":"`+constraint+`"}}`)
		h.run(t, "environment", "from", "file", path)
	}

	out := h.run(t, "environment", "compare", "dev", "prod")
	var row string
	for _, l := range objectsLines(out) {
		if strings.HasPrefix(l, "mycook") {
			row = l
		}
	}
	if row == "" {
		t.Fatalf("environment compare has no row for mycook:\n%s", out)
	}
	if !strings.Contains(row, "= 0.1.0") || !strings.Contains(row, "< 0.1.0") {
		t.Errorf("environment compare row %q does not show both constraints:\n%s", row, out)
	}
	header := objectsLines(out)[0]
	if !strings.Contains(header, "dev") || !strings.Contains(header, "prod") {
		t.Errorf("environment compare header %q does not name both environments", header)
	}
}

func TestKnifeTags(t *testing.T) {
	t.Parallel()
	h := setup(t)

	objectsNode(t, h, "web01", `{"name":"web01","chef_environment":"_default","json_class":"Chef::Node",`+
		`"chef_type":"node","normal":{"tags":["existing"]}}`)

	h.run(t, "tag", "create", "web01", "blue", "canary")
	objectsWantList(t, "tags after create", field(t, h.raw(t, "/nodes/web01"), "normal", "tags"),
		"existing", "blue", "canary")

	if got := objectsLines(h.run(t, "tag", "list", "web01")); !reflect.DeepEqual(got, []string{"existing", "blue", "canary"}) {
		t.Errorf("tag list = %q, want [existing blue canary]", got)
	}

	// Tags are searchable, which is what they exist for.
	if out := h.run(t, "search", "node", "tags:canary", "-i"); !strings.Contains(out, "web01") {
		t.Errorf("search tags:canary does not find web01:\n%s", out)
	}

	h.run(t, "tag", "delete", "web01", "canary", "existing")
	objectsWantList(t, "tags after delete", field(t, h.raw(t, "/nodes/web01"), "normal", "tags"), "blue")
}

func TestKnifeStatus(t *testing.T) {
	t.Parallel()
	h := setup(t)

	objectsNode(t, h, "web01", `{"name":"web01","chef_environment":"_default","json_class":"Chef::Node",`+
		`"chef_type":"node","run_list":["recipe[mycook]"],"automatic":{"ohai_time":1700000000.5,`+
		`"fqdn":"web01.example.com","ipaddress":"10.0.0.1","platform":"ubuntu","platform_version":"22.04"}}`)
	objectsNode(t, h, "db01", `{"name":"db01","chef_environment":"_default","json_class":"Chef::Node",`+
		`"chef_type":"node","automatic":{"ohai_time":1700000000.5,"fqdn":"db01.example.com",`+
		`"ipaddress":"10.0.0.2","platform":"debian","platform_version":"12"}}`)

	out := h.run(t, "status", "--run-list")
	var web string
	for _, l := range objectsLines(out) {
		if strings.Contains(l, "web01") {
			web = l
		}
	}
	if web == "" || !strings.Contains(out, "db01") {
		t.Fatalf("knife status does not list both nodes:\n%s", out)
	}
	for _, want := range []string{"hours ago", "ubuntu 22.04", "recipe[mycook]"} {
		if !strings.Contains(web, want) {
			t.Errorf("knife status line for web01 lacks %q: %q", want, web)
		}
	}

	// The default output comes from a partial search, whose filter omits fqdn
	// and which knife indexes with a symbol (so the ipaddress it asked for is
	// never printed); --long fetches whole nodes and shows both.
	long := h.run(t, "status", "name:web01", "--long")
	for _, want := range []string{"web01.example.com", "10.0.0.1", "ubuntu 22.04"} {
		if !strings.Contains(long, want) {
			t.Errorf("knife status --long lacks %q:\n%s", want, long)
		}
	}

	// A query narrows it, through the search index.
	out = h.run(t, "status", "platform:debian")
	if !strings.Contains(out, "db01") || strings.Contains(out, "web01") {
		t.Errorf("knife status platform:debian = %q, want only db01", out)
	}
}

func TestKnifeExec(t *testing.T) {
	t.Parallel()
	h := setup(t)

	for _, n := range []string{"web02", "web01"} {
		objectsNode(t, h, n, `{"name":"`+n+`","chef_environment":"_default","json_class":"Chef::Node","chef_type":"node"}`)
	}

	out := h.run(t, "exec", "-E", `puts "NODES=" + nodes.all.map(&:name).sort.join(",")`)
	if !strings.Contains(out, "NODES=web01,web02") {
		t.Errorf("knife exec listing nodes = %q, want NODES=web01,web02", out)
	}

	// A script can write as well as read.
	h.run(t, "exec", "-E", `r = Chef::Role.new; r.name("from-exec"); r.description("saved by exec"); `+
		`r.run_list("recipe[mycook]"); r.save`)
	role := h.raw(t, "/roles/from-exec")
	if got := field(t, role, "description"); got != "saved by exec" {
		t.Errorf("role saved by knife exec has description %v, want %q", got, "saved by exec")
	}
	objectsWantList(t, "role saved by knife exec run_list", field(t, role, "run_list"), "recipe[mycook]")
}

func TestKnifeRecipeList(t *testing.T) {
	t.Parallel()
	h := setup(t)

	write(t, filepath.Join(h.dir, "cookbooks", "mycook", "recipes", "extra.rb"), "log 'extra'\n")
	h.run(t, "cookbook", "upload", "mycook")

	got := objectsLines(h.run(t, "recipe", "list"))
	if want := []string{"mycook", "mycook::extra"}; !reflect.DeepEqual(got, want) {
		t.Errorf("recipe list = %q, want %q", got, want)
	}
	got = objectsLines(h.run(t, "recipe", "list", "extra"))
	if want := []string{"mycook::extra"}; !reflect.DeepEqual(got, want) {
		t.Errorf("recipe list extra = %q, want %q", got, want)
	}
}
