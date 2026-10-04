//go:build conformance

package conformance

import (
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

// cookbooksFiles is a cookbook with one file in each of the segments a client
// downloads, so uploads and downloads exercise the file store, checksums and
// every manifest segment rather than a lone recipe.
func cookbooksFiles(name, version, flavor string) map[string]string {
	return map[string]string{
		"metadata.rb":                "name '" + name + "'\nversion '" + version + "'\n",
		"recipes/default.rb":         "package '" + flavor + "'\n",
		"recipes/extra.rb":           "log 'extra " + flavor + "'\n",
		"attributes/default.rb":      "default['" + name + "']['flavor'] = '" + flavor + "'\n",
		"templates/default/conf.erb": "flavor=<%= @flavor %> # " + flavor + "\n",
		"files/default/motd.txt":     "welcome to " + name + " " + version + " (" + flavor + ")\n",
		"libraries/helper.rb":        "module " + strings.ToUpper(name[:1]) + name[1:] + "Helper; end # " + flavor + "\n",
	}
}

// cookbooksWrite lays a cookbook out under the harness's cookbook_path,
// replacing whatever version was there before.
func cookbooksWrite(t *testing.T, h *harness, name string, files map[string]string) {
	t.Helper()
	root := filepath.Join(h.dir, "cookbooks", name)
	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	for rel, content := range files {
		write(t, filepath.Join(root, rel), content)
	}
}

// cookbooksVersions returns the versions of a cookbook the server holds, from
// GET /cookbooks/NAME?num_versions=all.
func cookbooksVersions(t *testing.T, h *harness, name string) []string {
	t.Helper()
	doc := h.raw(t, "/cookbooks/"+name+"?num_versions=all")
	entry, ok := field(t, doc, name).(map[string]any)
	if !ok {
		t.Fatalf("/cookbooks/%s: entry is not an object: %v", name, doc)
	}
	list, _ := entry["versions"].([]any)
	var versions []string
	for _, v := range list {
		if m, ok := v.(map[string]any); ok {
			versions = append(versions, m["version"].(string))
		}
	}
	sort.Strings(versions)
	return versions
}

// cookbooksNames returns the cookbook names the server lists.
func cookbooksNames(t *testing.T, h *harness) []string {
	t.Helper()
	var names []string
	for name := range h.raw(t, "/cookbooks") {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// cookbooksAbsent asserts a GET of path is refused as not found.
func cookbooksAbsent(t *testing.T, h *harness, path string) {
	t.Helper()
	out, err := h.tryAs(h.knifeRB, "raw", path)
	if err == nil {
		t.Fatalf("%s still exists:\n%s", path, out)
	}
	if !strings.Contains(out, "404") && !strings.Contains(strings.ToLower(out), "not found") {
		t.Fatalf("%s: expected a 404, got:\n%s", path, out)
	}
}

// cookbooksListPaths turns knife list -R output, which groups entries under
// "/dir:" headers, into the set of full paths it lists.
func cookbooksListPaths(out string) map[string]bool {
	paths := map[string]bool{}
	dir := ""
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "":
		case strings.HasPrefix(line, "/") && strings.HasSuffix(line, ":"):
			dir = strings.TrimSuffix(line, ":")
			paths[dir] = true
		case strings.HasPrefix(line, "/"):
			paths[line] = true
		default:
			paths[strings.TrimSuffix(dir, "/")+"/"+line] = true
		}
	}
	return paths
}

// cookbooksReadFile reads a file, failing the test if it cannot.
func cookbooksReadFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// Several versions of a cookbook with real files: download must reproduce the
// uploaded bytes for the version asked for, and delete must remove exactly one
// version while leaving the other servable.
func TestKnifeCookbooksDeleteDownload(t *testing.T) {
	t.Parallel()
	h := setup(t)

	v1 := cookbooksFiles("webapp", "1.0.0", "apache")
	cookbooksWrite(t, h, "webapp", v1)
	h.run(t, "cookbook", "upload", "webapp")
	v2 := cookbooksFiles("webapp", "1.1.0", "nginx")
	cookbooksWrite(t, h, "webapp", v2)
	h.run(t, "cookbook", "upload", "webapp")

	if got := cookbooksVersions(t, h, "webapp"); !slices.Equal(got, []string{"1.0.0", "1.1.0"}) {
		t.Fatalf("webapp versions = %v, want [1.0.0 1.1.0]", got)
	}

	// Download the older version: every file must come back byte for byte,
	// which proves the manifest's checksums point at the right blobs.
	dl := filepath.Join(h.dir, "dl")
	h.run(t, "cookbook", "download", "webapp", "1.0.0", "--dir", dl)
	root := filepath.Join(dl, "webapp-1.0.0")
	for rel, want := range v1 {
		if got := cookbooksReadFile(t, filepath.Join(root, rel)); got != want {
			t.Errorf("downloaded webapp 1.0.0 %s = %q, want %q", rel, got, want)
		}
	}
	// And the newer one carries its own content, not the older version's.
	h.run(t, "cookbook", "download", "webapp", "1.1.0", "--dir", dl)
	for rel, want := range v2 {
		if got := cookbooksReadFile(t, filepath.Join(dl, "webapp-1.1.0", rel)); got != want {
			t.Errorf("downloaded webapp 1.1.0 %s = %q, want %q", rel, got, want)
		}
	}

	// Delete one specific version while two exist.
	h.run(t, "cookbook", "delete", "webapp", "1.0.0", "--yes")
	if got := cookbooksVersions(t, h, "webapp"); !slices.Equal(got, []string{"1.1.0"}) {
		t.Fatalf("after deleting 1.0.0, webapp versions = %v, want [1.1.0]", got)
	}
	cookbooksAbsent(t, h, "/cookbooks/webapp/1.0.0")
	// The surviving version is still complete and downloadable, so the shared
	// blobs it references were not collected with the deleted version.
	dl2 := filepath.Join(h.dir, "dl2")
	h.run(t, "cookbook", "download", "webapp", "1.1.0", "--dir", dl2)
	for rel, want := range v2 {
		if got := cookbooksReadFile(t, filepath.Join(dl2, "webapp-1.1.0", rel)); got != want {
			t.Errorf("after delete, webapp 1.1.0 %s = %q, want %q", rel, got, want)
		}
	}

	// Deleting the last version removes the cookbook altogether.
	h.run(t, "cookbook", "delete", "webapp", "1.1.0", "--yes")
	if names := cookbooksNames(t, h); slices.Contains(names, "webapp") {
		t.Fatalf("webapp still listed after deleting its last version: %v", names)
	}
}

// Bulk delete removes every cookbook whose name matches the regex, every
// version of each, and nothing else.
func TestKnifeCookbooksBulkDelete(t *testing.T) {
	t.Parallel()
	h := setup(t)

	cookbooksWrite(t, h, "app_one", cookbooksFiles("app_one", "1.0.0", "a"))
	cookbooksWrite(t, h, "app_two", cookbooksFiles("app_two", "2.0.0", "b"))
	cookbooksWrite(t, h, "other", cookbooksFiles("other", "0.3.0", "c"))
	h.run(t, "cookbook", "upload", "--all")
	// A second version of app_one, so bulk delete has to remove all of them.
	cookbooksWrite(t, h, "app_one", cookbooksFiles("app_one", "1.0.1", "a2"))
	h.run(t, "cookbook", "upload", "app_one")

	if got := cookbooksNames(t, h); !slices.Equal(got, []string{"app_one", "app_two", "mycook", "other"}) {
		t.Fatalf("cookbooks before bulk delete = %v", got)
	}

	h.run(t, "cookbook", "bulk", "delete", "^app_", "--yes")

	if got := cookbooksNames(t, h); !slices.Equal(got, []string{"mycook", "other"}) {
		t.Fatalf("cookbooks after bulk delete ^app_ = %v, want [mycook other]", got)
	}
	cookbooksAbsent(t, h, "/cookbooks/app_one/1.0.0")
	cookbooksAbsent(t, h, "/cookbooks/app_one/1.0.1")
	cookbooksAbsent(t, h, "/cookbooks/app_two/2.0.0")
	if got := cookbooksVersions(t, h, "other"); !slices.Equal(got, []string{"0.3.0"}) {
		t.Fatalf("other versions = %v, want [0.3.0]", got)
	}
}

// knife upload pushes a local chef repository to the server, and knife diff
// and download compare and pull it back.
func TestKnifeRepoUploadDiffDownload(t *testing.T) {
	t.Parallel()
	h := setup(t)
	repo := filepath.Join(h.dir, "repo")

	write(t, filepath.Join(repo, "roles", "web.json"),
		`{"name":"web","description":"web tier","json_class":"Chef::Role","chef_type":"role",`+
			`"default_attributes":{"port":80},"override_attributes":{},"run_list":["recipe[mycook]"],"env_run_lists":{}}`)
	write(t, filepath.Join(repo, "environments", "staging.json"),
		`{"name":"staging","description":"staging env","json_class":"Chef::Environment","chef_type":"environment",`+
			`"cookbook_versions":{"mycook":"= 0.1.0"},"default_attributes":{},"override_attributes":{}}`)
	write(t, filepath.Join(repo, "nodes", "db01.json"),
		`{"name":"db01","chef_environment":"staging","json_class":"Chef::Node","chef_type":"node",`+
			`"normal":{"tier":"db"},"run_list":["role[web]"]}`)
	write(t, filepath.Join(repo, "data_bags", "creds", "mysql.json"), `{"id":"mysql","password":"hunter2"}`)

	h.run(t, "upload", "/roles", "/environments", "/nodes", "/data_bags", "/cookbooks")

	role := h.raw(t, "/roles/web")
	if got := field(t, role, "default_attributes", "port"); got != float64(80) {
		t.Errorf("uploaded role port = %v, want 80", got)
	}
	env := h.raw(t, "/environments/staging")
	if got := field(t, env, "cookbook_versions", "mycook"); got != "= 0.1.0" {
		t.Errorf("uploaded environment pin = %v, want = 0.1.0", got)
	}
	node := h.raw(t, "/nodes/db01")
	if got := field(t, node, "normal", "tier"); got != "db" {
		t.Errorf("uploaded node tier = %v, want db", got)
	}
	item := h.raw(t, "/data/creds/mysql")
	if got := field(t, item, "password"); got != "hunter2" {
		t.Errorf("uploaded data bag item password = %v, want hunter2", got)
	}
	if got := cookbooksVersions(t, h, "mycook"); !slices.Equal(got, []string{"0.1.0"}) {
		t.Errorf("uploaded mycook versions = %v, want [0.1.0]", got)
	}

	// In sync: no differences.
	// knife compiles metadata.rb into a metadata.json and uploads that too
	// (Chef::CookbookVersion#compile_metadata), so the server's copy of a
	// cookbook carries a file the local one lacks; real Chef Infra Server
	// reports the same. Every other cookbook file must be identical.
	syncPaths := []string{"/roles", "/environments/staging.json", "/nodes", "/data_bags", "/cookbooks/mycook"}
	out := h.run(t, append([]string{"diff", "--name-status"}, syncPaths...)...)
	if strings.TrimSpace(out) != "D\t/cookbooks/mycook/metadata.json" {
		t.Fatalf("knife diff after upload reports differences:\n%s", out)
	}

	// A local change shows up as a modification of exactly that file.
	write(t, filepath.Join(repo, "roles", "web.json"),
		`{"name":"web","description":"web tier","json_class":"Chef::Role","chef_type":"role",`+
			`"default_attributes":{"port":8080},"override_attributes":{},"run_list":["recipe[mycook]"],"env_run_lists":{}}`)
	out, _ = h.tryAs(h.knifeRB, "diff", "--name-status", "/roles", "/nodes")
	if !strings.Contains(out, "M\t/roles/web.json") {
		t.Fatalf("knife diff did not report the modified role:\n%s", out)
	}
	if strings.Contains(out, "/nodes/") {
		t.Fatalf("knife diff reports an unchanged node:\n%s", out)
	}
	full, _ := h.tryAs(h.knifeRB, "diff", "/roles/web.json")
	if !strings.Contains(full, "8080") {
		t.Fatalf("knife diff does not show the changed value:\n%s", full)
	}

	// Download restores the local copy from the server.
	h.run(t, "download", "/roles/web.json")
	if got := decodeObject(t, "roles/web.json", cookbooksReadFile(t, filepath.Join(repo, "roles", "web.json"))); field(t, got, "default_attributes", "port") != float64(80) {
		t.Fatalf("downloaded role = %v, want port 80", got)
	}
	if out := h.run(t, "diff", "--name-status", "/roles"); strings.TrimSpace(out) != "" {
		t.Fatalf("knife diff after download reports differences:\n%s", out)
	}

	// Objects created on the server arrive in a fresh local repository with
	// the server's content.
	write(t, filepath.Join(h.dir, "app01.json"),
		`{"name":"app01","chef_environment":"_default","json_class":"Chef::Node","chef_type":"node","normal":{"tier":"app"},"run_list":[]}`)
	h.run(t, "node", "from", "file", filepath.Join(h.dir, "app01.json"))
	h.run(t, "download", "/nodes", "/data_bags", "/cookbooks/mycook")
	app := decodeObject(t, "nodes/app01.json", cookbooksReadFile(t, filepath.Join(repo, "nodes", "app01.json")))
	if got := field(t, app, "normal", "tier"); got != "app" {
		t.Errorf("downloaded node tier = %v, want app", got)
	}
	dl := decodeObject(t, "data_bags/creds/mysql.json", cookbooksReadFile(t, filepath.Join(repo, "data_bags", "creds", "mysql.json")))
	if got := field(t, dl, "password"); got != "hunter2" {
		t.Errorf("downloaded data bag item password = %v, want hunter2", got)
	}
}

// knife list, show and delete treat the server as a file system.
func TestKnifeRepoListShowDelete(t *testing.T) {
	t.Parallel()
	h := setup(t)

	write(t, filepath.Join(h.dir, "web01.json"),
		`{"name":"web01","chef_environment":"_default","json_class":"Chef::Node","chef_type":"node","normal":{"tier":"web"},"run_list":[]}`)
	h.run(t, "node", "from", "file", filepath.Join(h.dir, "web01.json"))
	write(t, filepath.Join(h.dir, "base.json"),
		`{"name":"base","json_class":"Chef::Role","chef_type":"role","run_list":["recipe[mycook]"]}`)
	h.run(t, "role", "from", "file", filepath.Join(h.dir, "base.json"))
	h.run(t, "cookbook", "upload", "mycook")
	h.run(t, "data", "bag", "create", "things")

	if out := h.run(t, "list", "/nodes"); strings.TrimSpace(out) != "/nodes/web01.json" {
		t.Errorf("knife list /nodes = %q, want /nodes/web01.json", out)
	}
	if out := h.run(t, "list", "/roles"); strings.TrimSpace(out) != "/roles/base.json" {
		t.Errorf("knife list /roles = %q, want /roles/base.json", out)
	}
	if out := h.run(t, "list", "/cookbooks"); strings.TrimSpace(out) != "/cookbooks/mycook" {
		t.Errorf("knife list /cookbooks = %q, want /cookbooks/mycook", out)
	}

	// A recursive listing walks every top-level container of a hosted org.
	all := cookbooksListPaths(h.run(t, "list", "-R", "/"))
	for _, want := range []string{
		"/nodes/web01.json", "/roles/base.json", "/cookbooks/mycook/metadata.rb",
		"/cookbooks/mycook/recipes/default.rb", "/data_bags/things", "/environments/_default.json",
		"/clients/acme-validator.json", "/groups/admins.json", "/containers/nodes.json",
		"/acls/nodes/web01.json", "/members.json", "/policies", "/policy_groups",
	} {
		if !all[want] {
			t.Errorf("knife list -R / lacks %s:\n%v", want, all)
		}
	}

	show := decodeObject(t, "show /nodes/web01.json", h.run(t, "show", "/nodes/web01.json"))
	if got := field(t, show, "normal", "tier"); got != "web" {
		t.Errorf("knife show node tier = %v, want web", got)
	}
	if got := h.run(t, "show", "/cookbooks/mycook/recipes/default.rb"); !strings.Contains(got, "package 'nginx'") {
		t.Errorf("knife show of a cookbook file = %q, want its content", got)
	}

	h.run(t, "delete", "/nodes/web01.json")
	cookbooksAbsent(t, h, "/nodes/web01")
	h.run(t, "delete", "-r", "/cookbooks/mycook")
	cookbooksAbsent(t, h, "/cookbooks/mycook")
	h.run(t, "delete", "-r", "/data_bags/things")
	cookbooksAbsent(t, h, "/data/things")
	// The role was not a target and survives.
	if got := field(t, h.raw(t, "/roles/base"), "name"); got != "base" {
		t.Errorf("unrelated role name = %v, want base", got)
	}
}

// knife deps follows a node to its roles and cookbooks, and a cookbook to the
// cookbooks it depends on, on the server.
func TestKnifeRepoDeps(t *testing.T) {
	t.Parallel()
	h := setup(t)

	cookbooksWrite(t, h, "libcook", map[string]string{
		"metadata.rb": "name 'libcook'\nversion '1.0.0'\n", "recipes/default.rb": "log 'lib'\n",
	})
	cookbooksWrite(t, h, "webcook", map[string]string{
		"metadata.rb":        "name 'webcook'\nversion '1.0.0'\ndepends 'libcook'\n",
		"recipes/default.rb": "include_recipe 'libcook'\n",
	})
	h.run(t, "cookbook", "upload", "--all")
	write(t, filepath.Join(h.dir, "base.json"),
		`{"name":"base","json_class":"Chef::Role","chef_type":"role","run_list":["recipe[webcook]"]}`)
	h.run(t, "role", "from", "file", filepath.Join(h.dir, "base.json"))
	write(t, filepath.Join(h.dir, "staging.json"),
		`{"name":"staging","json_class":"Chef::Environment","chef_type":"environment"}`)
	h.run(t, "environment", "from", "file", filepath.Join(h.dir, "staging.json"))
	write(t, filepath.Join(h.dir, "n1.json"),
		`{"name":"n1","chef_environment":"staging","json_class":"Chef::Node","chef_type":"node","run_list":["role[base]"]}`)
	h.run(t, "node", "from", "file", filepath.Join(h.dir, "n1.json"))

	lines := func(out string) []string {
		var ls []string
		for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
			ls = append(ls, strings.TrimSpace(l))
		}
		sort.Strings(ls)
		return ls
	}
	got := lines(h.run(t, "deps", "--remote", "/nodes/n1.json"))
	want := []string{"/cookbooks/libcook", "/cookbooks/webcook", "/environments/staging.json", "/nodes/n1.json", "/roles/base.json"}
	if !slices.Equal(got, want) {
		t.Errorf("knife deps --remote /nodes/n1.json = %v, want %v", got, want)
	}
	got = lines(h.run(t, "deps", "--remote", "/cookbooks/webcook"))
	if !slices.Equal(got, []string{"/cookbooks/libcook", "/cookbooks/webcook"}) {
		t.Errorf("knife deps --remote /cookbooks/webcook = %v", got)
	}
}

// knife edit and knife xargs change server objects in place.
func TestKnifeRepoEditXargs(t *testing.T) {
	t.Parallel()
	h := setup(t)

	write(t, filepath.Join(h.dir, "base.json"),
		`{"name":"base","description":"before","json_class":"Chef::Role","chef_type":"role","run_list":[]}`)
	h.run(t, "role", "from", "file", filepath.Join(h.dir, "base.json"))
	for _, n := range []string{"x1", "x2"} {
		write(t, filepath.Join(h.dir, n+".json"),
			`{"name":"`+n+`","chef_environment":"_default","json_class":"Chef::Node","chef_type":"node","normal":{"tier":"old"},"run_list":[]}`)
		h.run(t, "node", "from", "file", filepath.Join(h.dir, n+".json"))
	}

	h.edit(t, `doc["description"] = "edited"`, "edit", "/roles/base.json")
	if got := field(t, h.raw(t, "/roles/base"), "description"); got != "edited" {
		t.Fatalf("after knife edit, role description = %v, want edited", got)
	}

	// xargs hands the command temporary copies of the matched objects, and
	// uploads whatever the command changed.
	script := filepath.Join(h.dir, "retier.rb")
	write(t, script, "require 'json'\nARGV.each do |p|\n  d = JSON.parse(File.read(p))\n"+
		"  d['normal']['tier'] = 'new'\n  File.write(p, JSON.pretty_generate(d))\nend\n")
	h.run(t, "xargs", "--pattern", "/nodes/*", rubyBin(t)+" "+script)
	for _, n := range []string{"x1", "x2"} {
		if got := field(t, h.raw(t, "/nodes/"+n), "normal", "tier"); got != "new" {
			t.Errorf("after knife xargs, node %s tier = %v, want new", n, got)
		}
	}
	// A read-only command changes nothing and sees the server's content.
	if out := h.run(t, "xargs", "--pattern", "/roles/base.json", "cat"); !strings.Contains(out, "edited") {
		t.Errorf("knife xargs cat did not show the role:\n%s", out)
	}
}

// data bag edit changes an item, and data bag delete removes an item or a
// whole bag.
func TestKnifeDataBagsDeleteEdit(t *testing.T) {
	t.Parallel()
	h := setup(t)

	h.run(t, "data", "bag", "create", "apps")
	h.run(t, "data", "bag", "create", "scratch")
	for _, id := range []string{"one", "two"} {
		write(t, filepath.Join(h.dir, id+".json"), `{"id":"`+id+`","owner":"ops"}`)
		h.run(t, "data", "bag", "from", "file", "apps", filepath.Join(h.dir, id+".json"))
	}
	write(t, filepath.Join(h.dir, "tmp.json"), `{"id":"tmp"}`)
	h.run(t, "data", "bag", "from", "file", "scratch", filepath.Join(h.dir, "tmp.json"))

	h.edit(t, `doc["owner"] = "dev"; doc["added"] = [1, 2]`, "data", "bag", "edit", "apps", "one")
	item := h.raw(t, "/data/apps/one")
	if got := field(t, item, "owner"); got != "dev" {
		t.Errorf("edited item owner = %v, want dev", got)
	}
	if got, ok := field(t, item, "added").([]any); !ok || len(got) != 2 {
		t.Errorf("edited item added = %v, want [1 2]", field(t, item, "added"))
	}
	if got := field(t, h.raw(t, "/data/apps/two"), "owner"); got != "ops" {
		t.Errorf("unedited item owner = %v, want ops", got)
	}

	// Delete one item: its sibling and the bag remain.
	h.run(t, "data", "bag", "delete", "apps", "one", "--yes")
	cookbooksAbsent(t, h, "/data/apps/one")
	bag := h.raw(t, "/data/apps")
	if _, ok := bag["two"]; !ok || len(bag) != 1 {
		t.Errorf("apps after deleting one = %v, want only two", bag)
	}

	// Delete a whole bag with its items.
	h.run(t, "data", "bag", "delete", "scratch", "--yes")
	cookbooksAbsent(t, h, "/data/scratch")
	cookbooksAbsent(t, h, "/data/scratch/tmp")
	bags := h.raw(t, "/data")
	if _, ok := bags["scratch"]; ok {
		t.Errorf("scratch still listed: %v", bags)
	}
	if _, ok := bags["apps"]; !ok {
		t.Errorf("apps was deleted along with scratch: %v", bags)
	}
}
