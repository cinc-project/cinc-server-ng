//go:build conformance

package conformance

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

// The Policyfile workflow end to end, with the real Policyfile CLI: real
// Policyfile.rb files resolving real local cookbooks (with a dependency between
// them, attributes, a template), pushed, inspected, diffed, cleaned, deleted
// and undeleted, and finally converged by a real client. Every assertion about
// what a command did reads the server state back with knife raw.

// policyCookbooks writes two cookbooks into h.dir/cookbooks (knife's
// cookbook_path, so `knife cookbook upload` sees them too): pf_base, with an
// attribute and a template, and pf_app, which depends on pf_base and writes
// the file a converge is judged by. baseVersion lets a test produce a second,
// different pf_base.
func policyCookbooks(t *testing.T, h *harness, baseVersion string) string {
	t.Helper()
	books := filepath.Join(h.dir, "cookbooks")
	write(t, filepath.Join(books, "pf_base", "metadata.rb"),
		"name 'pf_base'\nversion '"+baseVersion+"'\n")
	write(t, filepath.Join(books, "pf_base", "attributes", "default.rb"),
		"default['pf_base']['greeting'] = 'hello from pf_base "+baseVersion+"'\n")
	write(t, filepath.Join(books, "pf_base", "templates", "default", "motd.erb"),
		"greeting=<%= @greeting %>\n")
	write(t, filepath.Join(books, "pf_base", "recipes", "default.rb"),
		"template ::File.join(node['pf_app']['dir'], 'motd') do\n"+
			"  source 'motd.erb'\n"+
			"  variables(greeting: node['pf_base']['greeting'])\n"+
			"end\n")
	write(t, filepath.Join(books, "pf_app", "metadata.rb"),
		"name 'pf_app'\nversion '1.0.0'\ndepends 'pf_base'\n")
	write(t, filepath.Join(books, "pf_app", "attributes", "default.rb"),
		"default['pf_app']['message'] = 'from the cookbook'\n")
	write(t, filepath.Join(books, "pf_app", "recipes", "default.rb"),
		"include_recipe 'pf_base::default'\n"+
			"file ::File.join(node['pf_app']['dir'], 'converged') do\n"+
			"  content node['pf_app']['message']\n"+
			"end\n")
	return books
}

// policyWritePolicyfile writes a Policyfile.rb for policy name into dir,
// resolving from source (a full default_source line), with extra lines
// appended.
func policyWritePolicyfile(t *testing.T, dir, name, source string, extra ...string) {
	t.Helper()
	write(t, filepath.Join(dir, "Policyfile.rb"), strings.Join(append([]string{
		"name '" + name + "'",
		source,
		"run_list 'pf_app::default'",
	}, extra...), "\n")+"\n")
}

// policyLock reads the Policyfile.lock.json the CLI wrote into dir.
func policyLock(t *testing.T, dir string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "Policyfile.lock.json"))
	if err != nil {
		t.Fatalf("reading the lock: %v", err)
	}
	var lock map[string]any
	if err := json.Unmarshal(data, &lock); err != nil {
		t.Fatalf("lock is not JSON: %v", err)
	}
	return lock
}

// policyLockIdentifier is the content identifier the lock pins cookbook to:
// the artifact id it is uploaded under.
func policyLockIdentifier(t *testing.T, lock map[string]any, cookbook string) string {
	t.Helper()
	id, _ := field(t, lock, "cookbook_locks", cookbook, "identifier").(string)
	if id == "" {
		t.Fatalf("lock pins no identifier for %s", cookbook)
	}
	return id
}

// policyRevisions lists a policy's revision ids from GET /policies/NAME.
func policyRevisions(t *testing.T, h *harness, name string) []string {
	t.Helper()
	revs, _ := field(t, h.raw(t, "/policies/"+name), "revisions").(map[string]any)
	var ids []string
	for id := range revs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// policyGroupRevision is the revision a group assigns to a policy, from
// GET /policy_groups/GROUP.
func policyGroupRevision(t *testing.T, h *harness, group, policy string) string {
	t.Helper()
	rev, _ := field(t, h.raw(t, "/policy_groups/"+group), "policies", policy, "revision_id").(string)
	return rev
}

// policyArtifactIDs lists the identifiers stored for a cookbook artifact, or
// nil when there is none.
func policyArtifactIDs(t *testing.T, h *harness, cookbook string) []string {
	t.Helper()
	all := h.raw(t, "/cookbook_artifacts")
	entry, ok := all[cookbook].(map[string]any)
	if !ok {
		return nil
	}
	versions, _ := entry["versions"].([]any)
	var ids []string
	for _, v := range versions {
		if m, ok := v.(map[string]any); ok {
			if id, ok := m["identifier"].(string); ok {
				ids = append(ids, id)
			}
		}
	}
	sort.Strings(ids)
	return ids
}

// policyRawMissing asserts that a GET on path is refused as not found.
func policyRawMissing(t *testing.T, h *harness, path string) {
	t.Helper()
	out, err := h.tryAs(h.knifeRB, "raw", path)
	if err == nil {
		t.Fatalf("GET %s still succeeds:\n%s", path, out)
	}
	if !strings.Contains(out, "404") && !strings.Contains(strings.ToLower(out), "not found") {
		t.Fatalf("GET %s failed, but not as not-found:\n%s", path, out)
	}
}

// install, update, push (twice), show-policy and diff, against a Policyfile
// that resolves path-free from a local chef repo.
func TestPolicyfileInstallPushShowDiff(t *testing.T) {
	t.Parallel()
	h := setup(t)
	books := policyCookbooks(t, h, "1.0.0")
	work := filepath.Join(h.dir, "policy")
	source := "default_source :chef_repo, '" + books + "'"
	policyWritePolicyfile(t, work, "app", source, "default['pf_app']['message'] = 'v1'")

	h.cli(t, work, "install")
	lock1 := policyLock(t, work)
	rev1, _ := field(t, lock1, "revision_id").(string)
	baseID := policyLockIdentifier(t, lock1, "pf_base")
	appID := policyLockIdentifier(t, lock1, "pf_app")
	if got := field(t, lock1, "cookbook_locks", "pf_base", "version"); got != "1.0.0" {
		t.Errorf("locked pf_base version = %v, want 1.0.0", got)
	}

	// First push: the group, the policy, the revision and both artifacts exist.
	h.cli(t, work, "push", "dev")
	if got := policyGroupRevision(t, h, "dev", "app"); got != rev1 {
		t.Fatalf("dev assigns app revision %q, want %q", got, rev1)
	}
	if out := h.run(t, "raw", "/policy_groups"); !strings.Contains(out, `"dev"`) {
		t.Errorf("/policy_groups does not list dev:\n%s", out)
	}
	if got := policyRevisions(t, h, "app"); !slices.Equal(got, []string{rev1}) {
		t.Errorf("/policies/app revisions = %v, want [%s]", got, rev1)
	}
	if _, ok := h.raw(t, "/policies")["app"]; !ok {
		t.Errorf("/policies does not list app")
	}
	stored := h.raw(t, "/policies/app/revisions/"+rev1)
	if got := field(t, stored, "default_attributes", "pf_app", "message"); got != "v1" {
		t.Errorf("stored revision's default attribute = %v, want v1", got)
	}
	if got := field(t, stored, "cookbook_locks", "pf_base", "identifier"); got != baseID {
		t.Errorf("stored revision pins pf_base %v, want %s", got, baseID)
	}
	if got := policyArtifactIDs(t, h, "pf_base"); !slices.Equal(got, []string{baseID}) {
		t.Errorf("pf_base artifacts = %v, want [%s]", got, baseID)
	}
	art := h.raw(t, "/cookbook_artifacts/pf_app/"+appID)
	if got := field(t, art, "identifier"); got != appID {
		t.Errorf("artifact identifier = %v, want %s", got, appID)
	}
	if deps := field(t, art, "metadata", "dependencies"); !strings.Contains(mustJSON(t, deps), "pf_base") {
		t.Errorf("pf_app artifact metadata lost its dependency: %v", deps)
	}

	// The same revision to prod, so there are two groups to compare later.
	h.cli(t, work, "push", "prod")

	// Change the policy and a cookbook, and re-resolve: update writes a new
	// lock with a new pf_base identifier and a new revision.
	policyCookbooks(t, h, "1.1.0")
	policyWritePolicyfile(t, work, "app", source, "default['pf_app']['message'] = 'v2'")
	h.cli(t, work, "update")
	lock2 := policyLock(t, work)
	rev2, _ := field(t, lock2, "revision_id").(string)
	if rev2 == rev1 {
		t.Fatalf("update did not produce a new revision")
	}
	if got := field(t, lock2, "cookbook_locks", "pf_base", "version"); got != "1.1.0" {
		t.Errorf("updated pf_base version = %v, want 1.1.0", got)
	}
	baseID2 := policyLockIdentifier(t, lock2, "pf_base")
	if policyLockIdentifier(t, lock2, "pf_app") != appID {
		t.Fatalf("pf_app did not change, so its identifier should not have either")
	}

	// diff of the local lock against a group, before pushing it there.
	diff := h.cli(t, work, "diff", "dev", "--no-pager")
	for _, want := range []string{"pf_base", "1.0.0", "1.1.0", "v1", "v2"} {
		if !strings.Contains(diff, want) {
			t.Errorf("diff dev does not mention %q:\n%s", want, diff)
		}
	}

	// Second push: a second revision, and content-addressed artifacts: the
	// unchanged pf_app is not stored again, the changed pf_base is added.
	h.cli(t, work, "push", "dev")
	if got := policyGroupRevision(t, h, "dev", "app"); got != rev2 {
		t.Fatalf("dev assigns %q after the second push, want %q", got, rev2)
	}
	wantRevs := []string{rev1, rev2}
	sort.Strings(wantRevs)
	if got := policyRevisions(t, h, "app"); !slices.Equal(got, wantRevs) {
		t.Errorf("/policies/app revisions = %v, want %v", got, wantRevs)
	}
	if got := policyArtifactIDs(t, h, "pf_app"); !slices.Equal(got, []string{appID}) {
		t.Errorf("pf_app artifacts = %v, want only [%s]", got, appID)
	}
	wantBase := []string{baseID, baseID2}
	sort.Strings(wantBase)
	if got := policyArtifactIDs(t, h, "pf_base"); !slices.Equal(got, wantBase) {
		t.Errorf("pf_base artifacts = %v, want %v", got, wantBase)
	}

	// diff between the two groups.
	diff = h.cli(t, work, "diff", "prod...dev", "--no-pager")
	for _, want := range []string{"1.0.0", "1.1.0", "v1", "v2"} {
		if !strings.Contains(diff, want) {
			t.Errorf("diff prod...dev does not mention %q:\n%s", want, diff)
		}
	}
	// And a lock against the group it matches: nothing to report.
	if diff := h.cli(t, work, "diff", "dev", "--no-pager"); strings.Contains(diff, "1.0.0") {
		t.Errorf("diff of a lock against its own group reports a change:\n%s", diff)
	}

	// show-policy: everything, one policy, one policy in one group.
	all := h.cli(t, work, "show-policy", "--no-pager")
	for _, want := range []string{"app", "dev", "prod", rev1[:10], rev2[:10]} {
		if !strings.Contains(all, want) {
			t.Errorf("show-policy does not mention %q:\n%s", want, all)
		}
	}
	one := h.cli(t, work, "show-policy", "app", "--no-pager")
	for _, want := range []string{"dev", "prod", rev1[:10], rev2[:10]} {
		if !strings.Contains(one, want) {
			t.Errorf("show-policy app does not mention %q:\n%s", want, one)
		}
	}
	group := h.cli(t, work, "show-policy", "app", "prod", "--no-pager")
	shown := decodeObject(t, "show-policy app prod", group)
	if got := field(t, shown, "revision_id"); got != rev1 {
		t.Errorf("show-policy app prod shows revision %v, want %s", got, rev1)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// clean-policy-revisions, clean-policy-cookbooks, delete-policy-group,
// delete-policy and undelete, each checked against what is on the server.
func TestPolicyfileCleanDeleteUndelete(t *testing.T) {
	t.Parallel()
	h := setup(t)
	books := policyCookbooks(t, h, "1.0.0")
	work := filepath.Join(h.dir, "policy")
	source := "default_source :chef_repo, '" + books + "'"
	policyWritePolicyfile(t, work, "app", source)

	h.cli(t, work, "install")
	lock1 := policyLock(t, work)
	rev1, _ := field(t, lock1, "revision_id").(string)
	base1 := policyLockIdentifier(t, lock1, "pf_base")
	appID := policyLockIdentifier(t, lock1, "pf_app")
	h.cli(t, work, "push", "dev")

	policyCookbooks(t, h, "1.1.0")
	h.cli(t, work, "update")
	lock2 := policyLock(t, work)
	rev2, _ := field(t, lock2, "revision_id").(string)
	base2 := policyLockIdentifier(t, lock2, "pf_base")
	h.cli(t, work, "push", "dev")
	h.cli(t, work, "push", "prod")

	// rev1 is now assigned to no group: it alone is cleaned.
	if got := policyRevisions(t, h, "app"); len(got) != 2 {
		t.Fatalf("expected two revisions before cleaning, got %v", got)
	}
	h.cli(t, work, "clean-policy-revisions")
	if got := policyRevisions(t, h, "app"); !slices.Equal(got, []string{rev2}) {
		t.Fatalf("after clean-policy-revisions, revisions = %v, want only [%s]", got, rev2)
	}
	policyRawMissing(t, h, "/policies/app/revisions/"+rev1)

	// With rev1 gone, the pf_base artifact only it referenced is unused; the
	// ones rev2 references are kept.
	h.cli(t, work, "clean-policy-cookbooks")
	if got := policyArtifactIDs(t, h, "pf_base"); !slices.Equal(got, []string{base2}) {
		t.Errorf("after clean-policy-cookbooks, pf_base artifacts = %v, want only [%s]", got, base2)
	}
	policyRawMissing(t, h, "/cookbook_artifacts/pf_base/"+base1)
	if got := policyArtifactIDs(t, h, "pf_app"); !slices.Equal(got, []string{appID}) {
		t.Errorf("after clean-policy-cookbooks, pf_app artifacts = %v, want [%s]", got, appID)
	}

	// delete-policy-group removes the group but leaves the policy and the
	// other group.
	h.cli(t, work, "delete-policy-group", "dev")
	policyRawMissing(t, h, "/policy_groups/dev")
	if got := policyGroupRevision(t, h, "prod", "app"); got != rev2 {
		t.Errorf("prod lost its policy when dev was deleted: %q", got)
	}
	// undelete restores it, assignment and all.
	h.cli(t, work, "undelete", "--last")
	if got := policyGroupRevision(t, h, "dev", "app"); got != rev2 {
		t.Fatalf("undelete did not restore dev's assignment: %q", got)
	}

	// delete-policy removes every revision, and the policy from the groups.
	h.cli(t, work, "delete-policy", "app")
	policyRawMissing(t, h, "/policies/app")
	policyRawMissing(t, h, "/policies/app/revisions/"+rev2)
	if out := h.run(t, "raw", "/policy_groups/prod"); strings.Contains(out, rev2) {
		t.Errorf("prod still assigns a revision of a deleted policy:\n%s", out)
	}
	// undelete brings the revision back, and its group assignments.
	h.cli(t, work, "undelete", "--last")
	if got := field(t, h.raw(t, "/policies/app/revisions/"+rev2), "revision_id"); got != rev2 {
		t.Errorf("undelete restored revision %v, want %s", got, rev2)
	}
	for _, g := range []string{"dev", "prod"} {
		if got := policyGroupRevision(t, h, g, "app"); got != rev2 {
			t.Errorf("undelete did not restore %s's assignment: %q", g, got)
		}
	}
}

// A Policyfile resolving from the server itself: cookbooks uploaded with knife
// are found through /universe, and install fetches them from the server.
func TestPolicyfileChefServerSource(t *testing.T) {
	t.Parallel()
	h := setup(t)
	policyCookbooks(t, h, "1.0.0")
	h.run(t, "cookbook", "upload", "pf_base", "pf_app")

	universe := h.raw(t, "/universe")
	if _, ok := universe["pf_app"].(map[string]any)["1.0.0"]; !ok {
		t.Fatalf("/universe lacks pf_app 1.0.0: %v", universe["pf_app"])
	}

	work := filepath.Join(h.dir, "policy")
	policyWritePolicyfile(t, work, "fromserver",
		"default_source :chef_server, '"+h.srv.URL()+"/organizations/"+orgName+"'")
	h.cli(t, work, "install")
	lock := policyLock(t, work)
	for _, cb := range []string{"pf_app", "pf_base"} {
		if got := field(t, lock, "cookbook_locks", cb, "version"); got != "1.0.0" {
			t.Errorf("locked %s version = %v, want 1.0.0", cb, got)
		}
		if got := mustJSON(t, field(t, lock, "cookbook_locks", cb, "source_options")); !strings.Contains(got, "chef_server") {
			t.Errorf("%s was not resolved from the server: %s", cb, got)
		}
	}
	h.cli(t, work, "push", "dev")
	rev, _ := field(t, lock, "revision_id").(string)
	if got := policyGroupRevision(t, h, "dev", "fromserver"); got != rev {
		t.Fatalf("dev assigns %q, want %q", got, rev)
	}
	id := policyLockIdentifier(t, lock, "pf_base")
	if got := policyArtifactIDs(t, h, "pf_base"); !slices.Equal(got, []string{id}) {
		t.Errorf("pf_base artifacts = %v, want [%s]", got, id)
	}
}

// push-archive: a policy exported as an archive and pushed from it.
func TestPolicyfilePushArchive(t *testing.T) {
	t.Parallel()
	h := setup(t)
	books := policyCookbooks(t, h, "1.0.0")
	work := filepath.Join(h.dir, "policy")
	policyWritePolicyfile(t, work, "archived", "default_source :chef_repo, '"+books+"'")
	h.cli(t, work, "install")
	lock := policyLock(t, work)
	rev, _ := field(t, lock, "revision_id").(string)

	out := filepath.Join(h.dir, "export")
	h.cli(t, work, "export", "-a", "Policyfile.rb", out)
	archives, _ := filepath.Glob(filepath.Join(out, "*.tgz"))
	if len(archives) != 1 {
		t.Fatalf("export -a produced %v", archives)
	}

	h.cli(t, work, "push-archive", "staging", archives[0])
	if got := policyGroupRevision(t, h, "staging", "archived"); got != rev {
		t.Fatalf("staging assigns %q, want %q", got, rev)
	}
	for _, cb := range []string{"pf_app", "pf_base"} {
		id := policyLockIdentifier(t, lock, cb)
		art := h.raw(t, "/cookbook_artifacts/"+cb+"/"+id)
		if got := field(t, art, "name"); got != cb+"-"+id && got != cb {
			t.Errorf("artifact %s name = %v", cb, got)
		}
	}
}

// A real converge: a client registered on the server runs with a policy name
// and group, fetches the policy, the artifacts and their files, converges, and
// saves its node. Then knife node policy set moves the node to another group.
func TestPolicyfileConverge(t *testing.T) {
	t.Parallel()
	h := setup(t)
	client := clientBin(t)
	books := policyCookbooks(t, h, "1.0.0")
	work := filepath.Join(h.dir, "policy")
	out := filepath.Join(h.dir, "converge-out")
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	policyWritePolicyfile(t, work, "app", "default_source :chef_repo, '"+books+"'",
		"default['pf_app']['dir'] = '"+out+"'",
		"override['pf_app']['message'] = 'converged by policy'")
	h.cli(t, work, "install")
	h.cli(t, work, "push", "dev")
	h.cli(t, work, "push", "prod")

	key := h.createClient(t, "policynode")
	cache := filepath.Join(h.dir, "client-cache")
	clientRB := filepath.Join(h.dir, "client.rb")
	write(t, clientRB, strings.Join([]string{
		"node_name 'policynode'",
		"client_key '" + key + "'",
		"chef_server_url '" + h.srv.URL() + "/organizations/" + orgName + "'",
		"policy_name 'app'",
		"policy_group 'dev'",
		"file_cache_path '" + cache + "'",
		"file_backup_path '" + filepath.Join(cache, "backup") + "'",
		"cache_path '" + cache + "'",
		"ssl_verify_mode :verify_none",
		"",
	}, "\n"))
	cmd := exec.Command(client, "-c", clientRB, "--once", "--no-fork", "-l", "info",
		"--chef-license", "accept-no-persist")
	cmd.Dir = h.dir
	cmd.Env = append(os.Environ(), "HOME="+h.dir, "CHEF_LICENSE=accept-no-persist")
	runOut, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("client run failed: %v\n%s", err, runOut)
	}

	got, err := os.ReadFile(filepath.Join(out, "converged"))
	if err != nil {
		t.Fatalf("the converge did not write its file: %v\n%s", err, runOut)
	}
	if string(got) != "converged by policy" {
		t.Errorf("converged file = %q, want the policy's override", got)
	}
	motd, err := os.ReadFile(filepath.Join(out, "motd"))
	if err != nil {
		t.Fatalf("the dependency's template was not rendered: %v\n%s", err, runOut)
	}
	if string(motd) != "greeting=hello from pf_base 1.0.0\n" {
		t.Errorf("rendered template = %q", motd)
	}

	node := h.raw(t, "/nodes/policynode")
	if got := field(t, node, "policy_name"); got != "app" {
		t.Errorf("saved node policy_name = %v, want app", got)
	}
	if got := field(t, node, "policy_group"); got != "dev" {
		t.Errorf("saved node policy_group = %v, want dev", got)
	}
	if got := field(t, node, "automatic", "hostname"); got == "" || got == nil {
		t.Errorf("saved node has no automatic hostname")
	}
	if got := mustJSON(t, field(t, node, "automatic", "recipes")); !strings.Contains(got, "pf_app") {
		t.Errorf("saved node's automatic recipes = %s, want pf_app", got)
	}

	// knife node policy set moves the node to another group.
	h.run(t, "node", "policy", "set", "policynode", "prod", "app")
	node = h.raw(t, "/nodes/policynode")
	if got := field(t, node, "policy_group"); got != "prod" {
		t.Errorf("after node policy set, policy_group = %v, want prod", got)
	}
	if got := field(t, node, "policy_name"); got != "app" {
		t.Errorf("after node policy set, policy_name = %v, want app", got)
	}
}
