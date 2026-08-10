package state

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/tas50/cinc-server-ng/internal/api"
	"github.com/tas50/cinc-server-ng/internal/store"
)

// writeState writes a set of relative path -> contents files under root,
// creating parent directories as needed.
func writeState(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, content := range files {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
}

// TestLoadGlobalUsers verifies users under users/ land in the global space,
// which --repo cannot express.
func TestLoadGlobalUsers(t *testing.T) {
	dir := t.TempDir()
	writeState(t, dir, map[string]string{
		"users/anna.json": `{"username":"anna","display_name":"Anna Example"}`,
		"users/ben.json":  `{"username":"ben"}`,
	})

	st := store.New()
	sum, err := Load(st, dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if sum.Users != 2 {
		t.Fatalf("Users = %d, want 2", sum.Users)
	}
	if _, ok := mustGet(t, st.Global(), "users", "anna"); !ok {
		t.Error("user anna not stored in global space")
	}
	if _, ok := mustGet(t, st.Global(), "users", "ben"); !ok {
		t.Error("user ben not stored in global space")
	}
}

// TestLoadCreatesOrgAndChefObjects verifies an org under organizations/ is
// created (with its _default environment) and its chef-objects are loaded via
// the existing repo loader.
func TestLoadCreatesOrgAndChefObjects(t *testing.T) {
	dir := t.TempDir()
	writeState(t, dir, map[string]string{
		"organizations/acme/nodes/web01.json":             `{"name":"web01","chef_environment":"production"}`,
		"organizations/acme/roles/web.json":               `{"name":"web"}`,
		"organizations/acme/environments/production.json": `{"name":"production"}`,
	})

	st := store.New()
	if _, err := Load(st, dir); err != nil {
		t.Fatalf("Load: %v", err)
	}

	org, ok, err := st.Org("acme")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("org acme was not created")
	}
	for coll, key := range map[string]string{
		"nodes":        "web01",
		"roles":        "web",
		"environments": "production",
	} {
		if _, ok := mustGet(t, org, coll, key); !ok {
			t.Errorf("%s/%s not loaded", coll, key)
		}
	}
	// CreateOrganization seeds the _default environment.
	if _, ok := mustGet(t, org, "environments", "_default"); !ok {
		t.Error("_default environment not seeded for created org")
	}
}

// TestLoadGroups verifies authz groups under groups/ load into the org's
// groups collection — another thing --repo cannot express.
func TestLoadGroups(t *testing.T) {
	dir := t.TempDir()
	writeState(t, dir, map[string]string{
		"organizations/acme/groups/devs.json": `{"groupname":"devs","actors":{"users":["anna"],"groups":[],"clients":[]}}`,
	})

	st := store.New()
	if _, err := Load(st, dir); err != nil {
		t.Fatalf("Load: %v", err)
	}
	org, _, err := st.Org("acme")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := mustGet(t, org, "groups", "devs"); !ok {
		t.Error("group devs not loaded")
	}
}

// TestLoadIntoExistingOrg verifies Load is idempotent about org existence: an
// org already created by server bootstrap is loaded into, not recreated.
func TestLoadIntoExistingOrg(t *testing.T) {
	dir := t.TempDir()
	writeState(t, dir, map[string]string{
		"organizations/acme/nodes/db01.json": `{"name":"db01"}`,
	})

	st := store.New()
	if _, err := api.CreateOrganization(st, "acme", "acme"); err != nil {
		t.Fatalf("pre-create org: %v", err)
	}

	if _, err := Load(st, dir); err != nil {
		t.Fatalf("Load into existing org: %v", err)
	}
	org, _, err := st.Org("acme")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := mustGet(t, org, "nodes", "db01"); !ok {
		t.Error("node db01 not loaded into pre-existing org")
	}
}

// TestLoadMultipleOrgs verifies each org under organizations/ is hydrated
// independently.
func TestLoadMultipleOrgs(t *testing.T) {
	dir := t.TempDir()
	writeState(t, dir, map[string]string{
		"organizations/acme/nodes/a.json":  `{"name":"a"}`,
		"organizations/other/nodes/b.json": `{"name":"b"}`,
	})

	st := store.New()
	if _, err := Load(st, dir); err != nil {
		t.Fatalf("Load: %v", err)
	}
	acme, ok, err := st.Org("acme")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("org acme missing")
	}
	other, ok, err := st.Org("other")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("org other missing")
	}
	if _, ok := mustGet(t, acme, "nodes", "a"); !ok {
		t.Error("acme node a missing")
	}
	if _, ok := mustGet(t, other, "nodes", "b"); !ok {
		t.Error("other node b missing")
	}
}

// TestLoadEmptyDirIsNoop verifies a directory with no users/ or organizations/
// loads nothing and does not error.
func TestLoadEmptyDirIsNoop(t *testing.T) {
	st := store.New()
	sum, err := Load(st, t.TempDir())
	if err != nil {
		t.Fatalf("Load empty dir: %v", err)
	}
	if sum.Users != 0 || len(sum.Orgs) != 0 {
		t.Fatalf("expected empty summary, got %+v", sum)
	}
}
