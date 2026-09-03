package repo

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// getOK reports whether (coll,key) exists, failing the test on a store error.
func getOK(t *testing.T, org *store.Org, coll, key string) bool {
	t.Helper()
	_, ok, err := org.Get(coll, key)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

// writeRepo lays out a small chef-repo under dir.
func writeRepo(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for rel, content := range files {
		path := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	writeRepo(t, dir, map[string]string{
		"nodes/web01.json":           `{"name":"web01","chef_environment":"prod"}`,
		"roles/web.json":             `{"name":"web","run_list":["recipe[nginx]"]}`,
		"environments/prod.json":     `{"name":"prod"}`,
		"clients/builder.json":       `{"name":"builder"}`,
		"policies/base-1.0.0.json":   `{"name":"base","revision_id":"1.0.0"}`,
		"policy_groups/prod.json":    `{"policies":{"base":{"revision_id":"1.0.0"}}}`,
		"data_bags/users/alice.json": `{"id":"alice","admin":true}`,
		"data_bags/users/bob.json":   `{"id":"bob"}`,
		"data_bags/secrets/key.json": `{"id":"key"}`,
		"unrelated/ignore.txt":       `not json, not in a known dir`,
	})

	st := store.New()
	org, _ := st.CreateOrg("acme")
	sum, err := Load(org, dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if !getOK(t, org, "nodes", "web01") {
		t.Fatal("node web01 not loaded")
	}
	if !getOK(t, org, "roles", "web") {
		t.Fatal("role web not loaded")
	}
	if !getOK(t, org, "environments", "prod") {
		t.Fatal("environment prod not loaded")
	}
	if !getOK(t, org, "clients", "builder") {
		t.Fatal("client builder not loaded")
	}
	// Policy locks load as revisions, keyed by revision_id, exactly where the
	// policy API reads them — not into a dead "policies" collection.
	if !getOK(t, org, "policy_revisions:base", "1.0.0") {
		t.Fatal("policy revision base/1.0.0 not loaded")
	}
	if !getOK(t, org, "policy_groups", "prod") {
		t.Fatal("policy group prod not loaded")
	}
	// Data bags register the bag and store items in the bag's item collection.
	if !getOK(t, org, "data_bags", "users") {
		t.Fatal("data bag users not registered")
	}
	if !getOK(t, org, "databag_items:users", "alice") {
		t.Fatal("data bag item alice not loaded")
	}
	if !getOK(t, org, "databag_items:secrets", "key") {
		t.Fatal("data bag item key not loaded")
	}

	if sum.Counts["nodes"] != 1 || sum.Counts["data_bag_items"] != 3 || sum.Counts["policy_revisions"] != 1 {
		t.Fatalf("summary counts = %+v", sum.Counts)
	}
}

// TestLoadPolicyRevisions loads several policy locks, including two revisions
// of the same policy, and confirms each lands under its policy's revision
// collection keyed by revision_id.
func TestLoadPolicyRevisions(t *testing.T) {
	dir := t.TempDir()
	writeRepo(t, dir, map[string]string{
		"policies/appserver-1.0.0.json": `{"name":"appserver","revision_id":"1.0.0","run_list":["recipe[appserver::default]"]}`,
		"policies/appserver-1.1.0.json": `{"name":"appserver","revision_id":"1.1.0","run_list":["recipe[appserver::default]"]}`,
		"policies/web-2.0.0.json":       `{"name":"web","revision_id":"2.0.0"}`,
	})

	st := store.New()
	org, _ := st.CreateOrg("acme")
	sum, err := Load(org, dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	for _, rev := range []string{"1.0.0", "1.1.0"} {
		if !getOK(t, org, "policy_revisions:appserver", rev) {
			t.Errorf("appserver revision %s not loaded", rev)
		}
	}
	if !getOK(t, org, "policy_revisions:web", "2.0.0") {
		t.Error("web revision 2.0.0 not loaded")
	}
	if sum.Counts["policy_revisions"] != 3 {
		t.Errorf("policy_revisions count = %d, want 3", sum.Counts["policy_revisions"])
	}
}

// TestLoadPolicyMissingRevisionID rejects a policy lock that omits the
// revision_id the policy API keys revisions by.
func TestLoadPolicyMissingRevisionID(t *testing.T) {
	dir := t.TempDir()
	writeRepo(t, dir, map[string]string{"policies/broken.json": `{"name":"broken"}`})

	st := store.New()
	org, _ := st.CreateOrg("acme")
	if _, err := Load(org, dir); err == nil {
		t.Fatal("expected an error for a policy lock without revision_id")
	}
}

func TestLoadEmptyOrMissing(t *testing.T) {
	st := store.New()
	org, _ := st.CreateOrg("acme")

	// A non-existent repo path is not an error; it just loads nothing.
	sum, err := Load(org, filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatalf("Load(missing): %v", err)
	}
	if len(sum.Counts) != 0 {
		t.Fatalf("expected no counts, got %+v", sum.Counts)
	}
}

func TestLoadNameFallsBackToFilename(t *testing.T) {
	dir := t.TempDir()
	// No "name" field: the filename (sans .json) is used as the key.
	writeRepo(t, dir, map[string]string{"nodes/fromfile.json": `{"chef_environment":"prod"}`})

	st := store.New()
	org, _ := st.CreateOrg("acme")
	if _, err := Load(org, dir); err != nil {
		t.Fatal(err)
	}
	if !getOK(t, org, "nodes", "fromfile") {
		t.Fatal("node keyed by filename not loaded")
	}
}
