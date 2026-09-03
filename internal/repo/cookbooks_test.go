package repo

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/cinc-project/cinc-server-ng/internal/store"
)

func md5hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestLoadCookbookWithMetadataRB(t *testing.T) {
	dir := t.TempDir()
	recipe := "package 'apache2'\n"
	writeRepo(t, dir, map[string]string{
		"cookbooks/apache2/metadata.rb":        "name 'apache2'\nversion '1.2.3'\ndepends 'apt', '>= 2.0.0'\n",
		"cookbooks/apache2/recipes/default.rb": recipe,
		"cookbooks/apache2/README.md":          "# apache2\n",
	})

	st := store.New()
	org, _ := st.CreateOrg("acme")
	sum, err := Load(org, dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if sum.Counts["cookbooks"] != 1 {
		t.Fatalf("cookbook count = %+v", sum.Counts)
	}

	raw, ok, err := org.Get("cookbooks", "apache2/1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("cookbook apache2/1.2.3 not stored")
	}
	var m struct {
		CookbookName string `json:"cookbook_name"`
		Version      string `json:"version"`
		Metadata     struct {
			Dependencies map[string]string `json:"dependencies"`
		} `json:"metadata"`
		AllFiles []struct {
			Path     string `json:"path"`
			Checksum string `json:"checksum"`
		} `json:"all_files"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	if m.CookbookName != "apache2" || m.Version != "1.2.3" {
		t.Fatalf("manifest name/version = %s", raw)
	}
	if m.Metadata.Dependencies["apt"] != ">= 2.0.0" {
		t.Fatalf("dependencies not parsed: %s", raw)
	}
	// The recipe file is present and its content is in the blob store.
	var found bool
	for _, f := range m.AllFiles {
		if f.Path == "recipes/default.rb" {
			found = true
			if f.Checksum != md5hex(recipe) {
				t.Fatalf("recipe checksum = %s, want %s", f.Checksum, md5hex(recipe))
			}
			has, err := org.HasBlob(f.Checksum)
			if err != nil {
				t.Fatal(err)
			}
			if !has {
				t.Fatal("recipe content not in blob store")
			}
		}
	}
	if !found {
		t.Fatalf("recipes/default.rb not in all_files: %s", raw)
	}
}

func TestLoadCookbookParsesLicenseAndDescriptionFromRB(t *testing.T) {
	dir := t.TempDir()
	writeRepo(t, dir, map[string]string{
		"cookbooks/apache2/metadata.rb": "name 'apache2'\nversion '1.2.3'\nlicense 'Apache-2.0'\ndescription 'Installs and configures Apache'\n",
	})

	st := store.New()
	org, _ := st.CreateOrg("acme")
	if _, err := Load(org, dir); err != nil {
		t.Fatalf("Load: %v", err)
	}

	raw, ok, err := org.Get("cookbooks", "apache2/1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("cookbook apache2/1.2.3 not stored")
	}
	var m struct {
		Metadata struct {
			License     string `json:"license"`
			Description string `json:"description"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	if m.Metadata.License != "Apache-2.0" {
		t.Fatalf("license = %q, want Apache-2.0; manifest=%s", m.Metadata.License, raw)
	}
	if m.Metadata.Description != "Installs and configures Apache" {
		t.Fatalf("description = %q; manifest=%s", m.Metadata.Description, raw)
	}
}

func TestLoadCookbookParsesLicenseAndDescriptionFromJSON(t *testing.T) {
	dir := t.TempDir()
	writeRepo(t, dir, map[string]string{
		"cookbooks/nginx/metadata.json": `{"name":"nginx","version":"2.0.0","license":"MIT","description":"Installs NGINX"}`,
	})

	st := store.New()
	org, _ := st.CreateOrg("acme")
	if _, err := Load(org, dir); err != nil {
		t.Fatalf("Load: %v", err)
	}

	raw, ok, err := org.Get("cookbooks", "nginx/2.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("cookbook nginx/2.0.0 not stored")
	}
	var m struct {
		Metadata struct {
			License     string `json:"license"`
			Description string `json:"description"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	if m.Metadata.License != "MIT" {
		t.Fatalf("license = %q, want MIT; manifest=%s", m.Metadata.License, raw)
	}
	if m.Metadata.Description != "Installs NGINX" {
		t.Fatalf("description = %q; manifest=%s", m.Metadata.Description, raw)
	}
}

func TestLoadCookbookParsesMaintainerAndURLsFromRB(t *testing.T) {
	dir := t.TempDir()
	writeRepo(t, dir, map[string]string{
		"cookbooks/webserver/metadata.rb": "name 'webserver'\nversion '2.1.0'\n" +
			"maintainer 'Acme Infra'\nmaintainer_email 'infra@acme.test'\n" +
			"source_url 'https://github.com/acme/webserver'\n" +
			"issues_url 'https://github.com/acme/webserver/issues'\n",
	})

	st := store.New()
	org, _ := st.CreateOrg("acme")
	if _, err := Load(org, dir); err != nil {
		t.Fatalf("Load: %v", err)
	}

	raw, ok, err := org.Get("cookbooks", "webserver/2.1.0")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("cookbook webserver/2.1.0 not stored")
	}
	var m struct {
		Metadata struct {
			Maintainer      string `json:"maintainer"`
			MaintainerEmail string `json:"maintainer_email"`
			SourceURL       string `json:"source_url"`
			IssuesURL       string `json:"issues_url"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	if m.Metadata.Maintainer != "Acme Infra" {
		t.Errorf("maintainer = %q; manifest=%s", m.Metadata.Maintainer, raw)
	}
	if m.Metadata.MaintainerEmail != "infra@acme.test" {
		t.Errorf("maintainer_email = %q; manifest=%s", m.Metadata.MaintainerEmail, raw)
	}
	if m.Metadata.SourceURL != "https://github.com/acme/webserver" {
		t.Errorf("source_url = %q; manifest=%s", m.Metadata.SourceURL, raw)
	}
	if m.Metadata.IssuesURL != "https://github.com/acme/webserver/issues" {
		t.Errorf("issues_url = %q; manifest=%s", m.Metadata.IssuesURL, raw)
	}
}

func TestLoadCookbookParsesMaintainerAndURLsFromJSON(t *testing.T) {
	dir := t.TempDir()
	writeRepo(t, dir, map[string]string{
		"cookbooks/nginx/metadata.json": `{"name":"nginx","version":"2.0.0",` +
			`"maintainer":"Acme Infra","maintainer_email":"infra@acme.test",` +
			`"source_url":"https://github.com/acme/nginx",` +
			`"issues_url":"https://github.com/acme/nginx/issues"}`,
	})

	st := store.New()
	org, _ := st.CreateOrg("acme")
	if _, err := Load(org, dir); err != nil {
		t.Fatalf("Load: %v", err)
	}

	raw, ok, err := org.Get("cookbooks", "nginx/2.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("cookbook nginx/2.0.0 not stored")
	}
	var m struct {
		Metadata struct {
			Maintainer      string `json:"maintainer"`
			MaintainerEmail string `json:"maintainer_email"`
			SourceURL       string `json:"source_url"`
			IssuesURL       string `json:"issues_url"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	if m.Metadata.Maintainer != "Acme Infra" {
		t.Errorf("maintainer = %q; manifest=%s", m.Metadata.Maintainer, raw)
	}
	if m.Metadata.MaintainerEmail != "infra@acme.test" {
		t.Errorf("maintainer_email = %q; manifest=%s", m.Metadata.MaintainerEmail, raw)
	}
	if m.Metadata.SourceURL != "https://github.com/acme/nginx" {
		t.Errorf("source_url = %q; manifest=%s", m.Metadata.SourceURL, raw)
	}
	if m.Metadata.IssuesURL != "https://github.com/acme/nginx/issues" {
		t.Errorf("issues_url = %q; manifest=%s", m.Metadata.IssuesURL, raw)
	}
}

func TestLoadCookbookWithMetadataJSON(t *testing.T) {
	dir := t.TempDir()
	writeRepo(t, dir, map[string]string{
		"cookbooks/nginx/metadata.json":      `{"name":"nginx","version":"2.0.0","dependencies":{"openssl":">= 1.0"}}`,
		"cookbooks/nginx/recipes/default.rb": "package 'nginx'\n",
	})

	st := store.New()
	org, _ := st.CreateOrg("acme")
	if _, err := Load(org, dir); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !getOK(t, org, "cookbooks", "nginx/2.0.0") {
		t.Fatal("cookbook nginx/2.0.0 (from metadata.json) not stored")
	}
}

func TestLoadCookbookNameFallsBackToDir(t *testing.T) {
	dir := t.TempDir()
	// No metadata: name from directory, version defaults.
	writeRepo(t, dir, map[string]string{
		"cookbooks/legacy/recipes/default.rb": "puts 1\n",
	})
	st := store.New()
	org, _ := st.CreateOrg("acme")
	if _, err := Load(org, dir); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !getOK(t, org, "cookbooks", "legacy/0.0.0") {
		keys, err := org.Keys("cookbooks")
		if err != nil {
			t.Fatal(err)
		}
		t.Fatalf("cookbook keyed by dir name with default version not stored; keys=%v", keys)
	}
}
