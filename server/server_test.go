package server

import (
	"context"
	"crypto/md5"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tas50/cinc-server-ng/internal/auth"
)

// putUser writes a global user with the given public key directly into the
// store and returns the matching PEM-encoded private key for signing.
func putUser(t *testing.T, srv *Server, name string, key *rsa.PrivateKey) []byte {
	t.Helper()
	pubPEM, err := auth.EncodePublicKeyPEM(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	doc := fmt.Sprintf(`{"username":%q,"public_key":%q}`, name, string(pubPEM))
	if err := srv.Store().Global().Put("users", name, []byte(doc)); err != nil {
		t.Fatal(err)
	}
	return auth.EncodePrivateKeyPEM(key)
}

// TestKeyRotationReauthenticates verifies that rotating an actor's public key
// takes effect immediately: requests signed with the old key are rejected and
// the new key is accepted. This guards the public-key cache against serving a
// stale key after rotation.
func TestKeyRotationReauthenticates(t *testing.T) {
	srv := startServer(t, Options{})
	url := srv.URL() + "/organizations/acme/nodes"

	keyA, _ := auth.GenerateKey()
	pemA := putUser(t, srv, "alice", keyA)

	if code := statusOf(t, signedAs(t, "alice", pemA, "GET", url, "")); code != http.StatusOK {
		t.Fatalf("initial auth with key A = %d, want 200", code)
	}

	// Rotate alice's key to B.
	keyB, _ := auth.GenerateKey()
	pemB := putUser(t, srv, "alice", keyB)

	if code := statusOf(t, signedAs(t, "alice", pemA, "GET", url, "")); code != http.StatusUnauthorized {
		t.Fatalf("auth with stale key A after rotation = %d, want 401", code)
	}
	if code := statusOf(t, signedAs(t, "alice", pemB, "GET", url, "")); code != http.StatusOK {
		t.Fatalf("auth with rotated key B = %d, want 200", code)
	}
}

func startServer(t *testing.T, opts Options) *Server {
	t.Helper()
	srv, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		srv.Stop(ctx)
	})
	return srv
}

// writeRepoFiles lays out a chef-repo under dir from a rel-path -> contents map.
func writeRepoFiles(t *testing.T, dir string, files map[string]string) {
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

// getBody GETs url and returns the response body, failing on a non-200.
func getBody(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("GET %s = %d: %s", url, resp.StatusCode, body)
	}
	return string(body)
}

// signed builds a request signed with the server's admin key.
func signed(t *testing.T, srv *Server, method, url, body string) *http.Request {
	t.Helper()
	key, err := auth.ParsePrivateKey(srv.AdminKey())
	if err != nil {
		t.Fatalf("parse admin key: %v", err)
	}
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Ops-Server-API-Version", "1")
	ts := time.Now().UTC().Format(time.RFC3339)
	if err := auth.SignRequest(req, srv.AdminName(), ts, []byte(body), key); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return req
}

func TestServerStatusUnauthenticated(t *testing.T) {
	srv := startServer(t, Options{})
	resp, err := http.Get(srv.URL() + "/_status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("_status without auth = %d", resp.StatusCode)
	}
}

func TestServerRejectsUnsignedRequest(t *testing.T) {
	srv := startServer(t, Options{})
	resp, err := http.Get(srv.URL() + "/organizations/acme/nodes")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("unsigned request = %d, want 401", resp.StatusCode)
	}
}

func TestServerAcceptsSignedRequestEndToEnd(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}})
	base := srv.URL() + "/organizations/acme"

	// Create a node with a signed request.
	req := signed(t, srv, "POST", base+"/nodes", `{"name":"web01"}`)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Fatalf("signed create = %d", resp.StatusCode)
	}

	// Read it back, signed.
	req = signed(t, srv, "GET", base+"/nodes/web01", "")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("signed get = %d: %s", resp.StatusCode, b)
	}
}

func TestServerRejectsStaleTimestamp(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}})
	key, _ := auth.ParsePrivateKey(srv.AdminKey())
	req, _ := http.NewRequest("GET", srv.URL()+"/organizations/acme/nodes", nil)
	req.Header.Set("X-Ops-Server-API-Version", "1")
	// Timestamp far outside the allowed skew.
	stale := time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339)
	auth.SignRequest(req, srv.AdminName(), stale, nil, key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("stale timestamp = %d, want 401", resp.StatusCode)
	}
}

func TestDisableAuthAllowsUnsigned(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, DisableAuth: true})
	resp, err := http.Get(srv.URL() + "/organizations/acme/nodes")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("DisableAuth unsigned = %d, want 200", resp.StatusCode)
	}
}

func TestServerLoadsRepo(t *testing.T) {
	dir := t.TempDir()
	nodes := filepath.Join(dir, "nodes")
	if err := os.MkdirAll(nodes, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nodes, "web01.json"),
		[]byte(`{"name":"web01","chef_environment":"prod"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	srv := startServer(t, Options{Orgs: []string{"acme"}, DisableAuth: true, Repo: dir})

	resp, err := http.Get(srv.URL() + "/organizations/acme/nodes/web01")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("loaded node GET = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "prod") {
		t.Fatalf("loaded node body = %s", body)
	}
}

// TestServerLoadsPolicyRepo proves that a policy lock and policy group loaded
// from a chef-repo are visible through the policy API — the read path keys
// revisions by "policy_revisions:<name>", so a loader that stored them anywhere
// else would leave `GET /policies` empty.
func TestServerLoadsPolicyRepo(t *testing.T) {
	dir := t.TempDir()
	writeRepoFiles(t, dir, map[string]string{
		"policies/appserver-1.0.0.json": `{"name":"appserver","revision_id":"1.0.0","run_list":["recipe[appserver::default]"]}`,
		"policy_groups/prod.json":       `{"policies":{"appserver":{"revision_id":"1.0.0"}}}`,
	})

	srv := startServer(t, Options{Orgs: []string{"acme"}, DisableAuth: true, Repo: dir})

	if body := getBody(t, srv.URL()+"/organizations/acme/policies"); !strings.Contains(body, "appserver") || !strings.Contains(body, "1.0.0") {
		t.Fatalf("GET /policies = %s, want the loaded appserver/1.0.0", body)
	}
	if body := getBody(t, srv.URL()+"/organizations/acme/policy_groups/prod"); !strings.Contains(body, "appserver") || !strings.Contains(body, "1.0.0") {
		t.Fatalf("GET /policy_groups/prod = %s, want the appserver pin", body)
	}
	// The group's pinned revision resolves to the loaded lock.
	if body := getBody(t, srv.URL()+"/organizations/acme/policy_groups/prod/policies/appserver"); !strings.Contains(body, "appserver::default") {
		t.Fatalf("GET pinned policy = %s, want the run_list from the loaded lock", body)
	}
}

func TestServerLoadsCookbookRepo(t *testing.T) {
	dir := t.TempDir()
	cb := filepath.Join(dir, "cookbooks", "apache2", "recipes")
	if err := os.MkdirAll(cb, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cookbooks", "apache2", "metadata.rb"),
		[]byte("name 'apache2'\nversion '1.0.0'\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cb, "default.rb"), []byte("package 'apache2'\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	srv := startServer(t, Options{Orgs: []string{"acme"}, DisableAuth: true, Repo: dir})

	// The loaded cookbook is served with a download URL injected per file.
	resp, err := http.Get(srv.URL() + "/organizations/acme/cookbooks/apache2/1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("loaded cookbook GET = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "recipes/default.rb") || !strings.Contains(string(body), "/file_store/") {
		t.Fatalf("cookbook manifest missing file or url: %s", body)
	}
}

func TestFileStorePathSkipsMixlibSigning(t *testing.T) {
	// The cookbook file store must accept requests that carry no Mixlib
	// signature (real Chef hands out pre-signed bookshelf URLs, which clients
	// use unsigned). Authorization rides on the URL instead, so the transfer
	// works with the grant the server issued and nothing else.
	srv := startServer(t, Options{Orgs: []string{"acme"}})

	content := "package 'nginx'\n"
	sum := md5.Sum([]byte(content))
	checksum := hex.EncodeToString(sum[:])

	// Unsigned PUT to the granted upload URL is accepted.
	req, _ := http.NewRequest("PUT", sandboxUploadURL(t, srv, checksum), strings.NewReader(content))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("granted file_store PUT = %d, want 200", resp.StatusCode)
	}

	// Unsigned GET at the granted download URL serves it back.
	resp, err = http.Get(grantedDownloadURL(t, srv, "acme", checksum))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != content {
		t.Fatalf("granted file_store GET = %d %q", resp.StatusCode, body)
	}

	// A non-file_store path still requires auth.
	resp, err = http.Get(srv.URL() + "/organizations/acme/nodes")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("unsigned nodes GET = %d, want 401", resp.StatusCode)
	}
}
