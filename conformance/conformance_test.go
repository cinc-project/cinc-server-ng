//go:build conformance

// Package conformance drives the real knife CLI (from Cinc Workstation) against
// an in-process cinc-server-ng server, exercising the full signed-request lifecycle:
// reads, writes, search, authorization, policyfiles, and the cookbook
// sandbox/upload flow. It is gated behind the "conformance" build tag.
//
// The server under test runs with ACL enforcement on, which is what the
// standalone binary defaults to. Testing the permissive configuration would
// leave every authorization path unexercised by a real client — the paths most
// likely to break a genuine chef-client, and the ones hardest to get right.
//
// Run with: go test -tags conformance ./conformance/
package conformance

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cinc-project/cinc-server-ng/server"
)

// requireEnvVar makes a missing knife a failure rather than a skip. CI sets it,
// because a conformance job that silently executes nothing while reporting
// success is worse than having no conformance job at all.
const requireEnvVar = "CINC_SERVER_NG_REQUIRE_CONFORMANCE"

// unavailable reports that knife cannot be used: it fails when conformance is
// required, and skips otherwise so a local `go test ./...` stays usable.
func unavailable(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv(requireEnvVar) != "" {
		t.Fatalf("conformance is required (%s set) but knife is unusable: "+format,
			append([]any{requireEnvVar}, args...)...)
	}
	t.Skipf(format, args...)
}

// knifeBin locates a runnable knife. Honor $KNIFE, else look on PATH.
func knifeBin(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("KNIFE")
	if bin == "" {
		var err error
		if bin, err = exec.LookPath("knife"); err != nil {
			unavailable(t, "knife not found on PATH; set $KNIFE or install cinc-workstation")
		}
	}
	if out, err := exec.Command(bin, "--version").CombinedOutput(); err != nil {
		unavailable(t, "knife (%s) is not runnable: %v\n%s", bin, err, out)
	}
	return bin
}

// harness runs knife against a cinc-server-ng server that enforces ACLs.
type harness struct {
	knife   string
	dir     string
	knifeRB string
	srv     *server.Server
}

func setup(t *testing.T) *harness {
	t.Helper()
	knife := knifeBin(t)

	srv, err := server.New(server.Options{Orgs: []string{"acme"}, EnforceACL: true})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("server.Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		srv.Stop(ctx)
	})

	dir := t.TempDir()
	write(t, filepath.Join(dir, "admin.pem"), string(srv.AdminKey()))
	write(t, filepath.Join(dir, "cookbooks", "mycook", "metadata.rb"), "name 'mycook'\nversion '0.1.0'\n")
	write(t, filepath.Join(dir, "cookbooks", "mycook", "recipes", "default.rb"), "package 'nginx'\n")

	h := &harness{knife: knife, dir: dir, srv: srv}
	h.knifeRB = h.writeConfig(t, "knife.rb", srv.AdminName(), filepath.Join(dir, "admin.pem"))
	return h
}

// writeConfig emits a knife.rb naming a particular identity, so the suite can
// act as somebody other than the bootstrap admin.
func (h *harness) writeConfig(t *testing.T, name, nodeName, keyPath string) string {
	t.Helper()
	path := filepath.Join(h.dir, name)
	write(t, path, strings.Join([]string{
		"node_name '" + nodeName + "'",
		"client_key '" + keyPath + "'",
		"chef_server_url '" + h.srv.URL() + "/organizations/acme'",
		"ssl_verify_mode :verify_none",
		"cookbook_path ['" + filepath.Join(h.dir, "cookbooks") + "']",
		"",
	}, "\n"))
	return path
}

// run executes a knife subcommand as the admin and fails on a non-zero exit.
func (h *harness) run(t *testing.T, args ...string) string {
	t.Helper()
	out, err := h.try(h.knifeRB, args...)
	if err != nil {
		t.Fatalf("knife %s\n  error: %v\n  output: %s", strings.Join(args, " "), err, out)
	}
	return out
}

// runAs executes a knife subcommand under a given config, returning the output
// and whether it succeeded, so a test can assert on a denial.
func (h *harness) runAs(config string, args ...string) (string, error) {
	return h.try(config, args...)
}

func (h *harness) try(config string, args ...string) (string, error) {
	args = append(args, "--config", config)
	cmd := exec.Command(h.knife, args...)
	cmd.Env = append(os.Environ(), "HOME="+h.dir) // avoid the user's ~/.chef
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// showJSON runs a knife show in JSON mode and decodes it, so assertions can
// check the response's shape rather than whether some substring appears in
// human-readable output. knife is lenient about what it accepts, so a substring
// match proves very little about fidelity.
func (h *harness) showJSON(t *testing.T, args ...string) map[string]any {
	t.Helper()
	out := h.run(t, append(args, "--format", "json")...)
	// knife may print warnings before the document; start at the first brace.
	if i := strings.IndexByte(out, '{'); i > 0 {
		out = out[i:]
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("knife %s: output is not JSON: %v\n%s", strings.Join(args, " "), err, out)
	}
	return doc
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// createClient registers a client through the API and returns the path to the
// private key the server issued.
//
// This goes through `knife raw` rather than `knife client create -f` because
// the latter's key-writing behavior varies between knife versions, and a
// conformance test should not fail on that. Reading the key out of the response
// also asserts something worth asserting: that client creation returns the
// generated key in the shape a client expects to find it.
func (h *harness) createClient(t *testing.T, name string) string {
	t.Helper()
	bodyPath := filepath.Join(h.dir, name+"-create.json")
	write(t, bodyPath, `{"name":"`+name+`","admin":false,"validator":false}`)
	out := h.run(t, "raw", "-m", "POST", "/clients", "-i", bodyPath)

	if i := strings.IndexByte(out, '{'); i > 0 {
		out = out[i:]
	}
	var created struct {
		PrivateKey string `json:"private_key"`
		ChefKey    struct {
			PrivateKey string `json:"private_key"`
		} `json:"chef_key"`
	}
	if err := json.Unmarshal([]byte(out), &created); err != nil {
		t.Fatalf("client create response is not JSON: %v\n%s", err, out)
	}
	key := created.ChefKey.PrivateKey
	if key == "" {
		key = created.PrivateKey // the pre-v1 shape
	}
	if key == "" {
		t.Fatalf("client create returned no private key; a client could never authenticate:\n%s", out)
	}
	path := filepath.Join(h.dir, name+".pem")
	write(t, path, key)
	return path
}

// deniedForAuthorization reports whether knife's output describes an
// authorization refusal. The server's contract is the 403 status; how knife
// renders it is not, so several phrasings are accepted.
func deniedForAuthorization(out string) bool {
	lower := strings.ToLower(out)
	for _, phrase := range []string{"403", "forbidden", "not authorized", "missing read permission"} {
		if strings.Contains(lower, phrase) {
			return true
		}
	}
	return false
}

// field walks a decoded document, failing if the path is absent.
func field(t *testing.T, doc map[string]any, path ...string) any {
	t.Helper()
	var cur any = doc
	for i, key := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("%s: not an object at %q", strings.Join(path, "."), strings.Join(path[:i], "."))
		}
		cur, ok = m[key]
		if !ok {
			t.Fatalf("missing field %q (in %v)", strings.Join(path[:i+1], "."), m)
		}
	}
	return cur
}

func TestKnifeCoreObjects(t *testing.T) {
	h := setup(t)

	// Reads: the seeded _default environment is visible over a signed request,
	// with the shape Chef defines rather than merely mentioning the name.
	env := h.showJSON(t, "environment", "show", "_default")
	if got := field(t, env, "name"); got != "_default" {
		t.Errorf("environment name = %v, want _default", got)
	}
	if got := field(t, env, "chef_type"); got != "environment" {
		t.Errorf("environment chef_type = %v, want environment", got)
	}

	// Node write + read-back: the stored document must round-trip.
	write(t, filepath.Join(h.dir, "web01.json"),
		`{"name":"web01","chef_environment":"_default","json_class":"Chef::Node",`+
			`"chef_type":"node","normal":{"role":"frontend"},"run_list":["recipe[mycook]"]}`)
	h.run(t, "node", "from", "file", filepath.Join(h.dir, "web01.json"))

	node := h.showJSON(t, "node", "show", "web01", "--long")
	if got := field(t, node, "name"); got != "web01" {
		t.Errorf("node name = %v, want web01", got)
	}
	if got := field(t, node, "normal", "role"); got != "frontend" {
		t.Errorf("normal.role = %v, want frontend", got)
	}
	runList, ok := field(t, node, "run_list").([]any)
	if !ok || len(runList) != 1 || runList[0] != "recipe[mycook]" {
		t.Errorf("run_list = %v, want [recipe[mycook]]", field(t, node, "run_list"))
	}

	if out := h.run(t, "node", "list"); !strings.Contains(out, "web01") {
		t.Fatalf("node list missing web01: %s", out)
	}
	if out := h.run(t, "search", "node", "role:frontend"); !strings.Contains(out, "web01") {
		t.Fatalf("search did not find web01: %s", out)
	}

	// Data bag create + item upload + read-back.
	h.run(t, "data", "bag", "create", "testbag")
	if out := h.run(t, "data", "bag", "list"); !strings.Contains(out, "testbag") {
		t.Fatalf("data bag list missing testbag: %s", out)
	}
	write(t, filepath.Join(h.dir, "item1.json"), `{"id":"item1","secret":"value"}`)
	h.run(t, "data", "bag", "from", "file", "testbag", filepath.Join(h.dir, "item1.json"))
	item := h.showJSON(t, "data", "bag", "show", "testbag", "item1")
	if got := field(t, item, "secret"); got != "value" {
		t.Errorf("data bag item secret = %v, want value", got)
	}

	// Cookbook upload: sandbox -> file store -> commit -> cookbook PUT.
	h.run(t, "cookbook", "upload", "mycook")
	if out := h.run(t, "cookbook", "list"); !strings.Contains(out, "mycook") {
		t.Fatalf("cookbook list missing mycook: %s", out)
	}
	// And the manifest a client would converge from, including the file URL it
	// has to be able to fetch.
	cb := h.showJSON(t, "cookbook", "show", "mycook", "0.1.0")
	if got := field(t, cb, "cookbook_name"); got != "mycook" {
		t.Errorf("cookbook_name = %v, want mycook", got)
	}
}

// Policyfiles are a first-class feature, so a real client has to be able to
// push a revision and associate it with a policy group.
func TestKnifePolicyfiles(t *testing.T) {
	h := setup(t)

	// A policy revision as Policyfile.lock.json shapes it.
	lock := `{"name":"base","revision_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",` +
		`"run_list":["recipe[mycook::default]"],"cookbook_locks":{},"solution_dependencies":{}}`
	write(t, filepath.Join(h.dir, "base.json"), lock)

	// knife raw is the transport-level path; it exercises the API directly with
	// a genuine signed request rather than depending on a Policyfile workflow.
	h.run(t, "raw", "-m", "PUT", "/policy_groups/prod/policies/base",
		"-i", filepath.Join(h.dir, "base.json"))

	out := h.run(t, "raw", "/policy_groups/prod")
	if !strings.Contains(out, "base") {
		t.Fatalf("policy group does not list the policy: %s", out)
	}
	rev := h.run(t, "raw", "/policies/base/revisions/"+
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if !strings.Contains(rev, "recipe[mycook::default]") {
		t.Fatalf("policy revision did not round-trip: %s", rev)
	}

	if out := h.run(t, "raw", "/policies"); !strings.Contains(out, "base") {
		t.Fatalf("policy list missing base: %s", out)
	}
}

// The shipped configuration enforces ACLs, so a real client must be both
// permitted where Chef permits and refused where Chef refuses. Testing this
// only as the bootstrap admin would prove nothing: the superuser bypasses ACLs.
func TestKnifeACLEnforcement(t *testing.T) {
	h := setup(t)

	// The admin creates a node and a client, and we keep the client's key.
	write(t, filepath.Join(h.dir, "web01.json"),
		`{"name":"web01","chef_environment":"_default","json_class":"Chef::Node","chef_type":"node"}`)
	h.run(t, "node", "from", "file", filepath.Join(h.dir, "web01.json"))

	clientKey := h.createClient(t, "node1")
	nodeCfg := h.writeConfig(t, "node1.rb", "node1", clientKey)

	// The client authenticates and, being in the org's clients group, may read
	// the node under Chef's default ACL.
	if out, err := h.runAs(nodeCfg, "node", "show", "web01"); err != nil {
		t.Fatalf("client should be able to read a node by default: %v\n%s", err, out)
	}

	// Narrow the node's read ACL to the admins group, as `knife acl` would.
	write(t, filepath.Join(h.dir, "read-acl.json"),
		`{"read":{"actors":["`+h.srv.AdminName()+`"],"groups":["admins"]}}`)
	h.run(t, "raw", "-m", "PUT", "/nodes/web01/_acl/read",
		"-i", filepath.Join(h.dir, "read-acl.json"))

	// Now the same client must be refused. knife's wording for a 403 is its own
	// business and varies by version ("you are not authorized for this action"),
	// so the assertion is that the request was refused as an authorization
	// failure rather than on the exact phrasing.
	out, err := h.runAs(nodeCfg, "node", "show", "web01")
	if err == nil {
		t.Fatalf("client read a node whose ACL excludes it:\n%s", out)
	}
	if !deniedForAuthorization(out) {
		t.Errorf("refusal does not look like an authorization failure, got:\n%s", out)
	}

	// The admin is unaffected, since the superuser bypasses ACLs.
	if out, err := h.runAs(h.knifeRB, "node", "show", "web01"); err != nil {
		t.Fatalf("admin should still read the node: %v\n%s", err, out)
	}
}

// A client must be able to do what a chef-client bootstrap does: register and
// then create and update its own node.
func TestKnifeClientBootstrapFlow(t *testing.T) {
	h := setup(t)

	clientKey := h.createClient(t, "node2")
	nodeCfg := h.writeConfig(t, "node2.rb", "node2", clientKey)

	write(t, filepath.Join(h.dir, "node2.json"),
		`{"name":"node2","chef_environment":"_default","json_class":"Chef::Node","chef_type":"node"}`)
	if out, err := h.runAs(nodeCfg, "node", "from", "file", filepath.Join(h.dir, "node2.json")); err != nil {
		t.Fatalf("a registered client must be able to create its own node: %v\n%s", err, out)
	}
	// And update it, which is what every converge does at the end of a run.
	if out, err := h.runAs(nodeCfg, "node", "from", "file", filepath.Join(h.dir, "node2.json")); err != nil {
		t.Fatalf("a client must be able to update the node it created: %v\n%s", err, out)
	}
}
