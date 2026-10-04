//go:build conformance

package conformance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Some server-facing commands come with Cinc Workstation rather than with the
// knife and Policyfile CLI gems: knife tidy, and the cinc wrapper's report and
// capture. A test for one runs where the installed tool has the command and is
// skipped where it does not, which matches the coverage gate: it only asks for
// the commands the installed tools list.

var (
	knifeCommandList = sync.OnceValue(func() []string {
		bin, err := findTool("KNIFE", "knife")
		if err != nil {
			return nil
		}
		return knifeCommands(bin)
	})
	cliCommandList = sync.OnceValue(func() []string {
		bin, err := findTool("CINC_CLI", "cinc", "chef-cli", "chef")
		if err != nil {
			return nil
		}
		return cliCommands(bin)
	})
)

func requireKnifeCommand(t *testing.T, command string) {
	t.Helper()
	if !slices.Contains(knifeCommandList(), command) {
		t.Skipf("this knife has no %q command (it comes with Cinc Workstation)", command)
	}
}

func requireCLICommand(t *testing.T, command string) {
	t.Helper()
	if !slices.Contains(cliCommandList(), command) {
		t.Skipf("this Policyfile CLI has no %q command (it comes with Cinc Workstation)", command)
	}
}

// workstationFleet uploads three versions of mycook and creates two nodes: one
// that last checked in two months ago, and one that checked in just now and
// ran mycook 0.1.0.
func workstationFleet(t *testing.T, h *harness) {
	t.Helper()
	meta := filepath.Join(h.dir, "cookbooks", "mycook", "metadata.rb")
	for _, v := range []string{"0.1.0", "0.2.0", "0.3.0"} {
		write(t, meta, "name 'mycook'\nversion '"+v+"'\n")
		h.run(t, "cookbook", "upload", "mycook")
	}
	stale := time.Now().Add(-60 * 24 * time.Hour).Unix()
	now := time.Now().Unix()
	for name, doc := range map[string]string{
		"stale1": `{"name":"stale1","chef_environment":"_default","json_class":"Chef::Node","chef_type":"node",` +
			`"automatic":{"ohai_time":` + strconv.FormatInt(stale, 10) + `,"platform":"ubuntu","platform_version":"24.04",` +
			`"chef_packages":{"chef":{"version":"18.10.17"}}},"run_list":[]}`,
		"fresh1": `{"name":"fresh1","chef_environment":"_default","json_class":"Chef::Node","chef_type":"node",` +
			`"automatic":{"ohai_time":` + strconv.FormatInt(now, 10) + `,"platform":"ubuntu","platform_version":"24.04",` +
			`"chef_packages":{"chef":{"version":"18.10.17"}},"cookbooks":{"mycook":{"version":"0.1.0"}},` +
			`"recipes":["mycook::default"],"roles":[]},"run_list":["recipe[mycook]"]}`,
	} {
		path := filepath.Join(h.dir, name+".json")
		write(t, path, doc)
		h.run(t, "node", "from", "file", path)
	}
}

// knife tidy reports the stale nodes and unused cookbook versions of an org,
// and server clean deletes exactly what the report names. It works across
// orgs, so it runs as the superuser.
func TestKnifeTidyReportAndClean(t *testing.T) {
	t.Parallel()
	requireKnifeCommand(t, "tidy server report")
	h := setup(t)
	workstationFleet(t, h)

	h.runAs(t, h.superRB, "tidy", "server", "report", "--orgs", orgName, "--node-threshold", "30")

	reports := filepath.Join(h.dir, "reports")
	var stale struct {
		Count int      `json:"count"`
		List  []string `json:"list"`
	}
	readJSON(t, filepath.Join(reports, orgName+"_stale_nodes.json"), &stale)
	if !slices.Equal(stale.List, []string{"stale1"}) || stale.Count != 1 {
		t.Errorf("stale nodes = %+v, want just stale1", stale)
	}
	var unused map[string][]string
	readJSON(t, filepath.Join(reports, orgName+"_unused_cookbooks.json"), &unused)
	// 0.1.0 is in use, and the newest version is always kept.
	if got := unused["mycook"]; !slices.Equal(got, []string{"0.2.0"}) {
		t.Errorf("unused mycook versions = %v, want [0.2.0]", got)
	}

	// tidy refuses to delete anything without a backup to restore from; the
	// directory only has to exist for this.
	h.runAs(t, h.superRB, "tidy", "server", "clean", "--orgs", orgName, "--backup-path", t.TempDir())

	versions := cookbookVersions(t, h, "mycook")
	if !slices.Equal(versions, []string{"0.1.0", "0.3.0"}) {
		t.Errorf("mycook versions after clean = %v, want [0.1.0 0.3.0]", versions)
	}
	nodes := h.raw(t, "/nodes")
	if _, ok := nodes["stale1"]; ok {
		t.Error("the stale node survived tidy server clean")
	}
	if _, ok := nodes["fresh1"]; !ok {
		t.Error("tidy server clean deleted a node that checked in just now")
	}
}

// cinc report reads nodes (through search) and cookbooks (downloading and
// analyzing each one) from the server.
func TestWorkstationReport(t *testing.T) {
	t.Parallel()
	requireCLICommand(t, "report")
	h := setup(t)
	workstationFleet(t, h)
	workstationCredentials(t, h)

	// The summary goes to stdout; the full report to a CSV file.
	out := h.cli(t, h.dir, "report", "nodes", "-f", "csv")
	nodes := workstationReport(t, h, "nodes-")
	for _, want := range []string{"fresh1", "stale1", "ubuntu", "mycook"} {
		if !strings.Contains(nodes, want) {
			t.Errorf("node report lacks %q:\n%s\n%s", want, nodes, out)
		}
	}
	// Only fresh1 ran a cookbook, and only 0.1.0 of it.
	out = h.cli(t, h.dir, "report", "cookbooks", "-f", "csv")
	cookbooks := workstationReport(t, h, "cookbooks-")
	if !strings.Contains(cookbooks, "mycook") || !strings.Contains(cookbooks, "0.1.0") {
		t.Errorf("cookbook report lacks mycook 0.1.0:\n%s\n%s", cookbooks, out)
	}
}

// workstationReport returns the CSV report the cinc report command just wrote.
func workstationReport(t *testing.T, h *harness, prefix string) string {
	t.Helper()
	matches, _ := filepath.Glob(filepath.Join(h.dir, ".chef-workstation", "reports", prefix+"*.csv"))
	if len(matches) != 1 {
		t.Fatalf("want one %s*.csv report, found %v", prefix, matches)
	}
	data, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// cinc capture copies a node, and what converging it needs, from the server
// into a local repository.
func TestWorkstationCapture(t *testing.T) {
	t.Parallel()
	requireCLICommand(t, "capture")
	h := setup(t)
	workstationFleet(t, h)

	workstationCredentials(t, h)
	out := h.cli(t, h.dir, "capture", "fresh1")
	repo := filepath.Join(h.dir, "node-fresh1-repo")
	var node map[string]any
	readJSON(t, filepath.Join(repo, "nodes", "fresh1.json"), &node)
	if node["name"] != "fresh1" {
		t.Errorf("captured node = %v\n%s", node, out)
	}
	if _, err := os.Stat(filepath.Join(repo, "cookbooks", "mycook", "metadata.rb")); err != nil {
		t.Errorf("captured repo lacks the node's cookbook: %v\n%s", err, out)
	}
}

// workstationCredentials writes alice's knife profile to ~/.chef/credentials
// (the harness's HOME), which report and capture read: unlike knife, they
// insist on a credentials file even when given the server and key as flags.
func workstationCredentials(t *testing.T, h *harness) {
	t.Helper()
	write(t, filepath.Join(h.dir, ".chef", "credentials"), "[default]\n"+
		"client_name = \""+userName+"\"\n"+
		"client_key = \""+filepath.Join(h.dir, userName+".pem")+"\"\n"+
		"chef_server_url = \""+h.srv.URL()+"/organizations/"+orgName+"\"\n")
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("%s: %v\n%s", path, err, data)
	}
}

// cookbookVersions lists a cookbook's versions on the server, ascending.
func cookbookVersions(t *testing.T, h *harness, name string) []string {
	t.Helper()
	doc := h.raw(t, "/cookbooks/"+name)
	entry, _ := doc[name].(map[string]any)
	list, _ := entry["versions"].([]any)
	var versions []string
	for _, v := range list {
		if m, ok := v.(map[string]any); ok {
			if s, ok := m["version"].(string); ok {
				versions = append(versions, s)
			}
		}
	}
	slices.Sort(versions)
	return versions
}
