// Command seedgen generates the large synthetic "real business" expansion of the
// dev fixture for the fictional company ACME: ~1000 realistically-named nodes
// across many functional tiers, the roles and cookbooks those nodes run, extra
// environments, and richer apps/secrets/users data bags. It writes them as an
// additive cinc-server-ng "--state" tree (default dev/seed.gen, git-ignored) that
// `make dev-db` bakes on top of the committed base seed.
//
// Output is deterministic: every value derives from a fixed RNG seed or from the
// object's own name, so re-running produces byte-identical files. Node
// "automatic" attributes are cloned from the committed base nodes' real fauxhai
// dumps, one template per platform, then stamped with per-node identity.
//
// This is a development tool; it is not built into the cinc-server-ng binary.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"hash/fnv"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
)

// baseOhaiTime is a fixed reference check-in (~2026-06-28 12:00 UTC) so generated
// ohai_time values are recent but reproducible rather than relative to "now".
const baseOhaiTime = 1782648000.0

const currentClientVersion = "19.3.14"

// olderVersions is the spread of lagging releases a minority of the fleet runs.
var olderVersions = []string{"13.12.14", "14.15.6", "15.10.12", "16.18.30", "17.10.95", "18.4.12"}

// dataCenters are short airport-style site codes, the way real fleets name
// machines (web-iad-014, db-fra-003).
var dataCenters = []string{"iad", "dfw", "pdx", "lhr", "fra", "nrt"}

// envWeights assigns environments with a realistic production-heavy split across
// the base environments (production/staging/development) and the generated
// qa/dr environments.
var envWeights = []string{
	"production", "production", "production", "production", "production", "production", "production", "production",
	"staging", "staging", "staging",
	"development", "development",
	"qa", "qa",
	"dr",
}

// serverType is one functional class of machine: the hostname prefix, the Chef
// role its run-list applies (which doubles as the role name), how many to make,
// whether it runs Windows, and — for roles not already in the base seed — a
// description so seedgen can generate the role too.
type serverType struct {
	prefix  string
	role    string
	count   int
	windows bool
	newRole bool
	desc    string
}

// The fleet uses realistic web-scale proportions: lots of web/app/workers, fewer
// databases, and only a handful of bastions, DNS, and domain controllers — not
// hundreds. Roles already in the base seed (web, app, database, cache,
// loadbalancer, monitoring, ci) are reused; the rest are generated. Counts sum
// to exactly 1000.
var serverTypes = []serverType{
	{"web", "web", 206, false, false, ""},
	{"app", "app", 187, false, false, ""},
	{"api", "api", 120, false, true, "Public API gateway server"},
	{"worker", "worker", 110, false, true, "Background job / async worker"},
	{"db", "database", 70, false, false, ""},
	{"cache", "cache", 60, false, false, ""},
	{"queue", "queue", 40, false, true, "Message queue broker"},
	{"search", "search", 35, false, true, "Search index server"},
	{"proxy", "proxy", 30, false, true, "Edge reverse proxy"},
	{"ci", "ci", 26, false, false, ""},
	{"lb", "loadbalancer", 24, false, false, ""},
	{"log", "logging", 20, false, true, "Log aggregation server"},
	{"monitor", "monitoring", 16, false, false, ""},
	{"storage", "storage", 14, false, true, "Network storage / NFS server"},
	{"dns", "dns", 8, false, true, "DNS resolver"},
	{"backup", "backup", 8, false, true, "Backup server"},
	{"dc", "domain_controller", 8, true, true, "Windows Active Directory domain controller"},
	{"mail", "mail", 6, false, true, "SMTP relay"},
	{"bastion", "bastion", 6, false, true, "SSH bastion / jump host"},
	{"vault", "vault", 6, false, true, "Secrets management server"},
}

// newRoleCookbook maps each generated role to the cookbook its run-list installs,
// so the fleet's roles and cookbooks form a coherent set.
var newRoleCookbook = map[string]string{
	"api":               "gateway",
	"worker":            "sidekiq",
	"queue":             "rabbitmq",
	"search":            "elasticsearch",
	"proxy":             "envoy",
	"logging":           "fluentd",
	"storage":           "nfs",
	"dns":               "bind",
	"mail":              "postfix",
	"vault":             "vault",
	"backup":            "restic",
	"bastion":           "openssh",
	"domain_controller": "active_directory",
}

// fillerKey is a single committed RSA public key shared by every generated filler
// user. They populate the org's user list but never authenticate or get
// webui-impersonated, so a shared key keeps generation deterministic (Go's
// rsa.GenerateKey is deliberately non-deterministic) while staying valid-looking.
const fillerKey = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAi4rjrKAVDLSwrPSKvVxJ\n8z7cXEQYTVb2wlJJcmMc9lFISVGHiUnX6Z7E758FFMs8o7DGb09w6lTLANPQzNec\n/FRQiBRAQ1+UeFDIBhvvjKSijyJUX+TmVntJdcq0cdeLw/9ySccA9RT2/X5aZGNF\nLXEai7wMH379IL62RruZ9PBWRgpeiUM3lyiltBkKKkE3wd9GVpMftTdxgykbYRFL\nDnaTGeS9aZK6DrxmIcUEBzTnrUca/dTaCw8o5eJGrhxBMuhAi3Y4ApB4xt7vLwNC\nVpXZdqBWWESTXo8OeSW4XKV9fGS+bL1jkjf+a0WYJN8HoRCRb79+2M7KQSg15cDL\n6wIDAQAB\n-----END PUBLIC KEY-----"

func main() {
	base := flag.String("base", "dev/test-repo", "committed base state dir to harvest node templates from")
	out := flag.String("out", "dev/seed.gen", "output state dir for the generated expansion")
	flag.Parse()

	linux, windows, err := harvestTemplates(filepath.Join(*base, "organizations", "acme", "nodes"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "harvest:", err)
		os.Exit(1)
	}
	if len(linux) == 0 || len(windows) == 0 {
		fmt.Fprintf(os.Stderr, "need at least one Linux and one Windows template (got %d/%d)\n", len(linux), len(windows))
		os.Exit(1)
	}

	g := generate(linux, windows, rand.New(rand.NewSource(1)))
	if err := g.write(*out); err != nil {
		fmt.Fprintln(os.Stderr, "write:", err)
		os.Exit(1)
	}
	fmt.Printf("seedgen wrote %d nodes, %d roles, %d cookbooks, %d environments, %d users, %d apps, %d secrets to %s\n",
		len(g.nodes), len(g.roles), len(g.cookbooks), len(g.envs), len(g.users), len(g.apps), len(g.secrets), *out)
}

// cookbook is a minimal generated cookbook: a version, description, and one
// default recipe.
type cookbook struct {
	version     string
	description string
	recipe      string
}

// genResult holds everything seedgen produces, keyed for deterministic output.
type genResult struct {
	nodes     map[string]map[string]any // name -> node object
	users     []map[string]any          // user records (have "username")
	apps      map[string]map[string]any // data bag item id -> item
	secrets   map[string]map[string]any
	roles     map[string]map[string]any // role name -> role object
	envs      map[string]map[string]any // env name -> environment object
	cookbooks map[string]cookbook       // cookbook name -> cookbook
}

func generate(linux, windows []map[string]any, rng *rand.Rand) genResult {
	g := genResult{
		nodes:     map[string]map[string]any{},
		users:     genUsers(),
		apps:      genApps(rng),
		secrets:   genSecrets(rng),
		roles:     genRoles(),
		envs:      genEnvironments(),
		cookbooks: genCookbooks(),
	}
	idx := 0
	for _, st := range serverTypes {
		pool := linux
		if st.windows {
			pool = windows
		}
		dcCount := map[string]int{}
		for n := 1; n <= st.count; n++ {
			dc := dataCenters[(n-1)%len(dataCenters)]
			dcCount[dc]++
			name := fmt.Sprintf("%s-%s-%03d", st.prefix, dc, dcCount[dc])
			g.nodes[name] = makeNode(name, st.role, pool, idx, rng)
			idx++
		}
	}
	return g
}

// makeNode clones a platform template and stamps per-node identity, environment,
// run-list, address, check-in time, and client version onto the copy.
func makeNode(name, role string, pool []map[string]any, idx int, rng *rand.Rand) map[string]any {
	automatic := deepCopy(pool[rng.Intn(len(pool))])

	automatic["fqdn"] = name + ".acme.example.com"
	automatic["hostname"] = name
	automatic["machinename"] = name
	automatic["ipaddress"] = fmt.Sprintf("10.1.%d.%d", idx/254, idx%254+1)
	automatic["macaddress"] = fmt.Sprintf("52:54:01:%02x:%02x:%02x", (idx>>16)&0xff, (idx>>8)&0xff, idx&0xff)
	automatic["ohai_time"] = baseOhaiTime - float64(nameHash(name)%3600)

	version := currentClientVersion
	if rng.Intn(100) < 12 { // ~12% of the fleet lags on an older release.
		version = olderVersions[rng.Intn(len(olderVersions))]
	}
	if pkgs, ok := automatic["chef_packages"].(map[string]any); ok {
		if chef, ok := pkgs["chef"].(map[string]any); ok {
			chef["version"] = version
		}
	}

	return map[string]any{
		"name":             name,
		"chef_type":        "node",
		"json_class":       "Chef::Node",
		"chef_environment": envWeights[rng.Intn(len(envWeights))],
		"run_list":         []any{"role[base]", "role[" + role + "]"},
		"automatic":        automatic,
		"default":          map[string]any{},
		"normal":           map[string]any{},
		"override":         map[string]any{},
	}
}

// harvestTemplates reads the base node files and returns one representative
// "automatic" block per platform, split into Linux and Windows pools.
func harvestTemplates(dir string) (linux, windows []map[string]any, err error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".json" {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names) // deterministic template selection
	seen := map[string]bool{}
	for _, fn := range names {
		raw, err := os.ReadFile(filepath.Join(dir, fn))
		if err != nil {
			return nil, nil, err
		}
		var node map[string]any
		if err := json.Unmarshal(raw, &node); err != nil {
			return nil, nil, err
		}
		automatic, ok := node["automatic"].(map[string]any)
		if !ok {
			continue
		}
		plat, _ := automatic["platform"].(string)
		ver, _ := automatic["platform_version"].(string)
		key := plat + "|" + ver
		if seen[key] {
			continue
		}
		seen[key] = true
		if fam, _ := automatic["platform_family"].(string); fam == "windows" || plat == "windows" {
			windows = append(windows, automatic)
		} else {
			linux = append(linux, automatic)
		}
	}
	return linux, windows, nil
}

// nameHash gives a stable per-name number for deterministic splay.
func nameHash(s string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(s))
	return h.Sum32()
}

// deepCopy clones a JSON-shaped map via a marshal/unmarshal round trip.
func deepCopy(m map[string]any) map[string]any {
	raw, _ := json.Marshal(m)
	var c map[string]any
	json.Unmarshal(raw, &c)
	return c
}

func (g genResult) write(out string) error {
	orgDir := filepath.Join(out, "organizations", "acme")
	writeJSON := func(path string, v any) error {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		raw, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(path, append(raw, '\n'), 0o644)
	}
	writeFile := func(path, content string) error {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		return os.WriteFile(path, []byte(content), 0o644)
	}

	for name, node := range g.nodes {
		if err := writeJSON(filepath.Join(orgDir, "nodes", name+".json"), node); err != nil {
			return err
		}
	}
	for name, role := range g.roles {
		if err := writeJSON(filepath.Join(orgDir, "roles", name+".json"), role); err != nil {
			return err
		}
	}
	for name, env := range g.envs {
		if err := writeJSON(filepath.Join(orgDir, "environments", name+".json"), env); err != nil {
			return err
		}
	}
	for name, cb := range g.cookbooks {
		cbDir := filepath.Join(orgDir, "cookbooks", name)
		if err := writeFile(filepath.Join(cbDir, "metadata.rb"), cookbookMetadata(name, cb)); err != nil {
			return err
		}
		if err := writeFile(filepath.Join(cbDir, "recipes", "default.rb"), cb.recipe); err != nil {
			return err
		}
	}
	members := make([]any, 0, len(g.users))
	for _, u := range g.users {
		username := u["username"].(string)
		if err := writeJSON(filepath.Join(out, "users", username+".json"), u); err != nil {
			return err
		}
		members = append(members, map[string]any{"username": username})
	}
	if err := writeJSON(filepath.Join(orgDir, "members.json"), members); err != nil {
		return err
	}
	for id, item := range g.apps {
		if err := writeJSON(filepath.Join(orgDir, "data_bags", "apps", id+".json"), item); err != nil {
			return err
		}
	}
	for id, item := range g.secrets {
		if err := writeJSON(filepath.Join(orgDir, "data_bags", "secrets", id+".json"), item); err != nil {
			return err
		}
	}
	return nil
}
