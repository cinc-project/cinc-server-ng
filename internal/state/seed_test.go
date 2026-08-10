package state

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/tas50/cinc-server-ng/internal/store"
)

// ohaiUptime renders a duration in seconds the way Ohai's uptime plugin does
// (seconds_to_human), so the test can assert each node's automatic.uptime string
// matches its uptime_seconds. The singular "1 day" case is intentional and
// mirrors the real plugin.
func ohaiUptime(seconds int64) string {
	days := seconds / 86400
	seconds -= 86400 * days
	hours := seconds / 3600
	seconds -= 3600 * hours
	minutes := seconds / 60
	seconds -= 60 * minutes

	switch {
	case days > 1:
		return fmt.Sprintf("%d days %02d hours %02d minutes %02d seconds", days, hours, minutes, seconds)
	case days == 1:
		return fmt.Sprintf("%d day %02d hours %02d minutes %02d seconds", days, hours, minutes, seconds)
	case hours > 0:
		return fmt.Sprintf("%d hours %02d minutes %02d seconds", hours, minutes, seconds)
	case minutes > 0:
		return fmt.Sprintf("%d minutes %02d seconds", minutes, seconds)
	default:
		return fmt.Sprintf("%d seconds", seconds)
	}
}

// TestSeedNodeUptime verifies every node carries a human-readable automatic.uptime
// string consistent with its uptime_seconds, matching real Ohai output.
func TestSeedNodeUptime(t *testing.T) {
	_, org, _ := loadSeed(t)

	for _, name := range mustKeys(t, org, "nodes") {
		raw, _ := mustGet(t, org, "nodes", name)
		var node struct {
			Automatic struct {
				Uptime        string `json:"uptime"`
				UptimeSeconds int64  `json:"uptime_seconds"`
			} `json:"automatic"`
		}
		if err := json.Unmarshal(raw, &node); err != nil {
			t.Fatalf("node %s: %v", name, err)
		}
		if node.Automatic.Uptime == "" {
			t.Errorf("node %s missing automatic.uptime", name)
			continue
		}
		if want := ohaiUptime(node.Automatic.UptimeSeconds); node.Automatic.Uptime != want {
			t.Errorf("node %s uptime = %q, want %q (from %d seconds)",
				name, node.Automatic.Uptime, want, node.Automatic.UptimeSeconds)
		}
	}
}

// TestSeedNodesHaveRichOhai verifies the nodes carry the structurally rich Ohai
// data fauxhai provides — non-empty filesystem and network (the signals every
// fauxhai platform ships; dmi/block_device are platform-dependent) — and that
// the node's own ipaddress and macaddress propagated into the network block
// (proving the per-node identity overlay, not fauxhai's placeholder address).
func TestSeedNodesHaveRichOhai(t *testing.T) {
	_, org, _ := loadSeed(t)

	for _, name := range mustKeys(t, org, "nodes") {
		raw, _ := mustGet(t, org, "nodes", name)
		var node struct {
			Automatic struct {
				IPAddress  string          `json:"ipaddress"`
				MacAddress string          `json:"macaddress"`
				Filesystem json.RawMessage `json:"filesystem"`
				Network    json.RawMessage `json:"network"`
			} `json:"automatic"`
		}
		if err := json.Unmarshal(raw, &node); err != nil {
			t.Fatalf("node %s: %v", name, err)
		}
		a := node.Automatic
		for field, val := range map[string]json.RawMessage{"filesystem": a.Filesystem, "network": a.Network} {
			if len(val) == 0 || string(val) == "{}" || string(val) == "null" {
				t.Errorf("node %s has empty automatic.%s, want rich fauxhai data", name, field)
			}
		}
		if a.IPAddress == "" || a.MacAddress == "" {
			t.Errorf("node %s missing automatic ipaddress/macaddress", name)
			continue
		}
		if !bytes.Contains(a.Network, []byte(a.IPAddress)) {
			t.Errorf("node %s ipaddress %q absent from automatic.network (identity overlay missing)", name, a.IPAddress)
		}
		if !bytes.Contains(a.Network, []byte(a.MacAddress)) {
			t.Errorf("node %s macaddress %q absent from automatic.network (identity overlay missing)", name, a.MacAddress)
		}
	}
}

// seedDir is the committed dev/test-repo state directory, relative to this
// package.
const seedDir = "../../dev/test-repo"

// loadSeed loads the committed dev/test-repo into a fresh store and returns the
// store, the acme org, and the load summary.
func loadSeed(t *testing.T) (*store.Store, *store.Org, *Summary) {
	t.Helper()
	st := store.New()
	sum, err := Load(st, seedDir)
	if err != nil {
		t.Fatalf("load %s: %v", seedDir, err)
	}
	org, ok, err := st.Org("acme")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("seed did not create org acme")
	}
	return st, org, sum
}

// mustKeys returns org.Keys(coll), failing the test on error.
func mustKeys(t *testing.T, org *store.Org, coll string) []string {
	t.Helper()
	keys, err := org.Keys(coll)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

// mustGet returns the value and presence flag from org.Get(coll, key), failing
// the test on error.
func mustGet(t *testing.T, org *store.Org, coll, key string) ([]byte, bool) {
	t.Helper()
	raw, ok, err := org.Get(coll, key)
	if err != nil {
		t.Fatal(err)
	}
	return raw, ok
}

// TestSeedCounts pins the shape of the committed dev/test-repo: a medium,
// realistic fleet with global users and a group the chef-repo format alone
// cannot express.
func TestSeedCounts(t *testing.T) {
	_, _, sum := loadSeed(t)

	if sum.Users != 2 {
		t.Errorf("global users = %d, want 2", sum.Users)
	}
	acme := sum.Orgs["acme"]
	for coll, want := range map[string]int{
		"nodes":            107,
		"roles":            8,
		"environments":     3,
		"cookbooks":        8,
		"policy_groups":    2,
		"policy_revisions": 2,
		"data_bags":        3,
		"data_bag_items":   8,
	} {
		if got := acme.Counts[coll]; got != want {
			t.Errorf("acme %s = %d, want %d", coll, got, want)
		}
	}
	if acme.Groups != 2 {
		t.Errorf("acme groups = %d, want 2 (admins, devs)", acme.Groups)
	}
}

// TestSeedDataBags verifies the seed's data bags and items load and are
// addressable: each expected bag exists, each item is stored under its bag
// keyed by its own "id", and the item JSON carries that matching id — the shape
// the data bag API serves.
func TestSeedDataBags(t *testing.T) {
	_, org, _ := loadSeed(t)

	want := map[string][]string{
		"users":   {"deploy", "ops", "jenkins"},
		"secrets": {"postgresql", "redis", "jenkins"},
		"apps":    {"webapp", "api"},
	}
	for bag, items := range want {
		if _, ok := mustGet(t, org, "data_bags", bag); !ok {
			t.Errorf("data bag %q not loaded", bag)
		}
		for _, id := range items {
			raw, ok := mustGet(t, org, "databag_items:"+bag, id)
			if !ok {
				t.Errorf("data bag %q missing item %q", bag, id)
				continue
			}
			var item struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal(raw, &item); err != nil {
				t.Fatalf("data bag %q item %q: %v", bag, id, err)
			}
			if item.ID != id {
				t.Errorf("data bag %q item %q has id %q, want %q", bag, id, item.ID, id)
			}
		}
	}
}

// TestSeedFauxhaiNodes verifies the nodes carry real fauxhai automatic
// attributes: each node reports a platform and platform_version.
func TestSeedFauxhaiNodes(t *testing.T) {
	_, org, _ := loadSeed(t)

	platforms := map[string]bool{}
	for _, name := range mustKeys(t, org, "nodes") {
		raw, _ := mustGet(t, org, "nodes", name)
		var node struct {
			Automatic struct {
				Platform        string `json:"platform"`
				PlatformVersion string `json:"platform_version"`
			} `json:"automatic"`
		}
		if err := json.Unmarshal(raw, &node); err != nil {
			t.Fatalf("node %s: %v", name, err)
		}
		if node.Automatic.Platform == "" || node.Automatic.PlatformVersion == "" {
			t.Errorf("node %s missing fauxhai automatic platform/version", name)
		}
		platforms[node.Automatic.Platform] = true
	}
	// The fleet spans several platforms, not just one.
	if len(platforms) < 4 {
		t.Errorf("fleet spans %d platforms, want >= 4 for realism", len(platforms))
	}
}

// TestSeedEnvironmentsHaveAttributesAndPins verifies the seed's environments
// are realistic: each carries some default/override attributes and pins at
// least one cookbook version, so the fixture exercises environment overrides
// and version constraints rather than shipping empty stubs.
func TestSeedEnvironmentsHaveAttributesAndPins(t *testing.T) {
	_, org, _ := loadSeed(t)

	for _, name := range mustKeys(t, org, "environments") {
		if name == "_default" {
			continue
		}
		raw, _ := mustGet(t, org, "environments", name)
		var env struct {
			DefaultAttributes  map[string]json.RawMessage `json:"default_attributes"`
			OverrideAttributes map[string]json.RawMessage `json:"override_attributes"`
			CookbookVersions   map[string]string          `json:"cookbook_versions"`
		}
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Fatalf("environment %s: %v", name, err)
		}

		if len(env.DefaultAttributes) == 0 && len(env.OverrideAttributes) == 0 {
			t.Errorf("environment %s has no default/override attributes", name)
		}
		if len(env.CookbookVersions) == 0 {
			t.Errorf("environment %s pins no cookbook versions", name)
		}
	}
}

// TestSeedRunListCookbooksLoaded verifies every cookbook named by a role
// run-list recipe (recipe[<cookbook>::<recipe>]) is loaded into the seed, so
// the fixture can actually resolve the recipes its nodes converge.
func TestSeedRunListCookbooksLoaded(t *testing.T) {
	_, org, _ := loadSeed(t)

	loaded := map[string]bool{}
	for _, key := range mustKeys(t, org, "cookbooks") {
		name, _, _ := strings.Cut(key, "/")
		loaded[name] = true
	}

	referenced := map[string]bool{}
	for _, name := range mustKeys(t, org, "roles") {
		raw, _ := mustGet(t, org, "roles", name)
		var role struct {
			RunList []string `json:"run_list"`
		}
		if err := json.Unmarshal(raw, &role); err != nil {
			t.Fatalf("role %s: %v", name, err)
		}
		for _, item := range role.RunList {
			if !strings.HasPrefix(item, "recipe[") {
				continue
			}
			spec := strings.TrimSuffix(strings.TrimPrefix(item, "recipe["), "]")
			cookbook, _, _ := strings.Cut(spec, "::")
			referenced[cookbook] = true
		}
	}

	if len(referenced) == 0 {
		t.Fatal("no recipe references found in role run-lists")
	}
	for cookbook := range referenced {
		if !loaded[cookbook] {
			t.Errorf("role run-lists reference cookbook %q but it is not loaded", cookbook)
		}
	}
}

// TestSeedNoDanglingReferences verifies every node points at objects that
// actually exist in the seed: run-list roles, chef_environment, and (for
// policy nodes) a policy revision pinned into the node's policy group.
func TestSeedNoDanglingReferences(t *testing.T) {
	_, org, _ := loadSeed(t)

	has := func(coll, key string) bool {
		_, ok := mustGet(t, org, coll, key)
		return ok
	}

	for _, name := range mustKeys(t, org, "nodes") {
		raw, _ := mustGet(t, org, "nodes", name)
		var node struct {
			ChefEnvironment string   `json:"chef_environment"`
			RunList         []string `json:"run_list"`
			PolicyName      string   `json:"policy_name"`
			PolicyGroup     string   `json:"policy_group"`
		}
		if err := json.Unmarshal(raw, &node); err != nil {
			t.Fatalf("node %s: %v", name, err)
		}

		if env := node.ChefEnvironment; env != "" && env != "_default" && !has("environments", env) {
			t.Errorf("node %s references missing environment %q", name, env)
		}

		for _, item := range node.RunList {
			role := strings.TrimSuffix(strings.TrimPrefix(item, "role["), "]")
			if strings.HasPrefix(item, "role[") && !has("roles", role) {
				t.Errorf("node %s run-list references missing role %q", name, role)
			}
		}

		if node.PolicyName != "" {
			if !has("policy_groups", node.PolicyGroup) {
				t.Errorf("node %s references missing policy_group %q", name, node.PolicyGroup)
				continue
			}
			groupRaw, _ := mustGet(t, org, "policy_groups", node.PolicyGroup)
			var group struct {
				Policies map[string]struct {
					RevisionID string `json:"revision_id"`
				} `json:"policies"`
			}
			if err := json.Unmarshal(groupRaw, &group); err != nil {
				t.Fatalf("policy_group %s: %v", node.PolicyGroup, err)
			}
			pin, ok := group.Policies[node.PolicyName]
			if !ok {
				t.Errorf("node %s policy %q not pinned in group %q", name, node.PolicyName, node.PolicyGroup)
				continue
			}
			if !has("policy_revisions:"+node.PolicyName, pin.RevisionID) {
				t.Errorf("node %s policy %q revision %q not loaded", name, node.PolicyName, pin.RevisionID)
			}
		}
	}
}

// currentClientVersion is the cinc-client / chef-client version the bulk of the
// fleet has converged onto; a minority of nodes lag on older releases (see
// TestSeedChefClientVersions) so the fixture exercises version-drift scenarios.
const currentClientVersion = "19.3.14"

// nodeAutomatic decodes the slice of a node's automatic attributes the
// version/check-in tests care about.
type nodeAutomatic struct {
	Automatic struct {
		OhaiTime     float64 `json:"ohai_time"`
		ChefPackages struct {
			Chef struct {
				Version string `json:"version"`
			} `json:"chef"`
		} `json:"chef_packages"`
	} `json:"automatic"`
}

// TestSeedChefClientVersions verifies the fleet models realistic version drift:
// the great majority of nodes run the current cinc-client (19.3.14) while a
// ~10% minority lag on a spread of older, differing releases.
func TestSeedChefClientVersions(t *testing.T) {
	_, org, _ := loadSeed(t)

	names := mustKeys(t, org, "nodes")
	total := len(names)
	current := 0
	old := map[string]int{}
	for _, name := range names {
		raw, _ := mustGet(t, org, "nodes", name)
		var node nodeAutomatic
		if err := json.Unmarshal(raw, &node); err != nil {
			t.Fatalf("node %s: %v", name, err)
		}
		v := node.Automatic.ChefPackages.Chef.Version
		if v == "" {
			t.Errorf("node %s reports no chef_packages.chef.version", name)
			continue
		}
		if v == currentClientVersion {
			current++
		} else {
			old[v]++
		}
	}

	oldCount := total - current
	// Most of the fleet is current.
	if current < total*8/10 {
		t.Errorf("only %d/%d nodes on current %s, want the majority (>=80%%)", current, total, currentClientVersion)
	}
	// A ~10% minority lags behind — enough to be meaningful, not a flood.
	if oldCount < 8 || oldCount > total/5 {
		t.Errorf("%d nodes on old versions, want a ~10%% minority (8..%d)", oldCount, total/5)
	}
	// Those stragglers run a *spread* of different old releases, not one.
	if len(old) < 5 {
		t.Errorf("old nodes run %d distinct versions %v, want a varied spread (>=5)", len(old), old)
	}
}

// TestSeedBareNodes verifies the fleet contains genuinely unconfigured nodes:
// freshly-bootstrapped boxes with neither a run-list nor a policy assignment, as
// distinct from policy nodes (which carry an empty run_list but a policy_name).
func TestSeedBareNodes(t *testing.T) {
	_, org, _ := loadSeed(t)

	bare := 0
	for _, name := range mustKeys(t, org, "nodes") {
		raw, _ := mustGet(t, org, "nodes", name)
		var node struct {
			RunList     []string `json:"run_list"`
			PolicyName  string   `json:"policy_name"`
			PolicyGroup string   `json:"policy_group"`
		}
		if err := json.Unmarshal(raw, &node); err != nil {
			t.Fatalf("node %s: %v", name, err)
		}
		if len(node.RunList) == 0 && node.PolicyName == "" && node.PolicyGroup == "" {
			bare++
		}
	}
	if bare < 8 {
		t.Errorf("fleet has %d bare (no run-list, no policy) nodes, want >= 8", bare)
	}
}

// recentCheckinFloor is a Unix timestamp safely after the original June-2024
// seed times: every node's last check-in (ohai_time) must be newer, modelling an
// active fleet that has all reported in recently rather than a stale snapshot.
// 1780000000 == 2026-05-31T16:26:40Z.
const recentCheckinFloor = 1780000000.0

// TestSeedRecentSplayedCheckins verifies every node's last check-in is recent,
// the times are not all identical, and the whole fleet falls within a ~1h
// window — i.e. a realistic, randomly-splayed wave of chef-client runs.
func TestSeedRecentSplayedCheckins(t *testing.T) {
	_, org, _ := loadSeed(t)

	var min, max float64
	distinct := map[float64]bool{}
	first := true
	for _, name := range mustKeys(t, org, "nodes") {
		raw, _ := mustGet(t, org, "nodes", name)
		var node nodeAutomatic
		if err := json.Unmarshal(raw, &node); err != nil {
			t.Fatalf("node %s: %v", name, err)
		}
		ts := node.Automatic.OhaiTime
		if ts < recentCheckinFloor {
			t.Errorf("node %s last checked in at %.0f, want recent (>= %.0f)", name, ts, recentCheckinFloor)
		}
		distinct[ts] = true
		if first || ts < min {
			min = ts
		}
		if first || ts > max {
			max = ts
		}
		first = false
	}

	if len(distinct) < 2 {
		t.Errorf("all nodes share one check-in time, want a random splay")
	}
	if span := max - min; span > 3600 {
		t.Errorf("check-in times span %.0fs, want all within a 1h (3600s) splay", span)
	}
}
