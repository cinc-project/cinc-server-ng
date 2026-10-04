//go:build conformance

package conformance

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"unicode"
)

// Coverage is measured, not claimed. Every test records the knife subcommand
// and Policyfile CLI command it runs; after a full run, the suite asks the
// installed tools which commands they have and fails unless each one was
// either run by some test or is excluded below with a reason. So "every knife
// command is tested" stays true as Workstation adds commands: a new one fails
// the build until someone tests it or says why it does not apply.
//
// An exclusion is only for a command that never talks to a Chef Infra Server
// or that needs something other than one, and it must say which. A command
// that does talk to the server is tested, however awkward.

// knifeExclusions are knife subcommands that cannot be exercised against the
// server, with the reason.
var knifeExclusions = map[string]string{
	"bootstrap": "connects to a target host over SSH or WinRM to install and run the client; the " +
		"server side of a bootstrap (client registration, node creation, the first converge) is " +
		"covered by TestKnifeClientBootstrapFlow and the policy converge",
	"ssh":                         "runs commands on nodes over SSH; its server side is a node search, covered by knife search",
	"supermarket download":        "talks to a Supermarket, not a Chef Infra Server",
	"supermarket install":         "talks to a Supermarket, not a Chef Infra Server",
	"supermarket list":            "talks to a Supermarket, not a Chef Infra Server",
	"supermarket search":          "talks to a Supermarket, not a Chef Infra Server",
	"supermarket share":           "talks to a Supermarket, not a Chef Infra Server",
	"supermarket show":            "talks to a Supermarket, not a Chef Infra Server",
	"supermarket unshare":         "talks to a Supermarket, not a Chef Infra Server",
	"license":                     "manages the local Chef license; no server involved",
	"license add":                 "manages the local Chef license; no server involved",
	"license list":                "manages the local Chef license; no server involved",
	"config list":                 "reads local knife configuration only",
	"config show":                 "reads local knife configuration only",
	"config use":                  "switches the local knife profile only",
	"configure":                   "writes local knife configuration only",
	"configure client":            "writes local client configuration only",
	"yaml convert":                "converts a local YAML recipe to Ruby",
	"rehash":                      "rebuilds knife's local plugin cache",
	"cookbook metadata":           "generates metadata.json from metadata.rb locally",
	"cookbook metadata from file": "generates metadata.json from a local file",
	"serve":                       "serves a local repository with an embedded chef-zero, not a Chef Infra Server",
	"ssl check":                   "inspects the server's TLS certificate; cinc-server-ng serves plain HTTP and TLS is terminated in front of it",
	"ssl fetch":                   "fetches the server's TLS certificate; cinc-server-ng serves plain HTTP and TLS is terminated in front of it",
}

// cliExclusions are Policyfile CLI commands that never talk to a server.
var cliExclusions = map[string]string{
	"exec":              "runs a command in the CLI's embedded Ruby",
	"env":               "prints local environment information",
	"gem":               "runs gem in the CLI's embedded Ruby",
	"generate":          "generates local repositories, cookbooks and templates",
	"shell-init":        "prints shell configuration",
	"export":            "writes a policy and its cookbooks to a local directory",
	"describe-cookbook": "computes a local cookbook's identifier",
	"license":           "manages the local Chef license",
}

var (
	invokedMu sync.Mutex
	invoked   = map[string]map[string]bool{"knife": {}, "cli": {}}
)

// recordKnife and recordCLI note the command a test ran. The command is matched
// against the tool's own list at the end, so the full argument list is kept.
func recordKnife(args []string) { record("knife", args) }
func recordCLI(args []string)   { record("cli", args) }

func record(tool string, args []string) {
	invokedMu.Lock()
	defer invokedMu.Unlock()
	invoked[tool][strings.Join(args, "\x00")] = true
}

func TestMain(m *testing.M) {
	code := m.Run()
	// Only a complete, passing run says anything about coverage; a -run
	// filter or a failure already explains the gaps.
	if code == 0 && flag.Lookup("test.run").Value.String() == "" && !skippedAll() {
		if msg := coverageGaps(); msg != "" {
			fmt.Fprintln(os.Stderr, msg)
			code = 1
		}
	}
	os.Exit(code)
}

// skippedAll reports whether nothing ran because the tools are missing, which
// is a skip locally and already a failure in CI.
func skippedAll() bool {
	invokedMu.Lock()
	defer invokedMu.Unlock()
	return len(invoked["knife"]) == 0
}

func coverageGaps() string {
	knife, err := findTool("KNIFE", "knife")
	if err != nil {
		return "coverage: " + err.Error()
	}
	cli, err := findTool("CINC_CLI", "cinc", "chef-cli", "chef")
	if err != nil {
		return "coverage: " + err.Error()
	}
	var problems []string
	problems = append(problems, gaps("knife", knifeCommands(knife), "knife", knifeExclusions)...)
	problems = append(problems, gaps("Policyfile CLI", cliCommands(cli), "cli", cliExclusions)...)
	if len(problems) == 0 {
		return ""
	}
	return "conformance coverage is incomplete. Test each command below, or (only if it never " +
		"talks to a Chef Infra Server) exclude it in conformance/coverage_test.go with a reason:\n  " +
		strings.Join(problems, "\n  ")
}

// gaps compares a tool's commands with what the tests ran and what is excluded.
func gaps(label string, commands []string, tool string, exclusions map[string]string) []string {
	invokedMu.Lock()
	ran := map[string]bool{}
	for joined := range invoked[tool] {
		if c := longestCommand(commands, strings.Split(joined, "\x00")); c != "" {
			ran[c] = true
		}
	}
	invokedMu.Unlock()

	var problems []string
	for _, c := range commands {
		_, excluded := exclusions[c]
		switch {
		case ran[c] && excluded:
			problems = append(problems, fmt.Sprintf("%s %s: excluded, but a test runs it; drop the exclusion", label, c))
		case !ran[c] && !excluded:
			problems = append(problems, fmt.Sprintf("%s %s: not run by any test", label, c))
		}
	}
	if len(commands) == 0 {
		problems = append(problems, label+": could not list its commands")
	}
	sort.Strings(problems)
	return problems
}

// longestCommand returns the longest command whose words prefix args.
func longestCommand(commands []string, args []string) string {
	best := ""
	for _, c := range commands {
		words := strings.Fields(c)
		if len(words) <= len(args) && slices.Equal(words, args[:len(words)]) && len(c) > len(best) {
			best = c
		}
	}
	return best
}

// knifeCommands lists knife's subcommands as knife itself reports them, from
// the usage lines it prints when run without arguments ("knife node run_list
// add [NODE] ..."): the words up to the first argument placeholder.
func knifeCommands(bin string) []string {
	out, _ := exec.Command(bin).CombinedOutput() // exits non-zero after printing usage
	seen := map[string]bool{}
	var commands []string
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 || fields[0] != "knife" {
			continue
		}
		var words []string
		for _, f := range fields[1:] {
			if !isCommandWord(f) {
				break
			}
			words = append(words, f)
		}
		if c := strings.Join(words, " "); c != "" && !seen[c] {
			seen[c] = true
			commands = append(commands, c)
		}
	}
	sort.Strings(commands)
	return commands
}

// isCommandWord tells a subcommand word ("run_list", "from") from an argument
// placeholder ("NODE", "[ENTRY", "(options)", "--email").
func isCommandWord(f string) bool {
	if strings.ContainsAny(f, "[]()<>|.=") || strings.HasPrefix(f, "-") {
		return false
	}
	for _, r := range f {
		if unicode.IsUpper(r) {
			return false
		}
	}
	return true
}

// cliCommands lists the Policyfile CLI's commands from its "Available
// Commands" section.
func cliCommands(bin string) []string {
	out, _ := exec.Command(bin).CombinedOutput()
	var commands []string
	inList := false
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "Available Commands") {
			inList = true
			continue
		}
		if !inList {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 || !strings.HasPrefix(line, " ") {
			if len(commands) > 0 {
				break
			}
			continue
		}
		commands = append(commands, fields[0])
	}
	sort.Strings(commands)
	return commands
}

// The command lists are parsed from human-readable output, so check the
// parsers against the installed tools: a parser that silently found nothing
// would make every coverage check pass.
func TestCoverageListsCommands(t *testing.T) {
	knife := knifeBin(t)
	kc := knifeCommands(knife)
	for _, want := range []string{"node show", "node run_list add", "data bag from file", "cookbook upload", "raw"} {
		if !slices.Contains(kc, want) {
			t.Errorf("knife command list lacks %q; parsed %d commands: %v", want, len(kc), kc)
		}
	}
	cc := cliCommands(policyCLIBin(t))
	for _, want := range []string{"install", "push", "show-policy", "clean-policy-revisions"} {
		if !slices.Contains(cc, want) {
			t.Errorf("Policyfile CLI command list lacks %q; parsed %v", want, cc)
		}
	}
	for c := range knifeExclusions {
		if !slices.Contains(kc, c) {
			t.Logf("exclusion %q is not a command of this knife (%s); it may be from another version", c, knife)
		}
	}
}
