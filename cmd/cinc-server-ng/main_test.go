package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cinc-project/cinc-server-ng/server"
)

// TestStateFlagHiddenFromUsage verifies the experimental --state flag is parsed
// but kept out of the usage/help output, while a documented flag (--repo) still
// appears.
func TestStateFlagHiddenFromUsage(t *testing.T) {
	var buf bytes.Buffer
	_, err := parseFlags([]string{"-h"}, &buf)
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("parseFlags(-h) error = %v, want flag.ErrHelp", err)
	}
	out := buf.String()
	if strings.Contains(out, "-state") {
		t.Errorf("usage should hide -state, got:\n%s", out)
	}
	if !strings.Contains(out, "-repo") {
		t.Errorf("usage should show -repo, got:\n%s", out)
	}
}

// TestStateFlagSetsStatePath verifies --state populates the parsed flags.
func TestStateFlagSetsStatePath(t *testing.T) {
	f, err := parseFlags([]string{"--state", "/tmp/seed"}, io.Discard)
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if f.state != "/tmp/seed" {
		t.Errorf("state = %q, want /tmp/seed", f.state)
	}
}

// TestInitSeedsAndExits verifies --init populates a SQLite database and exits
// without serving, and that the resulting database reopens cleanly (the
// pre-baked-DB workflow the dev environment relies on).
func TestInitSeedsAndExits(t *testing.T) {
	db := filepath.Join(t.TempDir(), "init.db")
	var buf bytes.Buffer
	if err := run([]string{"--storage", "sqlite", "--db", db, "--init", "--no-auth"}, &buf); err != nil {
		t.Fatalf("run(--init): %v", err)
	}
	if !strings.Contains(buf.String(), "initialized sqlite database") {
		t.Errorf("missing init confirmation, got: %q", buf.String())
	}
	// The baked database must reopen without recreating its org (idempotent).
	srv, err := server.New(server.Options{Storage: "sqlite", DB: db, DisableAuth: true})
	if err != nil {
		t.Fatalf("reopen baked db: %v", err)
	}
	if err := srv.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// TestEnforcementOnByDefault: the binary enforces ACLs unless told otherwise.
func TestEnforcementOnByDefault(t *testing.T) {
	f, err := parseFlags(nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if !f.enforceACLs {
		t.Error("--enforce-acls should default to true for the binary")
	}
}

// TestEnforcementCanBeDisabled: --enforce-acls=false opts back into permissive.
func TestEnforcementCanBeDisabled(t *testing.T) {
	f, err := parseFlags([]string{"--enforce-acls=false"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if f.enforceACLs {
		t.Error("--enforce-acls=false should disable enforcement")
	}
}

// TestNoAuthImpliesNoEnforcement: --no-auth must work on its own even though
// enforcement is on by default (the two are mutually exclusive), rather than
// erroring out of server.New.
func TestNoAuthImpliesNoEnforcement(t *testing.T) {
	var buf bytes.Buffer
	if err := run([]string{"--no-auth", "--init"}, &buf); err != nil {
		t.Fatalf("run(--no-auth --init): %v", err)
	}
}

// TestNoAuthWithExplicitEnforceIsAnError: explicitly asking for both --no-auth
// and --enforce-acls is contradictory and must fail loudly, not silently drop
// enforcement.
func TestNoAuthWithExplicitEnforceIsAnError(t *testing.T) {
	var buf bytes.Buffer
	err := run([]string{"--no-auth", "--enforce-acls=true", "--init"}, &buf)
	if err == nil {
		t.Fatal("expected an error for --no-auth --enforce-acls=true")
	}
	if !strings.Contains(err.Error(), "cannot be combined") {
		t.Errorf("unclear conflict error: %v", err)
	}
}

// TestVersionSubcommand verifies the "version" subcommand prints the injected
// build metadata and exits without starting the server.
func TestVersionSubcommand(t *testing.T) {
	version, commit, buildDate = "v1.2.3", "abc1234", "2026-05-30"

	for _, args := range [][]string{{"version"}, {"--version"}, {"-version"}} {
		var buf bytes.Buffer
		if err := run(args, &buf); err != nil {
			t.Fatalf("run(%v) returned error: %v", args, err)
		}
		out := buf.String()
		for _, want := range []string{"cinc-server-ng", "v1.2.3", "abc1234", "2026-05-30"} {
			if !strings.Contains(out, want) {
				t.Errorf("run(%v) output %q missing %q", args, out, want)
			}
		}
	}
}

// Group commit is on by default: it is worth roughly 2.5x write throughput and
// an order of magnitude better p99 under concurrent fleet load, at the cost of
// a few microseconds on a serialized single-client write. Fleet correctness of
// the default matters more than that latency, so it must be opt-out.
func TestGroupCommitDefaultsOn(t *testing.T) {
	f, err := parseFlags(nil, io.Discard)
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if !f.groupCommit {
		t.Error("sqlite group commit should default on")
	}
}

func TestGroupCommitCanBeDisabled(t *testing.T) {
	f, err := parseFlags([]string{"--sqlite-group-commit=false"}, io.Discard)
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if f.groupCommit {
		t.Error("--sqlite-group-commit=false should turn group commit off")
	}
}

// The stats user defaults to Chef Infra Server's statsuser; no password is set
// unless asked for, so the server generates one.
func TestStatsFlagsDefault(t *testing.T) {
	t.Setenv("CINC_SERVER_NG_STATS_USER", "")
	t.Setenv("CINC_SERVER_NG_STATS_PASSWORD", "")
	f, err := parseFlags(nil, io.Discard)
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if f.statsUser != "statsuser" {
		t.Errorf("stats user = %q, want statsuser", f.statsUser)
	}
	if f.statsPassword != "" {
		t.Errorf("stats password = %q, want empty (generated)", f.statsPassword)
	}
}

func TestStatsFlagsSet(t *testing.T) {
	f, err := parseFlags([]string{"--stats-user", "prom", "--stats-password", "pw"}, io.Discard)
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if f.statsUser != "prom" || f.statsPassword != "pw" {
		t.Errorf("stats credentials = %q/%q, want prom/pw", f.statsUser, f.statsPassword)
	}
}

// The environment is the way to pass the password without putting it on a
// command line other processes can read, and it must never surface in --help.
func TestStatsPasswordFromEnvNotInUsage(t *testing.T) {
	t.Setenv("CINC_SERVER_NG_STATS_USER", "prom")
	t.Setenv("CINC_SERVER_NG_STATS_PASSWORD", "env-secret")
	f, err := parseFlags(nil, io.Discard)
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if f.statsUser != "prom" || f.statsPassword != "env-secret" {
		t.Errorf("stats credentials = %q/%q, want prom/env-secret", f.statsUser, f.statsPassword)
	}

	var buf bytes.Buffer
	if _, err := parseFlags([]string{"-h"}, &buf); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("parseFlags(-h) error = %v", err)
	}
	if strings.Contains(buf.String(), "env-secret") {
		t.Errorf("usage leaks the stats password:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "-stats-password") {
		t.Errorf("usage should document -stats-password:\n%s", buf.String())
	}
}

// A flag wins over the environment, as with the other env-backed flags.
func TestStatsPasswordFlagOverridesEnv(t *testing.T) {
	t.Setenv("CINC_SERVER_NG_STATS_PASSWORD", "env-secret")
	f, err := parseFlags([]string{"--stats-password", "flag-secret"}, io.Discard)
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if f.statsPassword != "flag-secret" {
		t.Errorf("stats password = %q, want flag-secret", f.statsPassword)
	}
}

// The startup banner is the only place a generated password can be read, so it
// is printed then; a configured one is the operator's own and is not echoed.
func TestStatsBanner(t *testing.T) {
	cases := []struct {
		name              string
		noAuth, generated bool
		wantIn, wantNotIn []string
	}{
		{name: "generated", generated: true,
			wantIn: []string{"statsuser", "gen-pw", "generated"}},
		{name: "configured",
			wantIn: []string{"statsuser", "configured"}, wantNotIn: []string{"gen-pw"}},
		{name: "no auth", noAuth: true, generated: true,
			wantIn: []string{"open"}, wantNotIn: []string{"gen-pw"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := statsBanner("statsuser", "gen-pw", tc.generated, tc.noAuth)
			for _, w := range tc.wantIn {
				if !strings.Contains(got, w) {
					t.Errorf("banner %q missing %q", got, w)
				}
			}
			for _, w := range tc.wantNotIn {
				if strings.Contains(got, w) {
					t.Errorf("banner %q should not contain %q", got, w)
				}
			}
		})
	}
}
