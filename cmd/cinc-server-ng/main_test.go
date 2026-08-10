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

	"github.com/tas50/cinc-server-ng/server"
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
		for _, want := range []string{"cinc-zero", "v1.2.3", "abc1234", "2026-05-30"} {
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
