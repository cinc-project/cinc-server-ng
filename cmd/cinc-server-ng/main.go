// Command cinc-server-ng runs the in-memory Chef Infra Server as a standalone
// process for use in test pipelines.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cinc-project/cinc-server-ng/server"
)

// Build metadata, injected at link time via -ldflags (see the Makefile).
var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		log.Fatal(err)
	}
}

// cliFlags holds the parsed command-line options.
type cliFlags struct {
	addr           string
	orgsCSV        string
	admin          string
	keyFile        string
	noAuth         bool
	enforceACLs    bool
	enforceACLsSet bool // whether --enforce-acls was passed explicitly
	repo           string
	state          string
	webuiKey       string
	storage        string
	db             string
	groupCommit    bool
	initOnly       bool
	statsUser      string
	statsPassword  string

	tlsCert         string
	tlsKey          string
	externalURL     string
	shutdownDelay   time.Duration
	shutdownTimeout time.Duration
}

// hiddenFlags are registered and functional but omitted from usage/help output
// (experimental knobs). --state is hidden while its on-disk format settles.
var hiddenFlags = map[string]bool{"state": true}

// parseFlags defines the cinc-server-ng flag set, writing usage to out, and parses
// args into cliFlags. The usage printer suppresses any flag in hiddenFlags.
func parseFlags(args []string, out io.Writer) (*cliFlags, error) {
	fs := flag.NewFlagSet("cinc-server-ng", flag.ContinueOnError)
	fs.SetOutput(out)

	var f cliFlags
	fs.StringVar(&f.addr, "addr", "127.0.0.1:8889", "listen address (host:port)")
	fs.StringVar(&f.orgsCSV, "orgs", "acme", "comma-separated organizations to create")
	fs.StringVar(&f.admin, "admin", "pivotal", "bootstrap admin user name")
	fs.StringVar(&f.keyFile, "key-out", "", "write the admin private key to this file")
	fs.BoolVar(&f.noAuth, "no-auth", false, "disable request signature verification (also disables ACL enforcement)")
	fs.BoolVar(&f.enforceACLs, "enforce-acls", true, "enforce object ACLs and group membership; pass --enforce-acls=false for a permissive server")
	fs.StringVar(&f.repo, "repo", "", "path to a chef-repo to load into the first org at startup")
	fs.StringVar(&f.state, "state", "", "path to a full server-state directory to load at startup")
	fs.StringVar(&f.webuiKey, "webui-key", "", "path to a webui public/private key for X-Ops-Request-Source: web impersonation (defaults to the admin key)")
	fs.StringVar(&f.storage, "storage", envOr("CINC_SERVER_NG_STORAGE", "memory"), "storage backend: memory (ephemeral) or sqlite (durable)")
	fs.StringVar(&f.db, "db", os.Getenv("CINC_SERVER_NG_DB"), "sqlite database file path (required when --storage sqlite)")
	fs.BoolVar(&f.groupCommit, "sqlite-group-commit", true, "batch concurrent sqlite writes into shared transactions: much higher write throughput and far better tail latency under fleet load, at a few microseconds more on a serialized single-client write; pass --sqlite-group-commit=false to opt out")
	fs.StringVar(&f.statsUser, "stats-user", envOr("CINC_SERVER_NG_STATS_USER", server.DefaultStatsUser), "HTTP Basic user for GET /_stats")
	// The password's flag default stays empty so a value taken from the
	// environment never appears in --help; the environment is applied after
	// parsing instead.
	fs.StringVar(&f.statsPassword, "stats-password", "", "HTTP Basic password for GET /_stats (or CINC_SERVER_NG_STATS_PASSWORD, which keeps it off the command line); when unset, a random one is generated and printed at startup")
	fs.StringVar(&f.tlsCert, "tls-cert", os.Getenv("CINC_SERVER_NG_TLS_CERT"), "PEM certificate (chain) to serve HTTPS with; requires --tls-key. Send SIGHUP to reload a renewed pair")
	fs.StringVar(&f.tlsKey, "tls-key", os.Getenv("CINC_SERVER_NG_TLS_KEY"), "PEM private key for --tls-cert")
	fs.StringVar(&f.externalURL, "external-url", os.Getenv("CINC_SERVER_NG_EXTERNAL_URL"), "public scheme://host[:port] used in every URL the server returns (default: derived from each request's Host and X-Forwarded-Proto)")
	fs.DurationVar(&f.shutdownDelay, "shutdown-delay", 0, "on SIGTERM/SIGINT, fail /_status with 503 and keep serving for this long before stopping, so a load balancer drains this instance first (a second signal skips the wait)")
	fs.DurationVar(&f.shutdownTimeout, "shutdown-timeout", 30*time.Second, "how long to wait for in-flight requests when stopping before cutting them off")
	fs.BoolVar(&f.initOnly, "init", false, "seed the store (bootstrap plus any configured seed) and exit without serving; use to pre-bake a SQLite database")

	fs.Usage = func() {
		fmt.Fprintf(out, "Usage of cinc-server-ng:\n")
		fs.VisitAll(func(fl *flag.Flag) {
			if hiddenFlags[fl.Name] {
				return
			}
			line := fmt.Sprintf("  -%s", fl.Name)
			if fl.DefValue != "" {
				line += fmt.Sprintf(" (default %q)", fl.DefValue)
			}
			fmt.Fprintf(out, "%s\n    \t%s\n", line, fl.Usage)
		})
	}

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	// Record whether --enforce-acls was set explicitly (vs. left at its default),
	// so --no-auth can override the implicit default but conflict loudly with an
	// explicit request for enforcement.
	fs.Visit(func(fl *flag.Flag) {
		if fl.Name == "enforce-acls" {
			f.enforceACLsSet = true
		}
	})
	if f.statsPassword == "" {
		f.statsPassword = os.Getenv("CINC_SERVER_NG_STATS_PASSWORD")
	}
	return &f, nil
}

func run(args []string, out io.Writer) error {
	if len(args) > 0 {
		switch args[0] {
		case "version", "--version", "-version":
			fmt.Fprintf(out, "cinc-server-ng %s (commit %s, built %s)\n", version, commit, buildDate)
			return nil
		case "healthcheck":
			return healthcheck(args[1:], out)
		}
	}

	f, err := parseFlags(args, out)
	if err != nil {
		// -h/-help is a clean exit, not a failure.
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	var webuiKey []byte
	if f.webuiKey != "" {
		webuiKey, err = os.ReadFile(f.webuiKey)
		if err != nil {
			return fmt.Errorf("read webui key: %w", err)
		}
	}

	// ACL enforcement requires an authenticated actor. --no-auth on its own simply
	// turns off the default-on enforcement; but explicitly asking for both is a
	// contradiction we fail loudly on rather than silently dropping enforcement.
	if f.noAuth {
		if f.enforceACLsSet && f.enforceACLs {
			return errors.New("--no-auth cannot be combined with --enforce-acls: ACL enforcement requires authentication")
		}
		f.enforceACLs = false
	}

	srv, err := server.New(server.Options{
		Addr:        f.addr,
		Orgs:        splitCSV(f.orgsCSV),
		AdminName:   f.admin,
		DisableAuth: f.noAuth,
		EnforceACL:  f.enforceACLs,
		Repo:        f.repo,
		StatePath:   f.state,
		WebUIKey:    webuiKey,
		Storage:     f.storage,
		DB:          f.db,

		StatsUser:     f.statsUser,
		StatsPassword: f.statsPassword,

		SQLiteGroupCommit: f.groupCommit,

		ExternalURL: f.externalURL,
		TLSCertFile: f.tlsCert,
		TLSKeyFile:  f.tlsKey,
	})
	if err != nil {
		return err
	}
	// The admin key is available right after New (before Start), so --key-out and
	// --init both work without binding a listener.
	if f.keyFile != "" {
		if err := os.WriteFile(f.keyFile, srv.AdminKey(), 0o600); err != nil {
			return fmt.Errorf("write key file: %w", err)
		}
		fmt.Fprintf(out, "Admin key for %q written to %s\n", srv.AdminName(), f.keyFile)
	}

	// --init seeds the store (bootstrap plus any --state/--repo load happened in
	// server.New) and exits without serving, leaving a populated database behind.
	if f.initOnly {
		if f.storage == "sqlite" {
			fmt.Fprintf(out, "initialized sqlite database %s; exiting without serving\n", f.db)
		} else {
			fmt.Fprintln(out, "initialized in-memory store; nothing persisted (use --storage sqlite --db to pre-bake a database)")
		}
		return srv.Stop(context.Background())
	}

	if err := srv.Start(); err != nil {
		return err
	}
	fmt.Fprintf(out, "cinc-server-ng listening on %s\n", srv.URL())
	fmt.Fprintf(out, "  orgs: %s\n  admin user: %s (auth %s, acl-enforcement %s)\n",
		f.orgsCSV, srv.AdminName(), authState(f.noAuth), enforceState(f.enforceACLs))
	if f.storage == "sqlite" {
		fmt.Fprintf(out, "  storage: sqlite (%s)\n", f.db)
	} else {
		fmt.Fprintf(out, "  storage: memory (ephemeral)\n")
	}
	if f.repo != "" {
		fmt.Fprintf(out, "  loaded chef-repo from %s\n", f.repo)
	}
	if f.state != "" {
		fmt.Fprintf(out, "  loaded server state from %s\n", f.state)
	}
	statsUser, statsPassword := srv.StatsCredentials()
	fmt.Fprintln(out, statsBanner(statsUser, statsPassword, f.statsPassword == "", f.noAuth))
	if !f.noAuth {
		webuiSrc := "admin key"
		if f.webuiKey != "" {
			webuiSrc = f.webuiKey
		}
		fmt.Fprintf(out, "  webui impersonation: enabled (key: %s)\n", webuiSrc)
	}

	if f.externalURL != "" {
		fmt.Fprintf(out, "  external url: %s\n", f.externalURL)
	}

	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)
	return serveUntilSignal(srv, sigs, f.shutdownDelay, f.shutdownTimeout, out)
}

// serveUntilSignal runs a started server until SIGTERM or SIGINT, reloading the
// TLS certificate on each SIGHUP. Stopping drains first: for delay, /_status
// fails so a load balancer stops routing here while requests are still served
// (a second stop signal cuts the wait short). Then in-flight requests get up to
// timeout to finish before their connections are cut.
func serveUntilSignal(srv *server.Server, sigs <-chan os.Signal, delay, timeout time.Duration, out io.Writer) error {
	for sig := range sigs {
		if sig != syscall.SIGHUP {
			break
		}
		if err := srv.ReloadTLS(); err != nil {
			fmt.Fprintf(out, "SIGHUP: TLS not reloaded: %v\n", err)
			continue
		}
		fmt.Fprintln(out, "SIGHUP: reloaded TLS certificate")
	}

	if delay > 0 {
		srv.Drain()
		fmt.Fprintf(out, "draining for %s (signal again to stop now)...\n", delay)
		timer := time.NewTimer(delay)
	wait:
		for {
			select {
			case <-timer.C:
				break wait
			case sig := <-sigs:
				if sig != syscall.SIGHUP {
					timer.Stop()
					break wait
				}
			}
		}
	}

	fmt.Fprintln(out, "shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return srv.Stop(ctx)
}

// envOr returns the value of environment variable key, or def when it is unset
// or empty. It lets storage flags default from CINC_SERVER_NG_* (handy in containers).
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func splitCSV(s string) []string {
	var out []string
	for part := range strings.SplitSeq(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// statsBanner describes how to reach /_stats. A generated password is printed,
// since the banner is the only place an operator can read it; a configured one
// is theirs already and is not echoed into logs.
func statsBanner(user, password string, generated, noAuth bool) string {
	switch {
	case noAuth:
		return "  stats: GET /_stats is open (auth disabled)"
	case generated:
		return fmt.Sprintf("  stats: GET /_stats with HTTP Basic user %q, password %q (generated; set --stats-password or CINC_SERVER_NG_STATS_PASSWORD to fix it)", user, password)
	default:
		return fmt.Sprintf("  stats: GET /_stats with HTTP Basic user %q (password configured)", user)
	}
}

func authState(disabled bool) string {
	if disabled {
		return "disabled"
	}
	return "enabled"
}

func enforceState(enabled bool) string {
	if enabled {
		return "enabled"
	}
	return "permissive"
}
