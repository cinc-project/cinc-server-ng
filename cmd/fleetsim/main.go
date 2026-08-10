// Command fleetsim drives realistic steady-state check-in traffic against a
// cinc-server-ng org. It discovers the existing fleet, marks a deterministic 2% as
// "stuck" (they never check in, so their ohai_time goes stale), and drives every
// other node on a chef-client-style cadence: a check-in every interval plus up
// to splay of jitter, with the whole schedule compressed by --speed. Each
// check-in does GET /nodes/{name} -> stamp automatic.ohai_time = now -> PUT.
//
// This is a development tool; it is not built into the cinc-server-ng binary.
//
// Example:
//
//	go run ./cmd/fleetsim -base http://127.0.0.1:8902/organizations/acme
//	go run ./cmd/fleetsim -base http://127.0.0.1:8903/organizations/acme \
//	    -user pivotal -keypem /tmp/pivotal.pem -speed 60
package main

import (
	"context"
	"flag"
	"fmt"
	"hash/fnv"
	"log"
	"math/rand"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// config is a parsed, validated run configuration.
type config struct {
	client       *client
	interval     time.Duration
	splay        time.Duration
	speed        float64
	stuckFrac    float64
	seed         int64
	concurrency  int
	summaryEvery time.Duration
}

// stats are the live counters reported in the periodic summary.
type stats struct {
	checkins int64
	errors   int64
}

func main() {
	base := flag.String("base", "", "org URL, e.g. http://127.0.0.1:8902/organizations/acme")
	user := flag.String("user", "", "signing actor (empty = unsigned)")
	keyPEM := flag.String("keypem", "", "PEM private key path for signing")
	interval := flag.Duration("interval", 30*time.Minute, "simulated time between a node's check-ins")
	splay := flag.Duration("splay", 30*time.Minute, "max extra random jitter per cycle")
	speed := flag.Float64("speed", 1.0, "time-compression multiplier (60 = 30m sim is 30s real)")
	stuck := flag.Float64("stuck", 0.02, "fraction of the fleet that never checks in")
	seed := flag.Int64("seed", 1, "RNG seed for reproducible stuck-set and jitter")
	conc := flag.Int("concurrency", 64, "cap on in-flight HTTP requests")
	timeoutMS := flag.Int("timeout", 15000, "per-request timeout (ms)")
	flag.Parse()

	if *base == "" {
		fmt.Fprintln(os.Stderr, "need -base")
		os.Exit(2)
	}
	c, err := newClient(*base, *user, *keyPEM, time.Duration(*timeoutMS)*time.Millisecond)
	if err != nil {
		log.Fatalf("client: %v", err)
	}
	cfg := config{
		client: c, interval: *interval, splay: *splay, speed: *speed,
		stuckFrac: *stuck, seed: *seed, concurrency: *conc, summaryEvery: 30 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, cfg); err != nil {
		log.Fatalf("run: %v", err)
	}
}

// run discovers the fleet, marks the stuck fraction, and drives a check-in
// goroutine for every converging node until ctx is cancelled.
func run(ctx context.Context, cfg config) error {
	nodes, err := discover(ctx, cfg.client)
	if err != nil {
		return fmt.Errorf("discover: %w", err)
	}
	names := make([]string, len(nodes))
	for i, n := range nodes {
		names[i] = n.name
	}
	stuck := selectStuck(names, cfg.stuckFrac, rand.New(rand.NewSource(cfg.seed)))

	converging := len(nodes) - len(stuck)
	log.Printf("fleet: %d nodes, %d converging, %d stuck (interval=%v splay=%v speed=%gx)",
		len(nodes), converging, len(stuck), cfg.interval, cfg.splay, cfg.speed)

	sem := make(chan struct{}, cfg.concurrency)
	var st stats
	var wg sync.WaitGroup
	for _, n := range nodes {
		if stuck[n.name] {
			continue
		}
		wg.Add(1)
		go func(n *node) {
			defer wg.Done()
			nodeLoop(ctx, cfg, n, sem, &st)
		}(n)
	}
	go summaryLoop(ctx, cfg, &st, len(nodes), converging, len(stuck))

	wg.Wait()
	log.Printf("stopped: %d check-ins, %d errors",
		atomic.LoadInt64(&st.checkins), atomic.LoadInt64(&st.errors))
	return nil
}

// nodeLoop runs one node's lifetime: an initial splay, then a check-in every
// period until ctx is cancelled. Each node has its own rng (seeded from the
// global seed XOR the node name) so jitter is reproducible and goroutine-safe.
func nodeLoop(ctx context.Context, cfg config, n *node, sem chan struct{}, st *stats) {
	rng := rand.New(rand.NewSource(cfg.seed ^ int64(nameHash(n.name))))
	if !sleep(ctx, initialSplay(cfg, rng)) {
		return
	}
	for {
		checkInOnce(ctx, cfg, n, sem, st)
		if !sleep(ctx, period(cfg.interval, cfg.splay, cfg.speed, rng)) {
			return
		}
	}
}

// checkInOnce performs a single check-in under the concurrency semaphore,
// updating stats. Errors are counted and logged but never fatal. A check-in
// aborted by ctx cancellation (shutdown) is not logged as an error.
func checkInOnce(ctx context.Context, cfg config, n *node, sem chan struct{}, st *stats) {
	select {
	case sem <- struct{}{}:
	case <-ctx.Done():
		return
	}
	defer func() { <-sem }()
	if err := cfg.client.checkIn(ctx, n, time.Now().Unix()); err != nil {
		if ctx.Err() != nil {
			return // shutting down; the cancellation is expected, not a failure
		}
		atomic.AddInt64(&st.errors, 1)
		log.Printf("check-in %s: %v", n.name, err)
		return
	}
	atomic.AddInt64(&st.checkins, 1)
}

// initialSplay is the one-time startup delay before a node's first check-in, so
// the fleet is desynchronized from the start.
func initialSplay(cfg config, rng *rand.Rand) time.Duration {
	if cfg.splay <= 0 {
		return 0
	}
	speed := cfg.speed
	if speed <= 0 {
		speed = 1
	}
	return time.Duration(float64(rng.Int63n(int64(cfg.splay))) / speed)
}

// sleep waits d or until ctx is cancelled; it returns false if cancelled.
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// summaryLoop logs a periodic fleet summary until ctx is cancelled.
func summaryLoop(ctx context.Context, cfg config, st *stats, total, converging, stuck int) {
	t := time.NewTicker(cfg.summaryEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			log.Printf("summary: %d/%d converging, %d stuck | %d check-ins, %d errors",
				converging, total, stuck, atomic.LoadInt64(&st.checkins), atomic.LoadInt64(&st.errors))
		}
	}
}

// nameHash is a stable 32-bit hash of a node name, used to seed its rng.
func nameHash(s string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(s))
	return h.Sum32()
}
