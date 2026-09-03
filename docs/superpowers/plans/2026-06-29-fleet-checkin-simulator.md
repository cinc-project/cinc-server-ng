# Fleet check-in simulator (`cmd/fleetsim`) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A standalone `cmd/fleetsim` tool that discovers a cinc-server-ng fleet and drives realistic steady-state check-in traffic — most nodes refresh `ohai_time` on a chef-client-style cadence, a deterministic 2% never check in.

**Architecture:** One goroutine per converging node, each self-scheduling its check-ins via `sleep(initialSplay)` then a loop of `checkin(); sleep(interval + rand[0,splay))/speed`. Each check-in does `GET /nodes/{name}` → stamp `automatic.ohai_time = now` → `PUT /nodes/{name}`. A single admin actor signs requests (unsigned when no key). Logic is split into pure, unit-testable functions plus one `run()` orchestrator with an end-to-end test against an in-process `server.New`.

**Tech Stack:** Go 1.26, `net/http`, `math/rand` (v1), `internal/auth` for Mixlib signing, `server` package for the e2e test.

## Global Constraints

- Module path: `github.com/cinc-project/cinc-server-ng`.
- Go version floor: `go 1.26.3` (per `go.mod`).
- RNG: use `math/rand` (v1), matching `cmd/seedgen`. Never `math/rand/v2`.
- Not built into the `cinc-server-ng` binary — this is a dev tool like `cmd/loadtest`.
- Errors are surfaced, never silently swallowed: discovery failure is fatal; per-check-in errors are counted + logged but non-fatal.
- `ohai_time` is always stamped with real wall-clock `time.Now().Unix()`, regardless of `--speed`.
- Run `go test ./cmd/fleetsim/ && go vet ./cmd/fleetsim/` before each commit; `make test && make vet` before the final commit.

---

### Task 1: `period()` — per-cycle sleep duration

**Files:**
- Create: `cmd/fleetsim/schedule.go`
- Test: `cmd/fleetsim/schedule_test.go`

**Interfaces:**
- Produces: `func period(interval, splay time.Duration, speed float64, rng *rand.Rand) time.Duration`

- [ ] **Step 1: Write the failing test**

```go
package main

import (
	"math/rand"
	"testing"
	"time"
)

func TestPeriodWithinBounds(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	interval, splay := 30*time.Minute, 30*time.Minute
	for range 1000 {
		d := period(interval, splay, 1, rng)
		if d < interval || d >= interval+splay {
			t.Fatalf("period %v out of [%v, %v)", d, interval, interval+splay)
		}
	}
}

func TestPeriodNoSplayExact(t *testing.T) {
	d := period(10*time.Minute, 0, 1, rand.New(rand.NewSource(1)))
	if d != 10*time.Minute {
		t.Fatalf("period = %v, want 10m", d)
	}
}

func TestPeriodSpeedScales(t *testing.T) {
	d := period(60*time.Minute, 0, 60, rand.New(rand.NewSource(1)))
	if d != time.Minute {
		t.Fatalf("period = %v, want 1m", d)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/fleetsim/ -run TestPeriod -v`
Expected: FAIL — `undefined: period`

- [ ] **Step 3: Write minimal implementation**

```go
package main

import (
	"math/rand"
	"time"
)

// period returns the wall-clock duration a converging node sleeps before its
// next check-in: a base interval plus up to splay of random jitter, compressed
// by speed. With splay==0 it is exactly interval/speed. speed<=0 is treated as 1.
func period(interval, splay time.Duration, speed float64, rng *rand.Rand) time.Duration {
	sim := interval
	if splay > 0 {
		sim += time.Duration(rng.Int63n(int64(splay)))
	}
	if speed <= 0 {
		speed = 1
	}
	return time.Duration(float64(sim) / speed)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./cmd/fleetsim/ -run TestPeriod -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add cmd/fleetsim/schedule.go cmd/fleetsim/schedule_test.go
git commit -m "feat(fleetsim): period() per-cycle check-in scheduling"
```

---

### Task 2: `stampOhaiTime()` — pure JSON mutation

**Files:**
- Create: `cmd/fleetsim/checkin.go`
- Test: `cmd/fleetsim/checkin_test.go`

**Interfaces:**
- Produces: `func stampOhaiTime(body []byte, ts int64) ([]byte, error)`

- [ ] **Step 1: Write the failing test**

```go
package main

import (
	"encoding/json"
	"testing"
)

func TestStampOhaiTimeSetsTimestamp(t *testing.T) {
	out, err := stampOhaiTime([]byte(`{"name":"n1","automatic":{"ohai_time":1.0,"fqdn":"n1.example.com"}}`), 1780000000)
	if err != nil {
		t.Fatal(err)
	}
	var node map[string]any
	json.Unmarshal(out, &node)
	auto := node["automatic"].(map[string]any)
	if auto["ohai_time"].(float64) != 1780000000 {
		t.Fatalf("ohai_time = %v, want 1780000000", auto["ohai_time"])
	}
	if auto["fqdn"] != "n1.example.com" {
		t.Fatalf("clobbered fqdn: %v", auto["fqdn"])
	}
	if node["name"] != "n1" {
		t.Fatalf("clobbered name: %v", node["name"])
	}
}

func TestStampOhaiTimeCreatesAutomatic(t *testing.T) {
	out, err := stampOhaiTime([]byte(`{"name":"n1"}`), 42)
	if err != nil {
		t.Fatal(err)
	}
	var node map[string]any
	json.Unmarshal(out, &node)
	auto, ok := node["automatic"].(map[string]any)
	if !ok || auto["ohai_time"].(float64) != 42 {
		t.Fatalf("automatic not created: %v", node)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/fleetsim/ -run TestStampOhaiTime -v`
Expected: FAIL — `undefined: stampOhaiTime`

- [ ] **Step 3: Write minimal implementation**

Create `cmd/fleetsim/checkin.go` with just the imports and this function for now (the client and `checkIn` arrive in Task 3):

```go
package main

import "encoding/json"

// stampOhaiTime returns body with automatic.ohai_time set to ts (Unix seconds),
// creating the automatic map if absent. Every other field is preserved.
func stampOhaiTime(body []byte, ts int64) ([]byte, error) {
	var node map[string]any
	if err := json.Unmarshal(body, &node); err != nil {
		return nil, err
	}
	automatic, ok := node["automatic"].(map[string]any)
	if !ok {
		automatic = map[string]any{}
		node["automatic"] = automatic
	}
	automatic["ohai_time"] = float64(ts)
	return json.Marshal(node)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./cmd/fleetsim/ -run TestStampOhaiTime -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add cmd/fleetsim/checkin.go cmd/fleetsim/checkin_test.go
git commit -m "feat(fleetsim): stampOhaiTime() node ohai_time mutation"
```

---

### Task 3: HTTP client, signing, and `checkIn()`

**Files:**
- Create: `cmd/fleetsim/fleet.go` (the `node` type lives here, used by `checkIn`)
- Modify: `cmd/fleetsim/checkin.go` (add `signer`, `client`, `newClient`, `do`, `checkIn`)
- Test: `cmd/fleetsim/checkin_test.go` (add an httptest case)

**Interfaces:**
- Consumes: `stampOhaiTime` (Task 2); `auth.ParsePrivateKey([]byte) (*rsa.PrivateKey, error)`, `auth.SignRequest(*http.Request, userID, timestamp string, body []byte, *rsa.PrivateKey) error`.
- Produces:
  - `type node struct { name string; body []byte }`
  - `type client struct { ... }`
  - `func newClient(base, user, keyPEMPath string, timeout time.Duration) (*client, error)`
  - `func (c *client) do(method, path string, body []byte) ([]byte, int, error)`
  - `func (c *client) checkIn(n *node, now int64) error`

- [ ] **Step 1: Write the failing test** (append to `cmd/fleetsim/checkin_test.go`)

```go
import (
	"io"
	"net/http"
	"net/http/httptest"
	"time"
)

func TestCheckInStampsAndPuts(t *testing.T) {
	var putBody []byte
	mux := http.NewServeMux()
	mux.HandleFunc("GET /nodes/n1", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"name":"n1","automatic":{"ohai_time":1.0}}`))
	})
	mux.HandleFunc("PUT /nodes/n1", func(w http.ResponseWriter, r *http.Request) {
		putBody, _ = io.ReadAll(r.Body)
		w.Write([]byte(`{"name":"n1"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, err := newClient(srv.URL, "", "", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	n := &node{name: "n1", body: []byte(`{"name":"n1"}`)}
	if err := c.checkIn(n, 1780000000); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	json.Unmarshal(putBody, &got)
	auto := got["automatic"].(map[string]any)
	if auto["ohai_time"].(float64) != 1780000000 {
		t.Fatalf("PUT ohai_time = %v, want 1780000000", auto["ohai_time"])
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/fleetsim/ -run TestCheckIn -v`
Expected: FAIL — `undefined: newClient` / `undefined: node`

- [ ] **Step 3: Write minimal implementation**

Create `cmd/fleetsim/fleet.go`:

```go
package main

// node is one fleet member: its name and last-known full JSON body.
type node struct {
	name string
	body []byte
}
```

Add to `cmd/fleetsim/checkin.go` (update the import block to include the new packages):

```go
import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/cinc-project/cinc-server-ng/internal/auth"
)

// signer holds the single admin actor used to sign every request. A nil signer
// means unsigned (for a --no-auth server).
type signer struct {
	user string
	key  *rsa.PrivateKey
}

// client talks to one organization's API, optionally signing each request.
type client struct {
	http *http.Client
	base string // e.g. http://host/organizations/acme
	sign *signer
}

// newClient builds a client. When user and keyPEMPath are both set, requests are
// signed; otherwise they are sent unsigned.
func newClient(base, user, keyPEMPath string, timeout time.Duration) (*client, error) {
	c := &client{
		http: &http.Client{
			Timeout:   timeout,
			Transport: &http.Transport{MaxIdleConns: 256, MaxIdleConnsPerHost: 256},
		},
		base: base,
	}
	if user != "" && keyPEMPath != "" {
		pem, err := os.ReadFile(keyPEMPath)
		if err != nil {
			return nil, err
		}
		key, err := auth.ParsePrivateKey(pem)
		if err != nil {
			return nil, err
		}
		c.sign = &signer{user: user, key: key}
	}
	return c, nil
}

// do builds, signs, and sends a request to base+path, returning the response
// body and status code.
func (c *client) do(method, path string, body []byte) ([]byte, int, error) {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, c.base+path, r)
	if err != nil {
		return nil, 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Ops-Server-API-Version", "1")
	if c.sign != nil {
		ts := time.Now().UTC().Format(time.RFC3339)
		if err := auth.SignRequest(req, c.sign.user, ts, body, c.sign.key); err != nil {
			return nil, 0, err
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return out, resp.StatusCode, nil
}

// checkIn performs one simulated chef-client check-in for n: fetch the current
// node, stamp automatic.ohai_time with now, and PUT it back. On success the
// node's cached body is updated so the next cycle round-trips the latest state.
func (c *client) checkIn(n *node, now int64) error {
	body, status, err := c.do("GET", "/nodes/"+n.name, nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("GET node %s: status %d", n.name, status)
	}
	stamped, err := stampOhaiTime(body, now)
	if err != nil {
		return err
	}
	_, status, err = c.do("PUT", "/nodes/"+n.name, stamped)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("PUT node %s: status %d", n.name, status)
	}
	n.body = stamped
	return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./cmd/fleetsim/ -run TestCheckIn -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add cmd/fleetsim/fleet.go cmd/fleetsim/checkin.go cmd/fleetsim/checkin_test.go
git commit -m "feat(fleetsim): signing client and checkIn() GET-stamp-PUT round-trip"
```

---

### Task 4: `selectStuck()` — deterministic non-converging set

**Files:**
- Modify: `cmd/fleetsim/fleet.go`
- Test: `cmd/fleetsim/fleet_test.go`

**Interfaces:**
- Produces: `func selectStuck(names []string, frac float64, rng *rand.Rand) map[string]bool`

- [ ] **Step 1: Write the failing test**

```go
package main

import (
	"fmt"
	"math/rand"
	"reflect"
	"testing"
)

func TestSelectStuckCountAndDeterminism(t *testing.T) {
	var names []string
	for i := range 100 {
		names = append(names, fmt.Sprintf("node%02d", i))
	}
	a := selectStuck(names, 0.02, rand.New(rand.NewSource(7)))
	if len(a) != 2 {
		t.Fatalf("got %d stuck, want 2 (ceil(0.02*100))", len(a))
	}
	b := selectStuck(names, 0.02, rand.New(rand.NewSource(7)))
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("same seed produced different sets: %v vs %v", a, b)
	}
	c := selectStuck(names, 0.02, rand.New(rand.NewSource(8)))
	if reflect.DeepEqual(a, c) {
		t.Fatalf("different seeds produced identical sets")
	}
}

func TestSelectStuckCeil(t *testing.T) {
	// 0.02 * 3 = 0.06 -> ceil = 1
	got := selectStuck([]string{"a", "b", "c"}, 0.02, rand.New(rand.NewSource(1)))
	if len(got) != 1 {
		t.Fatalf("got %d, want 1", len(got))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/fleetsim/ -run TestSelectStuck -v`
Expected: FAIL — `undefined: selectStuck`

- [ ] **Step 3: Write minimal implementation** (append to `cmd/fleetsim/fleet.go`; add imports `math`, `math/rand`, `sort`)

```go
// selectStuck deterministically chooses ceil(frac*len(names)) node names that
// never check in. Sorting first makes the result independent of input order;
// the caller-seeded rng makes it reproducible.
func selectStuck(names []string, frac float64, rng *rand.Rand) map[string]bool {
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	rng.Shuffle(len(sorted), func(i, j int) { sorted[i], sorted[j] = sorted[j], sorted[i] })
	k := int(math.Ceil(frac * float64(len(sorted))))
	if k > len(sorted) {
		k = len(sorted)
	}
	stuck := make(map[string]bool, k)
	for _, name := range sorted[:k] {
		stuck[name] = true
	}
	return stuck
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./cmd/fleetsim/ -run TestSelectStuck -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add cmd/fleetsim/fleet.go cmd/fleetsim/fleet_test.go
git commit -m "feat(fleetsim): selectStuck() deterministic non-converging set"
```

---

### Task 5: `discover()` — read the fleet from the server

**Files:**
- Modify: `cmd/fleetsim/fleet.go`
- Test: `cmd/fleetsim/fleet_test.go`

**Interfaces:**
- Consumes: `client.do` (Task 3).
- Produces: `func discover(c *client) ([]*node, error)` — returns nodes sorted by name.

- [ ] **Step 1: Write the failing test** (append to `cmd/fleetsim/fleet_test.go`; add imports `net/http`, `net/http/httptest`, `time`)

```go
func TestDiscover(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /nodes", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"n1":"http://x/nodes/n1","n2":"http://x/nodes/n2"}`))
	})
	mux.HandleFunc("GET /nodes/{name}", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"name":%q}`, r.PathValue("name"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, _ := newClient(srv.URL, "", "", 5*time.Second)
	nodes, err := discover(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 || nodes[0].name != "n1" || nodes[1].name != "n2" {
		t.Fatalf("discover = %+v", nodes)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/fleetsim/ -run TestDiscover -v`
Expected: FAIL — `undefined: discover`

- [ ] **Step 3: Write minimal implementation** (append to `cmd/fleetsim/fleet.go`; add imports `encoding/json`, `fmt`, `net/http`)

```go
// discover reads the whole fleet from the server: list node names, then fetch
// each node's full body. Nodes are returned sorted by name.
func discover(c *client) ([]*node, error) {
	body, status, err := c.do("GET", "/nodes", nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("list nodes: status %d", status)
	}
	var list map[string]string
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(list))
	for name := range list {
		names = append(names, name)
	}
	sort.Strings(names)
	nodes := make([]*node, 0, len(names))
	for _, name := range names {
		nb, status, err := c.do("GET", "/nodes/"+name, nil)
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, fmt.Errorf("get node %s: status %d", name, status)
		}
		nodes = append(nodes, &node{name: name, body: nb})
	}
	return nodes, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./cmd/fleetsim/ -run TestDiscover -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add cmd/fleetsim/fleet.go cmd/fleetsim/fleet_test.go
git commit -m "feat(fleetsim): discover() reads the fleet from the server"
```

---

### Task 6: `run()` orchestrator, scheduler, and CLI

**Files:**
- Create: `cmd/fleetsim/main.go`
- Test: `cmd/fleetsim/main_test.go`

**Interfaces:**
- Consumes: `discover` (Task 5), `selectStuck` (Task 4), `period` (Task 1), `client.checkIn`/`newClient`/`client.do` (Task 3), `node` (Task 3).
- Produces:
  - `type config struct { client *client; interval, splay time.Duration; speed, stuckFrac float64; seed int64; concurrency int; summaryEvery time.Duration }`
  - `func run(ctx context.Context, cfg config) error`

- [ ] **Step 1: Write the failing test**

```go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"testing"
	"time"

	"github.com/cinc-project/cinc-server-ng/server"
)

func TestRunDrivesConvergingNotStuck(t *testing.T) {
	srv, err := server.New(server.Options{Orgs: []string{"acme"}, DisableAuth: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop(context.Background())

	base := srv.URL() + "/organizations/acme"
	c, _ := newClient(base, "", "", 5*time.Second)

	const N = 10
	names := make([]string, N)
	for i := range N {
		names[i] = fmt.Sprintf("node%02d", i)
		body := fmt.Sprintf(`{"name":%q,"chef_environment":"_default","automatic":{"ohai_time":1000.0}}`, names[i])
		if _, status, err := c.do("POST", "/nodes", []byte(body)); err != nil || status != http.StatusCreated {
			t.Fatalf("seed %s: status %d err %v", names[i], status, err)
		}
	}

	cfg := config{
		client: c, interval: 20 * time.Millisecond, splay: 10 * time.Millisecond,
		speed: 1, stuckFrac: 0.2, seed: 42, concurrency: 8, summaryEvery: time.Hour,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	if err := run(ctx, cfg); err != nil {
		t.Fatal(err)
	}

	stuck := selectStuck(names, cfg.stuckFrac, rand.New(rand.NewSource(cfg.seed)))
	if len(stuck) != 2 {
		t.Fatalf("expected 2 stuck, got %d", len(stuck))
	}
	for _, name := range names {
		body, status, _ := c.do("GET", "/nodes/"+name, nil)
		if status != http.StatusOK {
			t.Fatalf("get %s: status %d", name, status)
		}
		var n map[string]any
		json.Unmarshal(body, &n)
		ohai := n["automatic"].(map[string]any)["ohai_time"].(float64)
		if stuck[name] && ohai != 1000.0 {
			t.Errorf("stuck node %s checked in (ohai_time=%v)", name, ohai)
		}
		if !stuck[name] && ohai == 1000.0 {
			t.Errorf("converging node %s never checked in", name)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/fleetsim/ -run TestRun -v`
Expected: FAIL — `undefined: config` / `undefined: run`

- [ ] **Step 3: Write minimal implementation** (`cmd/fleetsim/main.go`)

```go
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
	nodes, err := discover(cfg.client)
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
		checkInOnce(cfg, n, sem, st)
		if !sleep(ctx, period(cfg.interval, cfg.splay, cfg.speed, rng)) {
			return
		}
	}
}

// checkInOnce performs a single check-in under the concurrency semaphore,
// updating stats. Errors are counted and logged but never fatal.
func checkInOnce(cfg config, n *node, sem chan struct{}, st *stats) {
	sem <- struct{}{}
	defer func() { <-sem }()
	if err := cfg.client.checkIn(n, time.Now().Unix()); err != nil {
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./cmd/fleetsim/ -run TestRun -v`
Expected: PASS

- [ ] **Step 5: Run the full package suite + vet**

Run: `go test ./cmd/fleetsim/ -race && go vet ./cmd/fleetsim/`
Expected: PASS, no vet complaints. (The `-race` run exercises the goroutine scheduler and shared stats/semaphore.)

- [ ] **Step 6: Commit**

```bash
git add cmd/fleetsim/main.go cmd/fleetsim/main_test.go
git commit -m "feat(fleetsim): run() orchestrator, per-node scheduler, and CLI"
```

---

### Task 7: Documentation and final verification

**Files:**
- Modify: `README.md` (if it carries a tools/commands list — add a one-line `cmd/fleetsim` entry mirroring how `cmd/loadtest` is described; skip if no such section exists).

- [ ] **Step 1: Check whether the README documents dev tools**

Run: `grep -n "loadtest\|seedgen" README.md`
Expected: either matching lines (add a sibling `fleetsim` entry in the same style) or no matches (skip the README edit — the package doc comment in `main.go` is the documentation, matching `cmd/loadtest`).

- [ ] **Step 2: If a tools section exists, add the entry**

Add a line next to the `loadtest`/`seedgen` entry, e.g.:

```markdown
- `cmd/fleetsim` — simulates steady-state fleet check-in traffic (most nodes refresh `ohai_time` every ~30m with splay; a deterministic 2% stay stale).
```

- [ ] **Step 3: Full project verification**

Run: `make test && make vet`
Expected: entire suite passes, no vet output.

- [ ] **Step 4: Manual smoke test (optional but recommended)**

```bash
# Terminal 1: a no-auth dev server seeded with the ACME fixture
make run-dev
# Terminal 2: drive it fast and watch check-ins land
go run ./cmd/fleetsim -base http://127.0.0.1:8902/organizations/acme -interval 30m -splay 30m -speed 120
```
Expected: a startup line reporting `N nodes, ~98% converging, ~2% stuck`, then periodic summaries with a rising check-in count.

- [ ] **Step 5: Commit (only if the README changed)**

```bash
git add README.md
git commit -m "docs: list cmd/fleetsim dev tool in README"
```

---

## Self-Review

**Spec coverage:**
- Discover fleet from server → Task 5 (`discover`). ✓
- 2% chosen at startup, deterministic → Task 4 (`selectStuck`) + Task 6 wiring. ✓
- Converge every interval with splay, ≥ interval spacing → Task 1 (`period`) + Task 6 (`nodeLoop`). ✓
- Single admin key / unsigned → Task 3 (`newClient`/`signer`). ✓
- `--speed` time compression, real-wall-clock `ohai_time` → Task 1 + Task 6 (`time.Now().Unix()`). ✓
- Check-in shape GET→stamp→PUT → Task 2 + Task 3. ✓
- Run until SIGINT, periodic summary, non-fatal errors → Task 6. ✓
- Flags + defaults → Task 6 `main()`. ✓
- Tests for `period`, `selectStuck`, end-to-end → Tasks 1, 4, 6. ✓

**Placeholder scan:** No TBD/TODO; every code step shows complete code. ✓

**Type consistency:** `node{name, body}`, `client.do(method, path, body) ([]byte, int, error)`, `client.checkIn(*node, int64) error`, `period(interval, splay, speed, rng)`, `selectStuck(names, frac, rng) map[string]bool`, `discover(*client) ([]*node, error)`, `config{...}`, `run(ctx, config) error` — names/signatures match across Tasks 1–7. ✓
