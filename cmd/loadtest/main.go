// Command loadtest is a small HTTP benchmark harness for comparing cinc-server-ng
// against other Chef Infra Server implementations (notably the chef-zero gem).
// It seeds an organization with nodes, then measures, per operation:
//
//   - cold ms : latency of the first request on a fresh connection
//   - p50/p95 : warm steady-state latency over many sequential requests
//   - QPS@1   : single-connection throughput
//   - QPS@N   : throughput at concurrency N
//
// It can talk to a server that requires Mixlib authentication (--user/--keypem):
// each operation is signed exactly once and the signed headers are replayed, so
// the throughput numbers reflect the server's signature-verification cost rather
// than the client's RSA-signing cost.
//
// This is a development tool; it is not built into the cinc-server-ng binary.
//
// Example:
//
//	go run ./cmd/loadtest --base http://127.0.0.1:8902/organizations/acme --label cinc-noauth
//	go run ./cmd/loadtest --base http://127.0.0.1:8903/organizations/acme \
//	    --user pivotal --keypem /tmp/pivotal.pem --label cinc-auth
package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tas50/cinc-server-ng/internal/auth"
)

var (
	base      = flag.String("base", "", "base URL including /organizations/{org}")
	user      = flag.String("user", "", "actor name for signed requests (empty = unsigned)")
	keyPEM    = flag.String("keypem", "", "path to a PEM private key for signing")
	seedN     = flag.Int("seed", 500, "number of nodes to seed")
	conc      = flag.Int("conc", 10, "concurrency for the QPS phase")
	durMS     = flag.Int("dur", 3000, "QPS phase duration per op (ms)")
	warmN     = flag.Int("warm", 3000, "sequential samples for the warm phase")
	timeoutMS = flag.Int("timeout", 15000, "per-request timeout (ms)")
	label     = flag.String("label", "server", "label for output")
	caCert    = flag.String("cacert", "", "PEM certificate to trust in addition to the system roots, for a server using its own CA")
	chefVer   = flag.String("chefversion", "18.10.17", "value for the X-Chef-Version header, which a Chef Infra Server front end uses to tell an API client from a browser")
)

var signer struct {
	on   bool
	key  *rsa.PrivateKey
	user string
}

type op struct{ name, method, path, body string }

func main() {
	flag.Parse()
	if *base == "" {
		fmt.Fprintln(os.Stderr, "need --base")
		os.Exit(2)
	}
	if *user != "" && *keyPEM != "" {
		pem, err := os.ReadFile(*keyPEM)
		must(err)
		k, err := auth.ParsePrivateKey(pem)
		must(err)
		signer.on, signer.key, signer.user = true, k, *user
	}

	fmt.Printf("== %s (%s, auth=%v) ==\n", *label, *base, signer.on)
	seed(*seedN)

	// The cold sample of each op is its first request after seeding. cinc-server-ng's
	// match-all (*:*) search returns whole objects without flattening, so the
	// "search *:*" op does not warm the node flatten cache: the later "search
	// filtered" cold therefore measures a genuine cold index build rather than
	// inheriting a cache the *:* op filled. (chef-zero re-flattens every query, so
	// its cold numbers are independent regardless of order.)
	ops := []op{
		{"GET node", "GET", "/nodes/node0", ""},
		{"GET node list", "GET", "/nodes", ""},
		{"PUT node", "PUT", "/nodes/node0", nodeBody("node0", "production", "updated")},
		{"search *:*", "GET", "/search/node?q=*:*", ""},
		{"search filtered", "GET", "/search/node?q=chef_environment:production", ""},
	}
	presign(ops)

	fmt.Printf("%-18s %9s %9s %9s %12s %12s\n",
		"operation", "cold ms", "p50 ms", "p95 ms", "QPS@1", fmt.Sprintf("QPS@%d", *conc))
	for _, o := range ops {
		cold := timeOne(o)
		p50, p95, qps1 := warmPhase(o, *warmN)
		qpsC := qpsPhase(o, *conc, time.Duration(*durMS)*time.Millisecond)
		fmt.Printf("%-18s %9s %9s %9s %12s %12s\n",
			o.name, f(cold), f(p50), f(p95), n(qps1), n(qpsC))
		time.Sleep(500 * time.Millisecond) // let a fragile server drain between ops
	}
}

func nodeBody(name, env, bar string) string {
	return fmt.Sprintf(`{"name":"%s","chef_environment":"%s","json_class":"Chef::Node","chef_type":"node",`+
		`"normal":{"foo":{"bar":"%s"},"tags":["a","b","c"]},`+
		`"automatic":{"os":"linux","memory":{"total":"16gb"},"ipaddress":"10.0.0.1",`+
		`"network":{"interfaces":{"eth0":{"addr":"10.0.0.1"}}}},`+
		`"default":{},"override":{},"run_list":["recipe[nginx]","recipe[base]"]}`, name, env, bar)
}

func seed(count int) {
	c := newClient()
	created := 0
	for i := range count {
		env := "production"
		if i%2 == 1 {
			env = "staging"
		}
		body := nodeBody(fmt.Sprintf("node%d", i), env, fmt.Sprintf("v%d", i))
		switch status(c, signReq("POST", *base+"/nodes", body)) {
		case 201:
			created++
		case 409:
			status(c, signReq("PUT", fmt.Sprintf("%s/nodes/node%d", *base, i), body))
		}
	}
	fmt.Printf("seeded %d nodes (%d newly created)\n", count, created)
}

// signReq builds a request and signs it inline (used only for one-time seeding).
func signReq(method, url, body string) *http.Request {
	req := newReq(method, url, body)
	if signer.on {
		ts := time.Now().UTC().Format(time.RFC3339)
		must(auth.SignRequest(req, signer.user, ts, []byte(body), signer.key))
	}
	return req
}

func newReq(method, url, body string) *http.Request {
	var r io.Reader
	if body != "" {
		r = bytes.NewReader([]byte(body))
	}
	req, err := http.NewRequest(method, url, r)
	must(err)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Ops-Server-API-Version", "1")
	// A Chef Infra Server front end answers requests without this with an HTML
	// landing page instead of routing them to the API.
	req.Header.Set("X-Chef-Version", *chefVer)
	return req
}

// signedHeaders holds each op's signed header set, computed exactly once so the
// hot path replays them instead of paying per-request RSA-signing cost.
var signedHeaders = map[string]http.Header{}

func presign(ops []op) {
	if !signer.on {
		return
	}
	for _, o := range ops {
		signedHeaders[o.name] = signReq(o.method, *base+o.path, o.body).Header.Clone()
	}
}

func cloneReq(o op) *http.Request {
	req := newReq(o.method, *base+o.path, o.body)
	if signer.on {
		maps.Copy(req.Header, signedHeaders[o.name])
	}
	return req
}

func newClient() *http.Client {
	tr := &http.Transport{MaxIdleConns: 256, MaxIdleConnsPerHost: 256}
	if *caCert != "" {
		// A real Chef Infra Server serves its own certificate. Trust that CA
		// rather than skipping verification: a benchmark that talks to whatever
		// answers is not measuring what it claims to.
		pem, err := os.ReadFile(*caCert)
		must(err)
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			must(fmt.Errorf("cacert %q is not a valid PEM certificate", *caCert))
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{
		Timeout:   time.Duration(*timeoutMS) * time.Millisecond,
		Transport: tr,
	}
}

// status sends req on c, draining and closing the body, returning the status
// code (0 on transport error).
func status(c *http.Client, req *http.Request) int {
	resp, err := c.Do(req)
	if err != nil {
		return 0
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

// timeOne measures the first request on a brand-new connection (genuine cold).
// Returns -1 on error.
func timeOne(o op) float64 {
	c := newClient()
	start := time.Now()
	if status(c, cloneReq(o)) == 0 {
		return -1
	}
	return msSince(start)
}

// warmPhase measures sequential steady-state latency and single-connection QPS.
func warmPhase(o op, samples int) (p50, p95, qps1 float64) {
	c := newClient()
	for range 20 { // warm-up
		status(c, cloneReq(o))
	}
	lat := make([]float64, 0, samples)
	total := time.Duration(0)
	for range samples {
		s := time.Now()
		if status(c, cloneReq(o)) == 0 {
			continue
		}
		d := time.Since(s)
		total += d
		lat = append(lat, float64(d.Microseconds())/1000.0)
	}
	if len(lat) == 0 {
		return -1, -1, -1
	}
	sort.Float64s(lat)
	return lat[len(lat)*50/100], lat[len(lat)*95/100], float64(len(lat)) / total.Seconds()
}

// qpsPhase measures throughput at concurrency c over dur, counting only
// successful (2xx) responses. Idle connections are closed afterward so a fragile
// server can recover before the next op.
func qpsPhase(o op, c int, dur time.Duration) float64 {
	var ok int64
	deadline := time.Now().Add(dur)
	clients := make([]*http.Client, c)
	var wg sync.WaitGroup
	start := time.Now()
	for w := range c {
		clients[w] = newClient()
		wg.Add(1)
		go func(cl *http.Client) {
			defer wg.Done()
			for time.Now().Before(deadline) {
				if code := status(cl, cloneReq(o)); code >= 200 && code < 300 {
					atomic.AddInt64(&ok, 1)
				}
			}
		}(clients[w])
	}
	wg.Wait()
	elapsed := time.Since(start)
	for _, cl := range clients {
		cl.CloseIdleConnections()
	}
	return float64(ok) / elapsed.Seconds()
}

func msSince(t time.Time) float64 { return float64(time.Since(t).Microseconds()) / 1000.0 }

func f(v float64) string {
	if v < 0 {
		return "err"
	}
	return fmt.Sprintf("%.3f", v)
}

func n(v float64) string {
	if v < 0 {
		return "err"
	}
	return fmt.Sprintf("%.0f", v)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
