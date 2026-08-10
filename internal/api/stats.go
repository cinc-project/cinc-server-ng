package api

import (
	"encoding/json"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/tas50/cinc-server-ng/internal/metrics"
)

// Server metrics.
//
// /_stats used to return an empty array, which meant a server absorbing fleet
// load could not be operated: there was no way to see request rate, tail
// latency, or whether the work per request was growing. What is exposed here is
// chosen to answer the questions that actually decide whether this server keeps
// up:
//
//   - How many requests, how fast, and what fraction are failing.
//   - How much store work a request costs. Read amplification is what sets
//     throughput on a durable backend, so reads, writes and scans are counted
//     separately; reads far outrunning writes on the check-in path is the
//     signal to look at.
//   - Whether searches are being answered from the index. A query the planner
//     cannot handle silently falls back to scanning the whole collection, which
//     is exactly the cost the index exists to avoid — so the fallback is
//     counted rather than left invisible.

// latencyBuckets spans the range a request can plausibly take here, from an
// in-memory read to a search over a large collection.
var latencyBuckets = []float64{
	0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5,
}

// Outcome labels for the request counter, fixed so cardinality cannot grow.
const (
	outcomeOK           = "2xx"
	outcomeRedirect     = "3xx"
	outcomeClientError  = "4xx"
	outcomeServerError  = "5xx"
	outcomeUnauthorized = "401"
)

// searchPlanned / searchScanned label whether a query was resolved through the
// inverted index or fell back to a full scan.
const (
	searchPlanned = "indexed"
	searchScanned = "scanned"
)

// instruments holds the handles the hot paths record into.
type instruments struct {
	registry *metrics.Registry
	requests *metrics.Counter
	latency  *metrics.Histogram
	searches *metrics.Counter
	started  time.Time
}

// newInstruments registers everything the server reports.
func newInstruments(a *API) *instruments {
	r := metrics.NewRegistry()
	in := &instruments{
		registry: r,
		started:  time.Now(),
		requests: r.Counter("cinc_zero_http_requests_total",
			"HTTP requests served, by response class", "outcome",
			outcomeOK, outcomeRedirect, outcomeClientError, outcomeServerError, outcomeUnauthorized),
		latency: r.Histogram("cinc_zero_http_request_duration_seconds",
			"HTTP request latency", latencyBuckets),
		searches: r.Counter("cinc_zero_search_queries_total",
			"Search queries, by how they were resolved", "resolution",
			searchPlanned, searchScanned),
	}

	counts := a.store.Counts()
	if counts != nil {
		r.CounterFunc("cinc_zero_store_reads_total",
			"Single-object store reads. Compare with writes: the check-in path is read-dominated, "+
				"and read amplification is what limits throughput on a durable backend.",
			func() float64 { return float64(counts.Reads.Load()) })
		r.CounterFunc("cinc_zero_store_writes_total", "Object writes performed",
			func() float64 { return float64(counts.Writes.Load()) })
		r.CounterFunc("cinc_zero_store_deletes_total", "Object deletes performed",
			func() float64 { return float64(counts.Deletes.Load()) })
		r.CounterFunc("cinc_zero_store_scans_total",
			"Collection scans performed. A scan reads a whole collection, so a rising rate here "+
				"means work that grows with the size of the data.",
			func() float64 { return float64(counts.Scans.Load()) })
	}

	r.Gauge("cinc_zero_search_indexed_documents",
		"Documents currently held in the inverted search indexes",
		func() float64 { return float64(a.searchIdx.documents()) })
	r.Gauge("cinc_zero_uptime_seconds", "Seconds since this server started",
		func() float64 { return time.Since(in.started).Seconds() })
	r.Gauge("cinc_zero_goroutines", "Goroutines currently running",
		func() float64 { return float64(runtime.NumGoroutine()) })
	r.Gauge("cinc_zero_heap_bytes", "Heap memory currently allocated", func() float64 {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return float64(m.HeapAlloc)
	})
	return in
}

// statusRecorder captures the status code so the middleware can classify the
// response without the handlers having to report it.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (w *statusRecorder) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusRecorder) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

// Unwrap lets the standard library reach the underlying writer for interfaces
// this wrapper does not implement (flushing, hijacking).
func (w *statusRecorder) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Instrument wraps h so every request it serves is counted and timed. It is
// applied outside authentication, so requests rejected before routing are
// measured too — an unauthenticated flood is exactly the thing worth seeing.
func (a *API) Instrument(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		h.ServeHTTP(rec, r)
		a.stats.latency.Observe(time.Since(start).Seconds())
		a.stats.requests.With(outcomeFor(rec.status)).Inc()
	})
}

// outcomeFor maps a status to its counter label. 401 is broken out from the
// rest of 4xx because a rise in rejected credentials means something different
// from a rise in bad requests.
func outcomeFor(status int) string {
	switch {
	case status == http.StatusUnauthorized:
		return outcomeUnauthorized
	case status >= 500:
		return outcomeServerError
	case status >= 400:
		return outcomeClientError
	case status >= 300:
		return outcomeRedirect
	default:
		return outcomeOK
	}
}

// Metrics exposes the registry so an embedding program can gather the same
// numbers the endpoint serves.
func (a *API) Metrics() *metrics.Registry { return a.stats.registry }

// stats serves the metric families.
//
// The default remains a JSON array, which is what this endpoint has always
// returned and what any existing consumer expects. A caller that asks for
// text/plain — every scraper does — gets Prometheus exposition instead.
func (a *API) statsHandler(w http.ResponseWriter, r *http.Request) {
	families := a.stats.registry.Gather()
	if prefersText(r.Header.Get("Accept")) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_ = metrics.WriteText(w, families)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(families)
}

// prefersText reports whether the Accept header asks for the text exposition
// format. JSON wins ties, keeping the historical default.
func prefersText(accept string) bool {
	if accept == "" {
		return false
	}
	for _, part := range strings.Split(accept, ",") {
		media, _, _ := strings.Cut(strings.TrimSpace(part), ";")
		switch strings.TrimSpace(media) {
		case "application/json":
			return false
		case "text/plain":
			return true
		}
	}
	return false
}

// documents reports how many documents are held across every search index, so
// the memory the indexes account for is visible.
func (s *searchIndexes) documents() int {
	s.mu.RLock()
	indexes := make([]*collIndex, 0, len(s.m))
	for _, idx := range s.m {
		indexes = append(indexes, idx)
	}
	s.mu.RUnlock()

	total := 0
	for _, idx := range indexes {
		idx.mu.RLock()
		total += idx.size()
		idx.mu.RUnlock()
	}
	return total
}
