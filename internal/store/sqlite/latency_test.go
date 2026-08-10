package sqlite_test

import (
	"fmt"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tas50/cinc-server-ng/internal/store/sqlite"
)

// Sustained-write latency distribution.
//
// Mean throughput hides stalls, and a fleet server is judged on whether a
// check-in ever blocks for a noticeable time, not on its average. WAL mode
// defers fsync work to a checkpoint, which by default runs on whichever writer
// happens to cross the WAL size threshold — so the cost lands on one unlucky
// request rather than being spread. These report the tail so that shows up.

// pct returns the p-th percentile of a sorted duration slice.
func pct(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	i := int(float64(len(sorted)-1) * p)
	return sorted[i]
}

// benchWriteLatency drives concurrent writers for a fixed number of writes and
// reports the latency distribution rather than the mean.
func benchWriteLatency(b *testing.B, opts ...sqlite.Option) {
	const (
		writers      = 16
		perWriter    = 400
		distinctKeys = 2048
	)
	be, err := sqlite.Open(filepath.Join(b.TempDir(), "lat.db"), opts...)
	if err != nil {
		b.Fatal(err)
	}
	defer be.Close()

	body := nodeBody("node0")
	samples := make([][]time.Duration, writers)
	var seq atomic.Int64

	b.ResetTimer()
	start := time.Now()
	var wg sync.WaitGroup
	wg.Add(writers)
	for w := range writers {
		go func(w int) {
			defer wg.Done()
			local := make([]time.Duration, 0, perWriter)
			for range perWriter {
				key := fmt.Sprintf("node%d", int(seq.Add(1))%distinctKeys)
				t0 := time.Now()
				if err := be.Put("acme", "nodes", key, body); err != nil {
					b.Error(err)
					return
				}
				local = append(local, time.Since(t0))
			}
			samples[w] = local
		}(w)
	}
	wg.Wait()
	elapsed := time.Since(start)
	b.StopTimer()

	var all []time.Duration
	for _, s := range samples {
		all = append(all, s...)
	}
	slices.Sort(all)

	b.ReportMetric(float64(len(all))/elapsed.Seconds(), "writes/s")
	b.ReportMetric(float64(pct(all, 0.50).Microseconds()), "p50-us")
	b.ReportMetric(float64(pct(all, 0.99).Microseconds()), "p99-us")
	b.ReportMetric(float64(all[len(all)-1].Microseconds()), "max-us")
	// ns/op over the whole run is meaningless here; the metrics above are.
	b.ReportMetric(0, "ns/op")
}

// These report a distribution rather than a per-op mean, so run them once:
//
//	go test ./internal/store/sqlite/ -run XXX -bench WriteLatency -benchtime 1x
//
// Repeating the fixed workload would only average distributions together.
func BenchmarkWriteLatency(b *testing.B) {
	benchWriteLatency(b)
}

func BenchmarkWriteLatencyGroupCommit(b *testing.B) {
	benchWriteLatency(b, sqlite.WithGroupCommit())
}
