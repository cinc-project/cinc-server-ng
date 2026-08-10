package metrics_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/tas50/cinc-server-ng/internal/metrics"
)

func TestCounterCountsAndLabels(t *testing.T) {
	r := metrics.NewRegistry()
	reqs := r.Counter("http_requests_total", "requests served", "outcome", "ok", "error")

	reqs.With("ok").Add(3)
	reqs.With("error").Inc()
	// An unregistered label value must not panic or silently corrupt a series;
	// it is dropped, since label sets are fixed at registration.
	reqs.With("nonsense").Inc()

	fams := r.Gather()
	fam := findFamily(t, fams, "http_requests_total")
	if fam.Type != "COUNTER" {
		t.Errorf("type = %q, want COUNTER", fam.Type)
	}
	if got := seriesValue(t, fam, "ok"); got != 3 {
		t.Errorf("ok = %v, want 3", got)
	}
	if got := seriesValue(t, fam, "error"); got != 1 {
		t.Errorf("error = %v, want 1", got)
	}
	if len(fam.Metrics) != 2 {
		t.Errorf("got %d series, want only the registered label values", len(fam.Metrics))
	}
}

func TestGaugeReadsThroughOnEveryGather(t *testing.T) {
	r := metrics.NewRegistry()
	n := 0
	r.Gauge("live_value", "a value sampled at scrape time", func() float64 {
		n++
		return float64(n * 10)
	})
	if got := seriesValue(t, findFamily(t, r.Gather(), "live_value"), ""); got != 10 {
		t.Fatalf("first gather = %v, want 10", got)
	}
	if got := seriesValue(t, findFamily(t, r.Gather(), "live_value"), ""); got != 20 {
		t.Fatalf("second gather = %v, want 20 (gauges must be sampled per scrape)", got)
	}
}

func TestHistogramBucketsAreCumulative(t *testing.T) {
	r := metrics.NewRegistry()
	h := r.Histogram("latency_seconds", "how long", []float64{0.01, 0.1, 1})
	for _, v := range []float64{0.005, 0.05, 0.5, 5} {
		h.Observe(v)
	}
	fam := findFamily(t, r.Gather(), "latency_seconds")
	if fam.Type != "HISTOGRAM" {
		t.Errorf("type = %q, want HISTOGRAM", fam.Type)
	}
	// Prometheus histogram buckets are "less than or equal", so each bucket
	// includes everything below it.
	for _, c := range []struct {
		le   string
		want float64
	}{{"0.01", 1}, {"0.1", 2}, {"1", 3}, {"+Inf", 4}} {
		if got := bucketValue(t, fam, c.le); got != c.want {
			t.Errorf("bucket le=%s = %v, want %v", c.le, got, c.want)
		}
	}
	if fam.Sum != 5.555 {
		t.Errorf("sum = %v, want 5.555", fam.Sum)
	}
	if fam.Count != 4 {
		t.Errorf("count = %v, want 4", fam.Count)
	}
}

// The JSON form is what the /_stats endpoint has always returned, so it must
// stay an array of metric families that decodes cleanly.
func TestGatherEncodesAsJSONArray(t *testing.T) {
	r := metrics.NewRegistry()
	r.Counter("things_total", "things", "kind", "a").With("a").Inc()

	raw, err := json.Marshal(r.Gather())
	if err != nil {
		t.Fatal(err)
	}
	var families []map[string]any
	if err := json.Unmarshal(raw, &families); err != nil {
		t.Fatalf("not a JSON array of objects: %v (%s)", err, raw)
	}
	if len(families) != 1 || families[0]["name"] != "things_total" {
		t.Fatalf("unexpected payload: %s", raw)
	}
}

// Prometheus text is the format anything scraping this will actually speak.
func TestWriteTextExposition(t *testing.T) {
	r := metrics.NewRegistry()
	r.Counter("things_total", "how many things", "kind", "a", "b").With("a").Add(2)
	r.Histogram("latency_seconds", "how long", []float64{0.1}).Observe(0.05)

	var sb strings.Builder
	if err := metrics.WriteText(&sb, r.Gather()); err != nil {
		t.Fatal(err)
	}
	out := sb.String()
	for _, want := range []string{
		"# HELP things_total how many things",
		"# TYPE things_total counter",
		`things_total{kind="a"} 2`,
		`things_total{kind="b"} 0`,
		"# TYPE latency_seconds histogram",
		`latency_seconds_bucket{le="0.1"} 1`,
		`latency_seconds_bucket{le="+Inf"} 1`,
		"latency_seconds_sum 0.05",
		"latency_seconds_count 1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("exposition missing %q:\n%s", want, out)
		}
	}
}

// --- helpers ---

func findFamily(t *testing.T, fams []metrics.Family, name string) metrics.Family {
	t.Helper()
	for _, f := range fams {
		if f.Name == name {
			return f
		}
	}
	t.Fatalf("no family %q in %+v", name, fams)
	return metrics.Family{}
}

func seriesValue(t *testing.T, f metrics.Family, label string) float64 {
	t.Helper()
	for _, m := range f.Metrics {
		if label == "" && len(m.Labels) == 0 {
			return m.Value
		}
		for _, l := range m.Labels {
			if l.Value == label {
				return m.Value
			}
		}
	}
	t.Fatalf("no series %q in family %q", label, f.Name)
	return 0
}

func bucketValue(t *testing.T, f metrics.Family, le string) float64 {
	t.Helper()
	for _, b := range f.Buckets {
		if b.LE == le {
			return b.Count
		}
	}
	t.Fatalf("no bucket %q in %q", le, f.Name)
	return 0
}
