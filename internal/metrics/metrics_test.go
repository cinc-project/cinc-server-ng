package metrics_test

import (
	"encoding/json"
	"math"
	"strings"
	"testing"

	"github.com/cinc-project/cinc-server-ng/internal/metrics"
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

// The JSON form is erchef's (chef_wm_prometheus_json_format): every number a
// string, labels an object left out when empty, and a histogram's sum, count
// and buckets on its metric.
func TestWriteJSONMatchesErchef(t *testing.T) {
	r := metrics.NewRegistry()
	r.Counter("things_total", "how many things", "kind", "a", "b").With("a").Add(2)
	r.Gauge("ratio", "a fraction", func() float64 { return 0.25 })
	r.Gauge("unlabelled", "a whole number", func() float64 { return 7 })
	h := r.Histogram("latency_seconds", "how long", []float64{0.00001, 0.1, 1})
	h.Observe(0.25)
	h.Observe(0.5)

	var sb strings.Builder
	if err := metrics.WriteJSON(&sb, r.Gather()); err != nil {
		t.Fatal(err)
	}
	want := `[` +
		`{"name":"latency_seconds","type":"HISTOGRAM","help":"how long","metrics":[` +
		`{"sample_sum":"0.75","sample_count":"2","bucket":[` +
		`{"cumulative_count":"0","upper_bound":"1.0e-5"},` +
		`{"cumulative_count":"0","upper_bound":"0.1"},` +
		`{"cumulative_count":"2","upper_bound":"1"},` +
		`{"cumulative_count":"2","upper_bound":"+Inf"}]}]},` +
		`{"name":"ratio","type":"GAUGE","help":"a fraction","metrics":[{"value":"0.25"}]},` +
		`{"name":"things_total","type":"COUNTER","help":"how many things","metrics":[` +
		`{"labels":{"kind":"a"},"value":"2"},{"labels":{"kind":"b"},"value":"0"}]},` +
		`{"name":"unlabelled","type":"GAUGE","help":"a whole number","metrics":[{"value":"7"}]}` +
		`]`
	if got := sb.String(); got != want {
		t.Fatalf("JSON =\n%s\nwant\n%s", got, want)
	}
	var v any
	if err := json.Unmarshal([]byte(sb.String()), &v); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
}

// Numbers are written as erchef's as_binary writes them: an integer as its
// digits, a float as Erlang's ~p (shortest round trip, choosing between fixed
// and exponent notation by length), infinity as +Inf/-Inf.
func TestErlangNumberFormat(t *testing.T) {
	for _, c := range []struct {
		in   float64
		want string
	}{
		{0, "0"},
		{42, "42"},
		{-3, "-3"},
		{1e21, "1000000000000000000000"},
		{0.25, "0.25"},
		{123.456, "123.456"},
		{0.001, "0.001"},
		{0.0001, "0.0001"},
		{0.00001, "1.0e-5"},
		{1.5e-7, "1.5e-7"},
		{-0.5, "-0.5"},
		{math.Inf(1), "+Inf"},
		{math.Inf(-1), "-Inf"},
	} {
		if got := metrics.ErlangNumber(c.in); got != c.want {
			t.Errorf("ErlangNumber(%v) = %q, want %q", c.in, got, c.want)
		}
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
