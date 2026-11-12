// Package metrics is a small, dependency-free instrument registry: counters,
// sampled gauges, and histograms, rendered either as the JSON metric families
// Chef's /_stats endpoint returns or as Prometheus text exposition.
//
// It is deliberately tiny rather than a Prometheus client dependency. cinc-server-ng
// ships as a single static binary with one direct dependency, and what a fleet
// server actually needs to expose — request rate and latency, how much store
// work a request costs, whether searches are being served from the index — is a
// few hundred lines.
//
// Label sets are fixed when an instrument is registered. That keeps the
// recording path a single atomic add with no map lookup or allocation, and it
// means an unbounded label (an org name, a node name) cannot quietly turn the
// registry into a memory leak.
package metrics

import (
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/cinc-project/cinc-server-ng/internal/chefjson"
)

// Label is one dimension of a series.
type Label struct {
	Name  string
	Value string
}

// Series is a single measurement within a family.
type Series struct {
	Labels []Label
	Value  float64
}

// Bucket is one cumulative histogram bucket.
type Bucket struct {
	LE    string
	Count float64
}

// Family is one named instrument and everything measured under it. A
// histogram's distribution is in Buckets, Sum and Count; its Metrics is empty.
// WriteJSON and WriteText are its wire forms.
type Family struct {
	Name    string
	Type    string
	Help    string
	Metrics []Series
	Buckets []Bucket
	Sum     float64
	Count   float64
}

// Registry holds the process's instruments.
type Registry struct {
	mu      sync.Mutex
	ordered []gatherer
}

// gatherer is anything that can render itself as a family.
type gatherer interface{ gather() Family }

func NewRegistry() *Registry { return &Registry{} }

func (r *Registry) add(g gatherer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ordered = append(r.ordered, g)
}

// Gather snapshots every instrument. Gauges are sampled here, so a scrape sees
// current values rather than whatever was last recorded.
func (r *Registry) Gather() []Family {
	r.mu.Lock()
	instruments := append([]gatherer(nil), r.ordered...)
	r.mu.Unlock()

	out := make([]Family, 0, len(instruments))
	for _, g := range instruments {
		out = append(out, g.gather())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// --- counters -------------------------------------------------------------

// Counter is a set of monotonically increasing series sharing one label name.
// Passing no label name and no values makes it a single unlabelled series.
type Counter struct {
	name, help string
	label      string
	order      []string
	values     map[string]*atomic.Int64
}

// Counter registers a counter. label names the single label dimension and
// labelValues enumerates every series it can have; both may be omitted for an
// unlabelled counter.
func (r *Registry) Counter(name, help, label string, labelValues ...string) *Counter {
	c := &Counter{name: name, help: help, label: label, values: map[string]*atomic.Int64{}}
	if len(labelValues) == 0 {
		labelValues = []string{""}
	}
	for _, v := range labelValues {
		c.order = append(c.order, v)
		c.values[v] = new(atomic.Int64)
	}
	r.add(c)
	return c
}

// With selects a series. A value that was not registered is discarded rather
// than creating a series, so a caller cannot accidentally make label
// cardinality unbounded.
func (c *Counter) With(value string) *Counter {
	if _, ok := c.values[value]; !ok {
		return &Counter{} // no-op handle
	}
	return &Counter{name: c.name, label: c.label, order: []string{value}, values: c.values}
}

func (c *Counter) Add(n int64) {
	if len(c.order) == 0 {
		return
	}
	if v, ok := c.values[c.order[0]]; ok {
		v.Add(n)
	}
}

func (c *Counter) Inc() { c.Add(1) }

func (c *Counter) gather() Family {
	f := Family{Name: c.name, Type: "COUNTER", Help: c.help}
	for _, v := range c.order {
		s := Series{Value: float64(c.values[v].Load())}
		if c.label != "" {
			s.Labels = []Label{{Name: c.label, Value: v}}
		}
		f.Metrics = append(f.Metrics, s)
	}
	return f
}

// --- gauges ---------------------------------------------------------------

type gauge struct {
	name, help string
	read       func() float64
}

// Gauge registers a value sampled at scrape time. Reading through to the source
// avoids having to keep a mirror of it up to date.
func (r *Registry) Gauge(name, help string, read func() float64) {
	r.add(&gauge{name: name, help: help, read: read})
}

func (g *gauge) gather() Family {
	return Family{
		Name: g.name, Type: "GAUGE", Help: g.help,
		Metrics: []Series{{Value: g.read()}},
	}
}

// counterFunc is a monotonic count owned elsewhere, read at scrape time.
type counterFunc struct {
	name, help string
	read       func() float64
}

// CounterFunc registers a counter whose value lives outside the registry — a
// count the store already keeps, say — so it need not be mirrored here.
func (r *Registry) CounterFunc(name, help string, read func() float64) {
	r.add(&counterFunc{name: name, help: help, read: read})
}

func (c *counterFunc) gather() Family {
	return Family{
		Name: c.name, Type: "COUNTER", Help: c.help,
		Metrics: []Series{{Value: c.read()}},
	}
}

// --- histograms -----------------------------------------------------------

// Histogram records a distribution across fixed buckets. Only a distribution
// shows tail latency; a mean hides exactly the stalls worth knowing about.
type Histogram struct {
	name, help string
	bounds     []float64
	counts     []atomic.Int64 // one per bound, plus a final +Inf
	sum        atomic.Uint64  // float64 bits
	total      atomic.Int64
}

func (r *Registry) Histogram(name, help string, bounds []float64) *Histogram {
	h := &Histogram{
		name: name, help: help,
		bounds: append([]float64(nil), bounds...),
		counts: make([]atomic.Int64, len(bounds)+1),
	}
	r.add(h)
	return h
}

func (h *Histogram) Observe(v float64) {
	i := sort.SearchFloat64s(h.bounds, v)
	// SearchFloat64s finds the first bound >= v; a bucket is "less than or
	// equal", so that is the bucket v belongs in.
	h.counts[i].Add(1)
	h.total.Add(1)
	for {
		old := h.sum.Load()
		next := math.Float64bits(math.Float64frombits(old) + v)
		if h.sum.CompareAndSwap(old, next) {
			return
		}
	}
}

func (h *Histogram) gather() Family {
	f := Family{
		Name: h.name, Type: "HISTOGRAM", Help: h.help,
		Sum:   math.Float64frombits(h.sum.Load()),
		Count: float64(h.total.Load()),
	}
	var cumulative float64
	for i, b := range h.bounds {
		cumulative += float64(h.counts[i].Load())
		f.Buckets = append(f.Buckets, Bucket{LE: formatFloat(b), Count: cumulative})
	}
	cumulative += float64(h.counts[len(h.bounds)].Load())
	f.Buckets = append(f.Buckets, Bucket{LE: "+Inf", Count: cumulative})
	return f
}

func formatFloat(f float64) string {
	return strconv.FormatFloat(f, 'g', -1, 64)
}

// --- JSON -----------------------------------------------------------------

// WriteJSON renders families as erchef's /_stats JSON
// (chef_wm_prometheus_json_format): an array of {"name","type","help",
// "metrics"}, where a metric is {"labels"?,"value"} or, for a histogram,
// {"labels"?,"sample_sum","sample_count","bucket":[{"cumulative_count",
// "upper_bound"}]}. Every number is a string (erlangNumber), and "labels" is
// an object of name to value, left out when a metric has none.
func WriteJSON(w io.Writer, families []Family) error {
	out := make([]any, 0, len(families))
	for _, f := range families {
		metrics := []any{}
		if f.Type == "HISTOGRAM" {
			buckets := make([]any, 0, len(f.Buckets))
			for _, b := range f.Buckets {
				bound, err := strconv.ParseFloat(b.LE, 64) // "+Inf" included
				if err != nil {
					return fmt.Errorf("histogram %s: bucket bound %q: %w", f.Name, b.LE, err)
				}
				buckets = append(buckets, object(
					"cumulative_count", erlangNumber(b.Count),
					"upper_bound", erlangNumber(bound)))
			}
			metrics = append(metrics, object(
				"sample_sum", erlangNumber(f.Sum),
				"sample_count", erlangNumber(f.Count),
				"bucket", buckets))
		} else {
			for _, s := range f.Metrics {
				m := object()
				if len(s.Labels) > 0 {
					labels := object()
					for _, l := range s.Labels {
						labels.Set(l.Name, l.Value)
					}
					m.Set("labels", labels)
				}
				m.Set("value", erlangNumber(s.Value))
				metrics = append(metrics, m)
			}
		}
		out = append(out, object(
			"name", f.Name, "type", f.Type, "help", f.Help, "metrics", metrics))
	}
	_, err := w.Write(chefjson.Marshal(out))
	return err
}

// object builds an ordered JSON object from name, value pairs.
func object(pairs ...any) *chefjson.Object {
	o := &chefjson.Object{}
	for i := 0; i+1 < len(pairs); i += 2 {
		o.Members = append(o.Members, chefjson.Member{Name: pairs[i].(string), Value: pairs[i+1]})
	}
	return o
}

// erlangNumber writes v as erchef's as_binary/1 does. Prometheus.erl keeps a
// count as an Erlang integer, written as its digits, and anything measured as
// a float, written with ~p; the registry holds both as float64, so a whole
// value is taken to be an integer. Infinity is "+Inf" or "-Inf".
func erlangNumber(v float64) string {
	switch {
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	case math.IsNaN(v):
		return "NaN"
	case v == math.Trunc(v):
		return strconv.FormatFloat(v, 'f', 0, 64)
	}
	sign := ""
	if v < 0 {
		sign, v = "-", -v
	}
	// Shortest round-trip digits and the decimal point's place, as Erlang's
	// io_lib_format:fwrite_g/1 computes them: v = 0.<digits> * 10^place.
	e := strconv.FormatFloat(v, 'e', -1, 64) // d[.ddd]e±XX
	mant, exp, _ := strings.Cut(e, "e")
	digits := strings.Replace(mant, ".", "", 1)
	x, _ := strconv.Atoi(exp)
	return sign + insertDecimal(x+1, digits)
}

// insertDecimal is io_lib_format:insert_decimal/2: it writes digits with the
// point at place, choosing exponent notation only when that is shorter.
func insertDecimal(place int, s string) string {
	l := len(s)
	if place == 0 {
		return "0." + s
	}
	if place > 0 && place < l {
		return s[:place] + "." + s[place:]
	}
	expL := strconv.Itoa(place - 1)
	expDot := 1
	if l == 1 {
		expDot = 2
	}
	expCost := len(expL) + 1 + expDot
	if place < 0 {
		if 2-place <= expCost {
			return "0." + strings.Repeat("0", -place) + s
		}
	} else if place-l+2 <= expCost {
		return s + strings.Repeat("0", place-l) + ".0"
	}
	if l == 1 {
		return s + ".0e" + expL
	}
	return s[:1] + "." + s[1:] + "e" + expL
}

// --- text exposition ------------------------------------------------------

// WriteText renders families in Prometheus text exposition format, which is
// what a scraper speaks.
func WriteText(w io.Writer, families []Family) error {
	for _, f := range families {
		if _, err := fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n",
			f.Name, f.Help, f.Name, typeText(f.Type)); err != nil {
			return err
		}
		switch f.Type {
		case "HISTOGRAM":
			for _, b := range f.Buckets {
				if _, err := fmt.Fprintf(w, "%s_bucket{le=%q} %s\n",
					f.Name, b.LE, formatFloat(b.Count)); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprintf(w, "%s_sum %s\n%s_count %s\n",
				f.Name, formatFloat(f.Sum), f.Name, formatFloat(f.Count)); err != nil {
				return err
			}
		default:
			for _, s := range f.Metrics {
				if _, err := fmt.Fprintf(w, "%s%s %s\n",
					f.Name, labelText(s.Labels), formatFloat(s.Value)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func typeText(t string) string {
	switch t {
	case "COUNTER":
		return "counter"
	case "GAUGE":
		return "gauge"
	case "HISTOGRAM":
		return "histogram"
	}
	return "untyped"
}

func labelText(labels []Label) string {
	if len(labels) == 0 {
		return ""
	}
	out := "{"
	for i, l := range labels {
		if i > 0 {
			out += ","
		}
		out += l.Name + "=" + strconv.Quote(l.Value)
	}
	return out + "}"
}
