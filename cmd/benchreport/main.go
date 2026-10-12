// Command benchreport turns repeated cmd/loadtest runs into one markdown
// report. Each server is run several times; every cell of the report is the
// median of that cell across the server's runs, so one noisy run on a shared
// machine does not decide a result.
//
// It also reads the memory samples scripts/memsample.sh writes, one per run:
// idle is the server's footprint once it is ready, peak is the most it used
// while seeded and under load.
//
// This is a development tool; it is not built into the cinc-server-ng binary.
//
// Example:
//
//	go run ./cmd/benchreport -runs 'results/run-*.json' -mem 'results/mem-*.json'
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

// loadRun and opResult mirror the JSON cmd/loadtest writes with -json.
type loadRun struct {
	Label string     `json:"label"`
	Conc  int        `json:"conc"`
	Ops   []opResult `json:"ops"`
}

type opResult struct {
	Name   string  `json:"name"`
	ColdMS float64 `json:"cold_ms"`
	P50MS  float64 `json:"p50_ms"`
	P95MS  float64 `json:"p95_ms"`
	QPS1   float64 `json:"qps1"`
	QPSC   float64 `json:"qpsc"`
	Errors int     `json:"errors"`
}

// memSample is one scripts/memsample.sh reading, in KiB of PSS.
type memSample struct {
	Label  string `json:"label"`
	IdleKB int64  `json:"idle_kb"`
	PeakKB int64  `json:"peak_kb"`
}

// server is one server's runs reduced to per-cell medians.
type server struct {
	Label string
	Reps  int
	Conc  int
	Ops   []opResult
}

func main() {
	runsGlob := flag.String("runs", "", "glob of cmd/loadtest -json result files")
	memGlob := flag.String("mem", "", "glob of scripts/memsample.sh files (optional)")
	out := flag.String("o", "", "write the report here instead of stdout")
	flag.Parse()
	if *runsGlob == "" {
		fmt.Fprintln(os.Stderr, "need -runs")
		os.Exit(2)
	}

	runs, err := loadRuns(glob(*runsGlob))
	must(err)
	if len(runs) == 0 {
		must(fmt.Errorf("no result files match %q", *runsGlob))
	}
	var mems []memSample
	if *memGlob != "" {
		mems, err = loadMem(glob(*memGlob))
		must(err)
	}

	var buf bytes.Buffer
	render(&buf, aggregate(runs), aggregateMem(mems))
	if *out != "" {
		must(os.WriteFile(*out, buf.Bytes(), 0o644))
		return
	}
	_, err = os.Stdout.Write(buf.Bytes())
	must(err)
}

func glob(pattern string) []string {
	paths, err := filepath.Glob(pattern)
	must(err)
	sort.Strings(paths)
	return paths
}

func loadRuns(paths []string) ([]loadRun, error) {
	runs := make([]loadRun, 0, len(paths))
	for _, p := range paths {
		var r loadRun
		if err := readJSON(p, &r); err != nil {
			return nil, err
		}
		runs = append(runs, r)
	}
	return runs, nil
}

func loadMem(paths []string) ([]memSample, error) {
	mems := make([]memSample, 0, len(paths))
	for _, p := range paths {
		var m memSample
		if err := readJSON(p, &m); err != nil {
			return nil, err
		}
		mems = append(mems, m)
	}
	return mems, nil
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// aggregate groups runs by label, in the order each label first appears, and
// reduces every metric of every op to its median across that label's runs.
// Errors are summed: one failed request in any run is worth reporting.
func aggregate(runs []loadRun) []server {
	var order []string
	byLabel := map[string][]loadRun{}
	for _, r := range runs {
		if _, seen := byLabel[r.Label]; !seen {
			order = append(order, r.Label)
		}
		byLabel[r.Label] = append(byLabel[r.Label], r)
	}

	servers := make([]server, 0, len(order))
	for _, label := range order {
		rs := byLabel[label]
		s := server{Label: label, Reps: len(rs), Conc: rs[0].Conc}
		for i, o := range rs[0].Ops {
			var cold, p50, p95, q1, qc []float64
			errs := 0
			for _, r := range rs {
				if i >= len(r.Ops) || r.Ops[i].Name != o.Name {
					continue
				}
				x := r.Ops[i]
				cold, p50, p95 = append(cold, x.ColdMS), append(p50, x.P50MS), append(p95, x.P95MS)
				q1, qc = append(q1, x.QPS1), append(qc, x.QPSC)
				errs += x.Errors
			}
			s.Ops = append(s.Ops, opResult{
				Name: o.Name, ColdMS: median(cold), P50MS: median(p50), P95MS: median(p95),
				QPS1: median(q1), QPSC: median(qc), Errors: errs,
			})
		}
		servers = append(servers, s)
	}
	return servers
}

func aggregateMem(samples []memSample) map[string]memSample {
	if len(samples) == 0 {
		return nil
	}
	idle, peak := map[string][]float64{}, map[string][]float64{}
	for _, m := range samples {
		idle[m.Label] = append(idle[m.Label], float64(m.IdleKB))
		peak[m.Label] = append(peak[m.Label], float64(m.PeakKB))
	}
	out := make(map[string]memSample, len(idle))
	for label := range idle {
		out[label] = memSample{Label: label, IdleKB: int64(median(idle[label])), PeakKB: int64(median(peak[label]))}
	}
	return out
}

// median of the non-negative values; cmd/loadtest reports a phase with no
// successful sample as -1, which is an absence, not a measurement. Returns -1
// when nothing is left.
func median(xs []float64) float64 {
	vals := make([]float64, 0, len(xs))
	for _, x := range xs {
		if x >= 0 {
			vals = append(vals, x)
		}
	}
	if len(vals) == 0 {
		return -1
	}
	sort.Float64s(vals)
	mid := len(vals) / 2
	if len(vals)%2 == 1 {
		return vals[mid]
	}
	return (vals[mid-1] + vals[mid]) / 2
}

func render(w io.Writer, servers []server, mem map[string]memSample) {
	if len(servers) == 0 {
		return
	}
	conc := servers[0].Conc
	table(w, fmt.Sprintf("QPS@%d", conc), servers, func(o opResult) string { return count(o.QPSC) })
	table(w, "p50 ms", servers, func(o opResult) string { return ms(o.P50MS) })
	table(w, "QPS@1", servers, func(o opResult) string { return count(o.QPS1) })
	table(w, "p95 ms", servers, func(o opResult) string { return ms(o.P95MS) })
	table(w, "cold ms", servers, func(o opResult) string { return ms(o.ColdMS) })

	if len(mem) > 0 {
		fmt.Fprintf(w, "### Memory (MiB, PSS)\n\n| server | idle | peak under load |\n|---|--:|--:|\n")
		for _, s := range servers {
			m, ok := mem[s.Label]
			if !ok {
				continue
			}
			fmt.Fprintf(w, "| %s | %d | %d |\n", s.Label, m.IdleKB/1024, m.PeakKB/1024)
		}
		fmt.Fprintln(w)
	}

	var failures []string
	for _, s := range servers {
		n := 0
		for _, o := range s.Ops {
			n += o.Errors
		}
		if n > 0 {
			failures = append(failures, fmt.Sprintf("- %s: %d failed requests across %d runs", s.Label, n, s.Reps))
		}
	}
	if len(failures) > 0 {
		fmt.Fprintf(w, "### Failed requests\n\nThese runs include requests that failed or were rejected, so their numbers may time rejections rather than work:\n\n")
		for _, f := range failures {
			fmt.Fprintln(w, f)
		}
		fmt.Fprintln(w)
	}
}

func table(w io.Writer, title string, servers []server, cell func(opResult) string) {
	fmt.Fprintf(w, "### %s\n\n| server | reps |", title)
	for _, o := range servers[0].Ops {
		fmt.Fprintf(w, " %s |", o.Name)
	}
	fmt.Fprintf(w, "\n|---|--:|")
	for range servers[0].Ops {
		fmt.Fprintf(w, "--:|")
	}
	fmt.Fprintln(w)
	for _, s := range servers {
		fmt.Fprintf(w, "| %s | %d |", s.Label, s.Reps)
		for _, o := range s.Ops {
			fmt.Fprintf(w, " %s |", cell(o))
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w)
}

func ms(v float64) string {
	if v < 0 {
		return "err"
	}
	return fmt.Sprintf("%.3f", v)
}

func count(v float64) string {
	if v < 0 {
		return "err"
	}
	return fmt.Sprintf("%.0f", v)
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "benchreport:", err)
		os.Exit(1)
	}
}
