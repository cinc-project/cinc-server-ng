package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMedianIgnoresMissing(t *testing.T) {
	cases := []struct {
		in   []float64
		want float64
	}{
		{[]float64{3, 1, 2}, 2},
		{[]float64{4, 1, 3, 2}, 2.5},
		{[]float64{5, -1, 1}, 3}, // -1 is "no successful sample", not a value
		{[]float64{-1, -1}, -1},
		{nil, -1},
	}
	for _, c := range cases {
		if got := median(c.in); got != c.want {
			t.Errorf("median(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

func run(label string, p50 float64, errs int) loadRun {
	return loadRun{Label: label, Conc: 10, Ops: []opResult{
		{Name: "GET node", ColdMS: 1, P50MS: p50, P95MS: p50 * 2, QPS1: 1000 / p50, QPSC: 10000 / p50, Errors: errs},
	}}
}

func TestAggregateTakesPerCellMediansInFirstSeenOrder(t *testing.T) {
	runs := []loadRun{
		run("chef", 40, 0), run("cinc", 0.4, 0),
		run("chef", 50, 0), run("cinc", 0.2, 0),
		run("chef", 45, 1), run("cinc", 0.3, 0),
	}
	got := aggregate(runs)
	if len(got) != 2 || got[0].Label != "chef" || got[1].Label != "cinc" {
		t.Fatalf("servers = %+v, want chef then cinc", got)
	}
	chef := got[0]
	if chef.Reps != 3 {
		t.Fatalf("chef reps = %d, want 3", chef.Reps)
	}
	if op := chef.Ops[0]; op.P50MS != 45 || op.Errors != 1 {
		t.Fatalf("chef GET node = %+v, want p50 45 and the one error summed", op)
	}
	if p50 := got[1].Ops[0].P50MS; p50 != 0.3 {
		t.Fatalf("cinc GET node p50 = %v, want 0.3", p50)
	}
}

func TestAggregateMemoryTakesMedians(t *testing.T) {
	got := aggregateMem([]memSample{
		{Label: "chef", IdleKB: 3_000_000, PeakKB: 3_500_000},
		{Label: "chef", IdleKB: 3_100_000, PeakKB: 3_400_000},
		{Label: "chef", IdleKB: 2_900_000, PeakKB: 3_600_000},
		{Label: "cinc", IdleKB: 20_000, PeakKB: 60_000},
	})
	if got["chef"].IdleKB != 3_000_000 || got["chef"].PeakKB != 3_500_000 {
		t.Fatalf("chef memory = %+v, want medians 3,000,000 / 3,500,000", got["chef"])
	}
	if got["cinc"].PeakKB != 60_000 {
		t.Fatalf("cinc memory = %+v", got["cinc"])
	}
}

func TestRenderIncludesEveryTableAndFlagsErrors(t *testing.T) {
	servers := aggregate([]loadRun{run("chef", 46, 0), run("cinc", 0.43, 2)})
	mem := aggregateMem([]memSample{
		{Label: "chef", IdleKB: 3 * 1024 * 1024, PeakKB: 4 * 1024 * 1024},
		{Label: "cinc", IdleKB: 20 * 1024, PeakKB: 64 * 1024},
	})
	var buf bytes.Buffer
	render(&buf, servers, mem)
	out := buf.String()

	for _, want := range []string{
		"### QPS@10",
		"### p50 ms",
		"### QPS@1",
		"### cold ms",
		"| server | reps | GET node |",
		"| chef | 1 | 217 |",
		"| cinc | 1 | 0.430 |",
		"### Memory",
		"| chef | 3072 | 4096 |",
		"| cinc | 20 | 64 |",
		"cinc: 2 failed requests",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("render output missing %q\n%s", want, out)
		}
	}
}

func TestRenderOmitsMemoryTableWithoutSamples(t *testing.T) {
	var buf bytes.Buffer
	render(&buf, aggregate([]loadRun{run("cinc", 0.4, 0)}), nil)
	if strings.Contains(buf.String(), "### Memory") {
		t.Fatalf("memory table rendered with no samples:\n%s", buf.String())
	}
	if strings.Contains(buf.String(), "failed requests") {
		t.Fatalf("error note rendered for a clean run:\n%s", buf.String())
	}
}

func TestLoadReadsRunAndMemoryFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	r := write("run-1.json", `{"label":"cinc","conc":10,"ops":[{"name":"GET node","p50_ms":0.4}]}`)
	m := write("mem-1.json", `{"label":"cinc","idle_kb":20480,"peak_kb":65536}`)

	runs, err := loadRuns([]string{r})
	if err != nil || len(runs) != 1 || runs[0].Ops[0].P50MS != 0.4 {
		t.Fatalf("loadRuns = %+v, %v", runs, err)
	}
	mems, err := loadMem([]string{m})
	if err != nil || len(mems) != 1 || mems[0].PeakKB != 65536 {
		t.Fatalf("loadMem = %+v, %v", mems, err)
	}
	if _, err := loadRuns([]string{write("bad.json", "{")}); err == nil {
		t.Fatal("loadRuns accepted malformed JSON")
	}
}
