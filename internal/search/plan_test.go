package search

import (
	"maps"
	"slices"
	"testing"
)

// Plan is an optimization of Matches. The only thing that really matters is
// that the two never disagree, so the test builds a corpus, evaluates every
// query both ways, and compares.

// memPostings is a straightforward inverted index over a fixed corpus, standing
// in for the real one so this test exercises Plan rather than storage.
type memPostings struct {
	docs map[string]map[string][]string // id -> flattened fields
}

func (m memPostings) All() DocIDs {
	out := make(DocIDs, len(m.docs))
	for id := range m.docs {
		out[id] = struct{}{}
	}
	return out
}

func (m memPostings) Exact(field, value string) DocIDs {
	out := DocIDs{}
	for id, f := range m.docs {
		if slices.Contains(f[field], value) {
			out[id] = struct{}{}
		}
	}
	return out
}

func (m memPostings) Exists(field string) DocIDs {
	out := DocIDs{}
	for id, f := range m.docs {
		if len(f[field]) > 0 {
			out[id] = struct{}{}
		}
	}
	return out
}

func (m memPostings) Match(field string, pred func(string) bool) DocIDs {
	out := DocIDs{}
	for id, f := range m.docs {
		for _, v := range f[field] {
			if pred(v) {
				out[id] = struct{}{}
				break
			}
		}
	}
	return out
}

func (m memPostings) MatchAny(pred func(string) bool) DocIDs {
	out := DocIDs{}
	for id, f := range m.docs {
		for _, vals := range f {
			for _, v := range vals {
				if pred(v) {
					out[id] = struct{}{}
				}
			}
		}
	}
	return out
}

func planCorpus() memPostings {
	return memPostings{docs: map[string]map[string][]string{
		"web01": {
			"name":             {"web01"},
			"chef_environment": {"production"},
			"roles":            {"web", "base"},
			"os":               {"linux"},
			"memory_total":     {"16384"},
			"tags":             {"public"},
		},
		"web02": {
			"name":             {"web02"},
			"chef_environment": {"production"},
			"roles":            {"web"},
			"os":               {"linux"},
			"memory_total":     {"8192"},
		},
		"db01": {
			"name":             {"db01"},
			"chef_environment": {"staging"},
			"roles":            {"database", "base"},
			"os":               {"windows"},
			"memory_total":     {"65536"},
		},
		"lonely": {
			"name": {"lonely"},
		},
	}}
}

// reference evaluates a query the scanning way, which is the definition.
func reference(q Query, c memPostings) DocIDs {
	out := DocIDs{}
	for id, fields := range c.docs {
		if q.Matches(fields) {
			out[id] = struct{}{}
		}
	}
	return out
}

func TestPlanAgreesWithMatches(t *testing.T) {
	corpus := planCorpus()
	queries := []string{
		"*:*",
		"chef_environment:production",
		"chef_environment:staging",
		"chef_environment:nonexistent",
		"name:web01",
		"roles:base",
		"os:*",
		"missing_field:*",
		"name:web*",
		"name:web0?",
		"os:lin*x",
		"memory_total:[8192 TO 16384]",
		"memory_total:{8192 TO 65536}",
		"memory_total:[16384 TO *]",
		"memory_total:[* TO 8192]",
		"chef_environment:production AND os:linux",
		"chef_environment:production AND memory_total:16384",
		"chef_environment:production OR chef_environment:staging",
		"roles:web OR roles:database",
		"NOT chef_environment:production",
		"-chef_environment:production",
		"NOT os:*",
		"chef_environment:production AND NOT name:web01",
		"(chef_environment:production OR chef_environment:staging) AND os:linux",
		"chef_environment:production os:linux",
		"linux",
		"production",
		"nosuchterm",
		`roles:"base"`,
		"NOT NOT os:linux",
		"chef_environment:production AND chef_environment:staging",
	}
	for _, qs := range queries {
		q, err := Parse(qs)
		if err != nil {
			t.Fatalf("parse %q: %v", qs, err)
		}
		want := reference(q, corpus)
		got, ok := Plan(q, corpus)
		if !ok {
			t.Errorf("%q: not plannable; every supported operator should be", qs)
			continue
		}
		if !maps.Equal(got, want) {
			t.Errorf("%q:\n planned %v\n scanned %v", qs, keys(got), keys(want))
		}
	}
}

func keys(d DocIDs) []string {
	out := slices.Collect(maps.Keys(d))
	slices.Sort(out)
	return out
}

// An AND whose left side is empty must not bother resolving the right side, and
// must still be correct.
func TestPlanShortCircuitsEmptyIntersection(t *testing.T) {
	corpus := planCorpus()
	q, err := Parse("chef_environment:nonexistent AND os:linux")
	if err != nil {
		t.Fatal(err)
	}
	got, ok := Plan(q, corpus)
	if !ok {
		t.Fatal("not plannable")
	}
	if len(got) != 0 {
		t.Fatalf("got %v, want empty", keys(got))
	}
}

// Plan must return sets the caller can mutate without corrupting the index.
func TestPlanResultIsCallerOwned(t *testing.T) {
	corpus := planCorpus()
	q, _ := Parse("*:*")
	first, _ := Plan(q, corpus)
	n := len(first)
	clear(first)
	second, _ := Plan(q, corpus)
	if len(second) != n {
		t.Fatalf("mutating a planned set changed later results: %d then %d", n, len(second))
	}
}
