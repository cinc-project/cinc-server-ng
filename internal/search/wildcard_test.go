package search

import (
	"fmt"
	"testing"
)

// matchVal runs once per value of every document a scan touches, so the
// wildcard pattern must be compiled when the term is parsed, not on each call.
func TestWildcardPatternCompiledOnce(t *testing.T) {
	q, err := Parse("name:web*")
	if err != nil {
		t.Fatal(err)
	}
	term, ok := q.(termQ)
	if !ok {
		t.Fatalf("parsed %T, want termQ", q)
	}
	if term.re == nil {
		t.Error("a wildcarded term carries no compiled matcher; matchVal recompiles per value")
	}
	// A term with nothing to expand needs no regexp at all — an exact compare is
	// both cheaper and what Plan relies on to use the postings directly.
	for _, s := range []string{"name:web01", `name:"web*"`} {
		q, err := Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		if term, ok := q.(termQ); ok && term.re != nil {
			t.Errorf("%s compiled a regexp for a non-wildcard term", s)
		}
	}
}

// Compiling earlier must not change what matches.
func TestWildcardMatchingUnchanged(t *testing.T) {
	cases := []struct {
		query, value string
		want         bool
	}{
		{"name:web*", "web01", true},
		{"name:web*", "db01", false},
		{"name:web?1", "web01", true},
		{"name:web?1", "web001", false},
		{"name:*01", "web01", true},
		{"name:w*b*1", "web01", true},
		{"name:web01", "web01", true},
		{"name:web01", "web02", false},
		{`name:"web*"`, "web*", true},
		{`name:"web*"`, "web01", false},
		{"name:a.c", "a.c", true},
		{"name:a.c", "abc", false},
	}
	for _, c := range cases {
		q, err := Parse(c.query)
		if err != nil {
			t.Fatalf("%s: %v", c.query, err)
		}
		got := q.Matches(map[string][]string{"name": {c.value}})
		if got != c.want {
			t.Errorf("%s against %q = %v, want %v", c.query, c.value, got, c.want)
		}
	}
}

// A wildcard scan over many values is what the compile cost was proportional to.
func BenchmarkWildcardScan(b *testing.B) {
	q, err := Parse("name:web*")
	if err != nil {
		b.Fatal(err)
	}
	docs := make([]map[string][]string, 2000)
	for i := range docs {
		docs[i] = map[string][]string{"name": {fmt.Sprintf("web%04d", i)}}
	}
	b.ResetTimer()
	for range b.N {
		for _, d := range docs {
			q.Matches(d)
		}
	}
}
