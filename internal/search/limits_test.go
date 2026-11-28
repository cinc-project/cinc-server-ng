package search

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// Deep nesting must be refused with an error rather than recursed into: each
// paren costs four parser frames, so enough of them overflows the stack and
// kills the process. 100k levels parses (slowly) on unbounded code, which is
// what makes this a failing test there rather than a crashed binary.
func TestParseRejectsDeepNesting(t *testing.T) {
	cases := map[string]string{
		"parens":   strings.Repeat("(", 100000) + "name:a" + strings.Repeat(")", 100000),
		"NOT":      strings.Repeat("NOT ", 30000) + "name:a",
		"mixed":    strings.Repeat("(NOT ", 20000) + "name:a" + strings.Repeat(")", 20000),
		"unclosed": strings.Repeat("(", 100000),
	}
	for name, q := range cases {
		if _, err := Parse(q); err == nil {
			t.Errorf("%s: Parse accepted a query nested %d bytes deep", name, len(q))
		}
	}
}

// Nesting a realistic query would ever use stays well inside the limit.
func TestParseAcceptsReasonableNesting(t *testing.T) {
	q := strings.Repeat("(", maxQueryDepth-1) + "name:a" + strings.Repeat(")", maxQueryDepth-1)
	if _, err := Parse(q); err != nil {
		t.Fatalf("nesting %d levels: %v", maxQueryDepth-1, err)
	}
	q = strings.Repeat("NOT ", maxQueryDepth-1) + "name:a"
	if _, err := Parse(q); err != nil {
		t.Fatalf("%d NOTs: %v", maxQueryDepth-1, err)
	}
}

// The length cap is checked before lexing, which otherwise allocates a token
// per character of the input.
func TestParseRejectsOverlongQuery(t *testing.T) {
	q := "name:" + strings.Repeat("a", maxQueryLength)
	if _, err := Parse(q); err == nil {
		t.Fatalf("Parse accepted a %d-byte query", len(q))
	}
}

// Every leaf term (and negation) is a clause the planner resolves separately,
// so their number is bounded as Solr's maxBooleanClauses bounds it.
func TestParseRejectsTooManyClauses(t *testing.T) {
	terms := make([]string, maxQueryClauses+1)
	for i := range terms {
		terms[i] = "a"
	}
	if _, err := Parse(strings.Join(terms, " ")); err == nil {
		t.Fatalf("Parse accepted %d clauses", len(terms))
	}
	if _, err := Parse(strings.Join(terms[:maxQueryClauses], " ")); err != nil {
		t.Fatalf("%d clauses: %v", maxQueryClauses, err)
	}
}

// What knife and chef-client recipes actually send must keep parsing: a
// host-list OR across a large fleet, wildcards, match-all, grouped clauses.
func TestParseAcceptsRealisticQueries(t *testing.T) {
	names := make([]string, 1000)
	for i := range names {
		names[i] = fmt.Sprintf("name:node-%04d.prod.example.com", i)
	}
	queries := []string{
		strings.Join(names, " OR "),
		"(" + strings.Join(names[:500], " OR ") + ") AND chef_environment:production",
		"name:web*",
		"*:*",
		"role:web* AND NOT (chef_environment:dev OR chef_environment:test) AND platform:ubuntu",
		`run_list:recipe\[base\] AND tags:"db primary"`,
		"((role:a AND (b:1 OR (c:2 AND NOT d:3))) OR e:*)",
	}
	for _, q := range queries {
		if _, err := Parse(q); err != nil {
			t.Errorf("Parse(%.60q...) = %v", q, err)
		}
	}
}

// Many '*' in a row cost what one does: the matcher's work must not grow with
// the number of stars. The old regexp expansion cost value length times stars,
// for every distinct value a wildcard term is run against.
func TestWildcardCostIndependentOfStars(t *testing.T) {
	pattern := strings.Repeat("*a", 20000) + "b"
	value := strings.Repeat("a", 20000)
	g := compileGlob(pattern)
	start := time.Now()
	for range 10 {
		if g.match(value) {
			t.Fatal("matched a value without the trailing b")
		}
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("10 matches took %v; wildcard cost is not linear", d)
	}
	if !g.match(value + "b") {
		t.Fatal("did not match a value with the trailing b")
	}
}

// Consecutive stars collapse to one segment boundary.
func TestGlobCollapsesStars(t *testing.T) {
	g := compileGlob("a*****b")
	if len(g.lines) != 1 || len(g.lines[0].segs) != 2 {
		t.Fatalf("a*****b compiled to %+v, want two segments", g.lines)
	}
}
