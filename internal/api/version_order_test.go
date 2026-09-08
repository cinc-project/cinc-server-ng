package api

import (
	"sort"
	"testing"
)

// compareVersions ran every segment through strconv.Atoi and used 0 on failure,
// so any two versions differing only in a non-numeric segment compared equal.
// Chef rejects such versions, but this server stores whatever it is given, and
// "equal" makes the ordering non-total: sort.Slice is not stable, so which one
// _latest resolves to depends on the input order.
func TestCompareVersionsIsTotal(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.2.0", "1.10.0", -1},
		{"1.10.0", "1.2.0", 1},
		{"2.0", "2.0.0", 0},
		{"1.0.0-alpha", "1.0.0", 1}, // deterministic, either way, but not equal
		{"1.0.0-alpha", "1.0.0-beta", -1},
		{"1.0.0-alpha", "1.0.0-alpha", 0},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		if got, back := compareVersions(c.a, c.b), compareVersions(c.b, c.a); got != -back {
			t.Errorf("compareVersions(%q,%q)=%d but (%q,%q)=%d: not antisymmetric",
				c.a, c.b, got, c.b, c.a, back)
		}
	}
}

// The consequence: a version list must sort to the same order however it arrives,
// or _latest is a coin flip.
func TestVersionSortIsDeterministic(t *testing.T) {
	inputs := [][]string{
		{"1.0.0", "1.0.0-alpha", "1.0.0-beta"},
		{"1.0.0-beta", "1.0.0", "1.0.0-alpha"},
		{"1.0.0-alpha", "1.0.0-beta", "1.0.0"},
	}
	var first []string
	for i, in := range inputs {
		got := append([]string(nil), in...)
		sort.Slice(got, func(x, y int) bool { return compareVersions(got[x], got[y]) > 0 })
		if i == 0 {
			first = got
			continue
		}
		for j := range got {
			if got[j] != first[j] {
				t.Fatalf("input order changed the result: %v vs %v", got, first)
			}
		}
	}
}
