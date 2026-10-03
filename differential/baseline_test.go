package differential_test

import (
	"os"
	"reflect"
	"testing"

	"github.com/cinc-project/cinc-server-ng/differential"
)

// A key minted per install (a group named by its authz id, say) must not make
// a field path differ between runs, or no baseline could ever match it.
func TestNormalizeReplacesIdentifierKeys(t *testing.T) {
	got := differential.Normalize(map[string]any{
		"00000000000011129a2a0665f564c967": "a",
		"0000000000007230cd0973102024c03f": "b",
		"admins":                           "c",
	}, "")
	want := map[string]any{"<guid>": "a", "<guid>#2": "b", "admins": "c"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Normalize = %v, want %v", got, want)
	}
}

func TestBaselineSeparatesNewFromKnownDebt(t *testing.T) {
	diffs := []differential.Difference{
		{Step: "node missing", Field: "error[0]", Reference: "node 'x' not found", Candidate: "Cannot find nodes x"},
		{Step: "node acl", Field: "create.actors.length", Reference: 2, Candidate: 1},
		{Step: "role read", Field: "description", Reference: "d", Candidate: "<missing>"},
	}
	base := []differential.BaselineEntry{
		{Step: "node missing", Field: "error[0]", Reference: "node 'x' not found", Candidate: "Cannot find nodes x"},
		// Same field, but the candidate now answers differently: that is a new
		// difference, not the recorded one.
		{Step: "node acl", Field: "create.actors.length", Reference: "2", Candidate: "0"},
		// Recorded but no longer seen: fixed (or flaky), and due for removal.
		{Step: "org read", Field: "full_name", Reference: "Differential", Candidate: "diffs"},
	}
	fresh, stale := differential.ApplyBaseline(diffs, base)
	if len(fresh) != 2 || fresh[0].Step != "node acl" || fresh[1].Step != "role read" {
		t.Errorf("fresh = %v, want the node acl and role read differences", fresh)
	}
	if len(stale) != 2 || stale[0].Step != "node acl" || stale[1].Step != "org read" {
		t.Errorf("stale = %v, want the changed node acl entry and the org read entry", stale)
	}
}

// The baseline written by a run is the file to commit: stable order, so a
// change to it is a readable diff, and it parses back to the same entries.
func TestBaselineRoundTrips(t *testing.T) {
	diffs := []differential.Difference{
		{Step: "b", Field: "x", Reference: []any{"y"}, Candidate: nil},
		{Step: "a", Field: "status", Reference: 201, Candidate: 200},
	}
	data := differential.FormatBaseline(differential.BaselineOf(diffs))
	entries, err := differential.ParseBaseline(data)
	if err != nil {
		t.Fatal(err)
	}
	want := []differential.BaselineEntry{
		{Step: "a", Field: "status", Reference: "201", Candidate: "200"},
		{Step: "b", Field: "x", Reference: "[y]", Candidate: "<nil>"},
	}
	if !reflect.DeepEqual(entries, want) {
		t.Errorf("round trip = %v, want %v", entries, want)
	}
	if fresh, stale := differential.ApplyBaseline(diffs, entries); len(fresh) != 0 || len(stale) != 0 {
		t.Errorf("a run's own baseline does not match it: fresh %v, stale %v", fresh, stale)
	}
	if empty, err := differential.ParseBaseline([]byte("[]\n")); err != nil || len(empty) != 0 {
		t.Errorf("empty baseline = %v, %v", empty, err)
	}
}

// The committed baseline is read only by the real-server run; check it parses
// here too, so a bad edit fails the ordinary test suite instead.
func TestCommittedBaselineParses(t *testing.T) {
	data, err := os.ReadFile("baseline.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := differential.ParseBaseline(data); err != nil {
		t.Fatal(err)
	}
}
