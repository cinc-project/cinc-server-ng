package differential

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
)

// The baseline is the differences we already know about but have not yet
// triaged into a fix or an accepted deviation (known.go). It exists so the
// comparison can gate every change from the day it is turned on: a run fails
// on any unexplained difference that is not in the baseline, while the debt
// the baseline records is worked down separately.
//
// It is debt, not policy. An entry says "this differs and nobody has decided
// what to do about it yet"; it carries no reason because it has none. Entries
// should only ever leave the baseline — fixed, or promoted to known.go with a
// reason — and a change that adds one should say why in its review.
//
// An entry records the values on both sides, not just the field, so a known
// difference that starts differing in a new way is reported as new.

// BaselineEntry is one known, untriaged difference. Values are rendered as the
// report renders them.
type BaselineEntry struct {
	Step      string `json:"step"`
	Field     string `json:"field"`
	Reference string `json:"reference"`
	Candidate string `json:"candidate"`
}

func entryOf(d Difference) BaselineEntry {
	return BaselineEntry{
		Step:      d.Step,
		Field:     d.Field,
		Reference: fmt.Sprintf("%v", d.Reference),
		Candidate: fmt.Sprintf("%v", d.Candidate),
	}
}

// BaselineOf records diffs as baseline entries, in a stable order.
func BaselineOf(diffs []Difference) []BaselineEntry {
	out := make([]BaselineEntry, 0, len(diffs))
	for _, d := range diffs {
		out = append(out, entryOf(d))
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Step != b.Step {
			return a.Step < b.Step
		}
		if a.Field != b.Field {
			return a.Field < b.Field
		}
		if a.Reference != b.Reference {
			return a.Reference < b.Reference
		}
		return a.Candidate < b.Candidate
	})
	return out
}

// FormatBaseline renders entries as the baseline file's contents.
func FormatBaseline(entries []BaselineEntry) []byte {
	if entries == nil {
		entries = []BaselineEntry{}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	_ = enc.Encode(entries)
	return buf.Bytes()
}

// ParseBaseline reads a baseline file's contents.
func ParseBaseline(data []byte) ([]BaselineEntry, error) {
	var entries []BaselineEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("baseline: %w", err)
	}
	return entries, nil
}

// ApplyBaseline splits unexplained differences into those the baseline does
// not record (fresh: these fail a run) and returns the baseline entries no
// difference matched (stale: fixed, or no longer reproducing, and due for
// removal). Each entry absorbs at most one difference.
func ApplyBaseline(diffs []Difference, base []BaselineEntry) (fresh []Difference, stale []BaselineEntry) {
	remaining := map[BaselineEntry]int{}
	for _, e := range base {
		remaining[e]++
	}
	for _, d := range diffs {
		if e := entryOf(d); remaining[e] > 0 {
			remaining[e]--
			continue
		}
		fresh = append(fresh, d)
	}
	for _, e := range base {
		if remaining[e] > 0 {
			remaining[e]--
			stale = append(stale, e)
		}
	}
	return fresh, stale
}
