package api

import "github.com/tas50/cinc-zero/internal/search"

// Thin aliases so index tests can drive the planner without importing the
// search package into every case.
func parseForTest(q string) (search.Query, error) { return search.Parse(q) }
func planForTest(q search.Query, p search.Postings) (search.DocIDs, bool) {
	return search.Plan(q, p)
}
