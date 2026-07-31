package search

// Planning a query against an index.
//
// Matches evaluates one document at a time, so answering a query with it costs
// a pass over the whole collection however few documents actually match. Plan
// instead resolves a query to a set of document ids using an inverted index, so
// cost tracks the number of candidates rather than the size of the collection.
//
// The two must agree exactly: Plan is an optimization of Matches, not a second
// definition of the query language. Every operator is expressed in terms of the
// same predicates Matches uses, and anything Plan does not recognize reports
// ok=false so the caller can fall back to scanning.

// DocIDs is a set of document identifiers.
type DocIDs map[string]struct{}

// Postings is the index side of planning: a way to ask which documents carry a
// given field or value. Implementations own storage; this package owns the set
// algebra and the query semantics.
//
// Every method returns a set the caller may modify, so implementations must
// return a fresh set rather than internal state.
type Postings interface {
	// Exact returns the documents whose field holds exactly value.
	Exact(field, value string) DocIDs
	// Exists returns the documents that have any value for field.
	Exists(field string) DocIDs
	// Match returns the documents with any value of field satisfying pred. It
	// walks that field's distinct values, which is what keeps a wildcard or
	// range query off the document list.
	Match(field string, pred func(value string) bool) DocIDs
	// MatchAny is Match across every field, for bare terms.
	MatchAny(pred func(value string) bool) DocIDs
	// All returns every document in the collection.
	All() DocIDs
}

// Plan resolves q to the set of matching document ids. ok is false when the
// query contains something the planner does not handle, in which case the
// caller must fall back to evaluating Matches over the collection.
func Plan(q Query, p Postings) (DocIDs, bool) {
	switch t := q.(type) {
	case matchAll:
		return p.All(), true

	case termQ:
		// A term with no wildcard is a direct postings hit; one with a wildcard
		// has to consult the field's value dictionary, which is still far
		// smaller than the document list.
		if t.field == "" {
			return p.MatchAny(t.matchVal), true
		}
		if t.phrase || !hasWildcard(t.value) {
			return p.Exact(t.field, t.value), true
		}
		return p.Match(t.field, t.matchVal), true

	case existsQ:
		if t.field == "" {
			return p.All(), true
		}
		return p.Exists(t.field), true

	case rangeQ:
		return p.Match(t.field, t.inRange), true

	case andQ:
		l, ok := Plan(t.l, p)
		if !ok {
			return nil, false
		}
		// Nothing on the left means nothing overall, so the right side need not
		// be resolved at all.
		if len(l) == 0 {
			return l, true
		}
		r, ok := Plan(t.r, p)
		if !ok {
			return nil, false
		}
		return intersect(l, r), true

	case orQ:
		l, ok := Plan(t.l, p)
		if !ok {
			return nil, false
		}
		r, ok := Plan(t.r, p)
		if !ok {
			return nil, false
		}
		return union(l, r), true

	case notQ:
		inner, ok := Plan(t.q, p)
		if !ok {
			return nil, false
		}
		return difference(p.All(), inner), true
	}
	return nil, false
}

func hasWildcard(v string) bool {
	for i := range len(v) {
		if v[i] == '*' || v[i] == '?' {
			return true
		}
	}
	return false
}

// intersect keeps the ids present in both sets, iterating the smaller one.
func intersect(a, b DocIDs) DocIDs {
	if len(b) < len(a) {
		a, b = b, a
	}
	out := make(DocIDs, len(a))
	for id := range a {
		if _, ok := b[id]; ok {
			out[id] = struct{}{}
		}
	}
	return out
}

// union merges both sets, growing the larger one.
func union(a, b DocIDs) DocIDs {
	if len(b) > len(a) {
		a, b = b, a
	}
	for id := range b {
		a[id] = struct{}{}
	}
	return a
}

// difference removes b's ids from a.
func difference(a, b DocIDs) DocIDs {
	for id := range b {
		delete(a, id)
	}
	return a
}
