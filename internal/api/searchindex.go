package api

import (
	"encoding/json"
	"sync"

	"github.com/tas50/cinc-zero/internal/search"
	"github.com/tas50/cinc-zero/internal/store"
)

// The inverted search index.
//
// Search used to answer every query by scanning the collection and evaluating
// the query against each document, which costs the same whether the query
// matches one node or all of them — on a fleet of thousands that is the
// dominant cost of a chef-client run.
//
// Instead each collection that gets searched is indexed: field/value pairs map
// to the documents carrying them, so a query resolves to a candidate set
// without touching documents that cannot match. The index is built once, on
// first search of a collection, and then kept current from the store's write
// stream, so a write costs one document's worth of work rather than
// invalidating everything.

// term is one indexed field/value pair, retained per document so a rewrite can
// retract exactly what that document previously contributed.
type term struct{ field, value string }

// collIndex is the inverted index for one collection of one organization.
// Callers hold mu for the whole of a plan, so the postings view it hands to the
// planner needs no locking of its own.
type collIndex struct {
	mu        sync.RWMutex
	merge     bool // node-style attribute precedence merge before flattening
	postings  map[string]map[string]map[string]struct{}
	fieldDocs map[string]map[string]struct{}
	docTerms  map[string][]term
	all       map[string]struct{}
}

func newCollIndex(merge bool) *collIndex {
	return &collIndex{
		merge:     merge,
		postings:  map[string]map[string]map[string]struct{}{},
		fieldDocs: map[string]map[string]struct{}{},
		docTerms:  map[string][]term{},
		all:       map[string]struct{}{},
	}
}

// putRaw indexes a document from its stored bytes. A document that is not
// decodable JSON is dropped from the index, matching what the scanning path
// does with it.
func (c *collIndex) putRaw(id string, raw []byte) {
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil {
		c.remove(id)
		return
	}
	searchable := doc
	if c.merge {
		searchable = nodeSearchDoc(doc)
	}
	c.put(id, search.Flatten(searchable))
}

// put replaces a document's entry with the given flattened fields.
func (c *collIndex) put(id string, fields map[string][]string) {
	c.retract(id)
	terms := make([]term, 0, len(fields))
	for field, values := range fields {
		byValue, ok := c.postings[field]
		if !ok {
			byValue = map[string]map[string]struct{}{}
			c.postings[field] = byValue
		}
		docs, ok := c.fieldDocs[field]
		if !ok {
			docs = map[string]struct{}{}
			c.fieldDocs[field] = docs
		}
		docs[id] = struct{}{}
		for _, v := range values {
			ids, ok := byValue[v]
			if !ok {
				ids = map[string]struct{}{}
				byValue[v] = ids
			}
			ids[id] = struct{}{}
			terms = append(terms, term{field, v})
		}
	}
	c.docTerms[id] = terms
	c.all[id] = struct{}{}
}

// remove drops a document from the index entirely.
func (c *collIndex) remove(id string) {
	c.retract(id)
	delete(c.docTerms, id)
	delete(c.all, id)
}

// retract removes a document's contributions, pruning postings that become
// empty so a long-lived index does not accumulate dead values.
func (c *collIndex) retract(id string) {
	for _, t := range c.docTerms[id] {
		if byValue, ok := c.postings[t.field]; ok {
			if ids, ok := byValue[t.value]; ok {
				delete(ids, id)
				if len(ids) == 0 {
					delete(byValue, t.value)
				}
			}
			if len(byValue) == 0 {
				delete(c.postings, t.field)
			}
		}
		if docs, ok := c.fieldDocs[t.field]; ok {
			delete(docs, id)
			if len(docs) == 0 {
				delete(c.fieldDocs, t.field)
			}
		}
	}
	c.docTerms[id] = nil
}

// size reports how many documents are indexed. Callers hold at least a read
// lock.
func (c *collIndex) size() int { return len(c.all) }

// postingsView adapts a collIndex to the planner. The caller holds the index's
// read lock for the duration of a plan, so these methods do no locking; each
// returns a fresh set, as the planner requires.
type postingsView struct{ c *collIndex }

func copySet(src map[string]struct{}) search.DocIDs {
	out := make(search.DocIDs, len(src))
	for id := range src {
		out[id] = struct{}{}
	}
	return out
}

func (p postingsView) All() search.DocIDs { return copySet(p.c.all) }

func (p postingsView) Exact(field, value string) search.DocIDs {
	return copySet(p.c.postings[field][value])
}

func (p postingsView) Exists(field string) search.DocIDs {
	return copySet(p.c.fieldDocs[field])
}

func (p postingsView) Match(field string, pred func(string) bool) search.DocIDs {
	out := search.DocIDs{}
	for value, ids := range p.c.postings[field] {
		if pred(value) {
			for id := range ids {
				out[id] = struct{}{}
			}
		}
	}
	return out
}

func (p postingsView) MatchAny(pred func(string) bool) search.DocIDs {
	out := search.DocIDs{}
	for _, byValue := range p.c.postings {
		for value, ids := range byValue {
			if pred(value) {
				for id := range ids {
					out[id] = struct{}{}
				}
			}
		}
	}
	return out
}

// searchIndexes holds one index per (organization, collection), built on first
// use and thereafter maintained from the write stream.
type searchIndexes struct {
	mu sync.RWMutex
	m  map[string]*collIndex
}

func newSearchIndexes() *searchIndexes {
	return &searchIndexes{m: map[string]*collIndex{}}
}

func indexKey(org, coll string) string { return org + "\x00" + coll }

// get returns the index for a collection, building it on first use.
//
// The build inserts the (write-locked) index into the registry before reading
// the collection, so a write landing mid-build blocks on that lock and is
// applied straight after rather than being lost. Applying a write the build
// already saw is harmless: indexing a document is idempotent.
func (s *searchIndexes) get(org *store.Org, coll string, merge bool) (*collIndex, error) {
	key := indexKey(org.Name(), coll)

	s.mu.RLock()
	idx, ok := s.m[key]
	s.mu.RUnlock()
	if ok {
		return idx, nil
	}

	s.mu.Lock()
	if idx, ok = s.m[key]; ok {
		s.mu.Unlock()
		return idx, nil
	}
	idx = newCollIndex(merge)
	idx.mu.Lock()
	s.m[key] = idx
	s.mu.Unlock()
	defer idx.mu.Unlock()

	if err := org.Range(coll, func(id string, raw []byte) bool {
		idx.putRaw(id, raw)
		return true
	}); err != nil {
		// Leave nothing half-built behind for the next caller to trust.
		s.mu.Lock()
		delete(s.m, key)
		s.mu.Unlock()
		return nil, err
	}
	return idx, nil
}

// observe applies one committed write to whichever index covers it. Writes to
// collections nobody has searched are ignored: the index for such a collection
// does not exist yet, and building it will read the current data.
func (s *searchIndexes) observe(ev store.Event) {
	// Dropping an organization invalidates every index it owns.
	if ev.Deleted && ev.Collection == "" {
		s.dropOrg(ev.Org)
		return
	}
	s.mu.RLock()
	idx, ok := s.m[indexKey(ev.Org, ev.Collection)]
	s.mu.RUnlock()
	if !ok {
		return
	}
	idx.mu.Lock()
	defer idx.mu.Unlock()
	if ev.Deleted {
		idx.remove(ev.Key)
		return
	}
	idx.putRaw(ev.Key, ev.Value)
}

// dropOrg discards every index belonging to an organization, so a name that is
// deleted and recreated cannot inherit the old contents.
func (s *searchIndexes) dropOrg(org string) {
	prefix := org + "\x00"
	s.mu.Lock()
	defer s.mu.Unlock()
	for key := range s.m {
		if len(key) >= len(prefix) && key[:len(prefix)] == prefix {
			delete(s.m, key)
		}
	}
}
