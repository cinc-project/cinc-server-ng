package api

import (
	"sync"

	"github.com/cinc-project/cinc-server-ng/internal/chefjson"
	"github.com/cinc-project/cinc-server-ng/internal/search"
	"github.com/cinc-project/cinc-server-ng/internal/store"
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

// idSet is the set of documents holding one term. Most terms are held by a
// single document (every attribute only one node carries), so a set of one is
// kept inline and a map is made only once a second document joins.
type idSet struct {
	one  string
	has  bool
	many map[string]struct{}
}

func (s *idSet) add(id string) {
	switch {
	case s.many != nil:
		s.many[id] = struct{}{}
	case !s.has:
		s.one, s.has = id, true
	case s.one != id:
		s.many = map[string]struct{}{s.one: {}, id: {}}
		s.one, s.has = "", false
	}
}

// del removes id, returning the set to its inline form once one member is left
// so a term that was briefly shared does not keep a map for good.
func (s *idSet) del(id string) {
	if s.many == nil {
		if s.has && s.one == id {
			s.one, s.has = "", false
		}
		return
	}
	delete(s.many, id)
	if len(s.many) == 1 {
		for last := range s.many {
			s.one, s.has = last, true
		}
		s.many = nil
	}
}

func (s *idSet) empty() bool { return !s.has && len(s.many) == 0 }

// addTo adds the set's members to out.
func (s *idSet) addTo(out search.DocIDs) {
	if s.has {
		out[s.one] = struct{}{}
	}
	for id := range s.many {
		out[id] = struct{}{}
	}
}

// fieldIndex is one field's postings: each value the field holds, with the
// documents holding it. Most fields hold a single value across the collection
// (again, any attribute only one node carries), so that value is kept inline
// and the map is made only once the field holds a second.
type fieldIndex struct {
	value  string
	ids    idSet             // the documents holding value, while values is nil
	values map[string]*idSet // every value, once the field has held two
}

func (f *fieldIndex) add(value, id string) {
	if f.values == nil {
		if f.ids.empty() || f.value == value {
			f.value = value
			f.ids.add(id)
			return
		}
		first := f.ids
		f.values = map[string]*idSet{f.value: &first}
		f.value, f.ids = "", idSet{}
	}
	ids, ok := f.values[value]
	if !ok {
		ids = &idSet{}
		f.values[value] = ids
	}
	ids.add(id)
}

// del removes id from value's documents, returning the field to its inline
// form once it holds a single value again.
func (f *fieldIndex) del(value, id string) {
	if f.values == nil {
		if f.value == value {
			f.ids.del(id)
			if f.ids.empty() {
				f.value = ""
			}
		}
		return
	}
	ids, ok := f.values[value]
	if !ok {
		return
	}
	ids.del(id)
	if ids.empty() {
		delete(f.values, value)
	}
	if len(f.values) == 1 {
		for v, last := range f.values {
			f.value, f.ids = v, *last
		}
		f.values = nil
	}
}

func (f *fieldIndex) empty() bool { return f.values == nil && f.ids.empty() }

// lookup returns the documents holding value, or nil.
func (f *fieldIndex) lookup(value string) *idSet {
	if f.values != nil {
		return f.values[value]
	}
	if f.value == value && !f.ids.empty() {
		return &f.ids
	}
	return nil
}

// each calls fn for every value the field holds.
func (f *fieldIndex) each(fn func(value string, ids *idSet)) {
	if f.values == nil {
		if !f.ids.empty() {
			fn(f.value, &f.ids)
		}
		return
	}
	for v, ids := range f.values {
		fn(v, ids)
	}
}

// collIndex is the inverted index for one collection of one organization. The
// postings view takes mu for each lookup it makes on the planner's behalf.
type collIndex struct {
	mu       sync.RWMutex
	merge    bool // node-style attribute precedence merge before flattening
	fields   map[string]*fieldIndex
	docTerms map[string][]term
	all      map[string]struct{}
}

func newCollIndex(merge bool) *collIndex {
	return &collIndex{
		merge:    merge,
		fields:   map[string]*fieldIndex{},
		docTerms: map[string][]term{},
		all:      map[string]struct{}{},
	}
}

// putRaw indexes a document from its stored bytes. A document that is not
// decodable JSON is dropped from the index, matching what the scanning path
// does with it.
func (c *collIndex) putRaw(id string, raw []byte) {
	doc, err := chefjson.DecodeObject(raw)
	if err != nil {
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
		f, ok := c.fields[field]
		if !ok {
			f = &fieldIndex{}
			c.fields[field] = f
		}
		for _, v := range values {
			f.add(v, id)
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

// retract removes a document's contributions, pruning values and fields that
// become empty so a long-lived index does not accumulate dead ones.
func (c *collIndex) retract(id string) {
	for _, t := range c.docTerms[id] {
		if f, ok := c.fields[t.field]; ok {
			f.del(t.value, id)
			if f.empty() {
				delete(c.fields, t.field)
			}
		}
	}
	c.docTerms[id] = nil
}

// size reports how many documents are indexed. Callers hold at least a read
// lock.
func (c *collIndex) size() int { return len(c.all) }

// postingsView adapts a collIndex to the planner. Each method holds the index's
// read lock for its own lookup only, not for the whole plan: the index is
// maintained by observers running on the writing goroutine, so a plan of many
// terms held under one lock would stall every write to the collection for all
// of them. Each method returns a fresh set, as the planner requires, so nothing
// it returns is touched after the lock is released.
//
// A plan's lookups can therefore see the index at different moments, with
// writes landing between them. Each lookup is consistent on its own, and a
// search is no more a snapshot than Solr's eventually-committed index is.
type postingsView struct{ c *collIndex }

func (p postingsView) All() search.DocIDs {
	p.c.mu.RLock()
	defer p.c.mu.RUnlock()
	out := make(search.DocIDs, len(p.c.all))
	for id := range p.c.all {
		out[id] = struct{}{}
	}
	return out
}

func (p postingsView) Exact(field, value string) search.DocIDs {
	p.c.mu.RLock()
	defer p.c.mu.RUnlock()
	f, ok := p.c.fields[field]
	if !ok {
		return search.DocIDs{}
	}
	ids := f.lookup(value)
	if ids == nil {
		return search.DocIDs{}
	}
	out := make(search.DocIDs, max(len(ids.many), 1))
	ids.addTo(out)
	return out
}

// Exists is the union of the field's values' documents: keeping a separate
// per-field document set would cost a set for every field of every document.
func (p postingsView) Exists(field string) search.DocIDs {
	return p.Match(field, func(string) bool { return true })
}

func (p postingsView) Match(field string, pred func(string) bool) search.DocIDs {
	p.c.mu.RLock()
	defer p.c.mu.RUnlock()
	out := search.DocIDs{}
	if f, ok := p.c.fields[field]; ok {
		f.each(func(value string, ids *idSet) {
			if pred(value) {
				ids.addTo(out)
			}
		})
	}
	return out
}

func (p postingsView) MatchAny(pred func(string) bool) search.DocIDs {
	p.c.mu.RLock()
	defer p.c.mu.RUnlock()
	out := search.DocIDs{}
	for _, f := range p.c.fields {
		f.each(func(value string, ids *idSet) {
			if pred(value) {
				ids.addTo(out)
			}
		})
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
