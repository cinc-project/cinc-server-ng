package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/tas50/cinc-zero/internal/search"
	"github.com/tas50/cinc-zero/internal/store"
)

// searchCache memoizes the flattened searchable view of stored documents.
//
// Flattening (and the node attribute-precedence merge) is the dominant per-query
// cost, and a collection is usually searched far more often than it is written.
// Each entry is validated against the store's backing slice by identity: the
// store never mutates a value in place (Put writes a fresh slice), so an entry
// whose raw slice still aliases the stored one is known current. A write
// replaces the slice, so the stale entry simply fails the identity check and is
// recomputed — no explicit invalidation is needed. Entries for deleted objects
// linger but are bounded by the set of distinct keys ever searched; cinc-zero
// is a short-lived in-memory test server, so this is acceptable.
//
// A search scan reads one entry per stored document, so the hit path must not
// contend: the cache is a sync.Map, giving lock-free reads (the common case is a
// hit on unchanged content) while a first-flatten or post-write recompute does a
// single Store.
type searchCache struct {
	m sync.Map // key string -> searchEntry
}

type searchEntry struct {
	raw    []byte // identity-checked against the current stored slice
	merged map[string]any
	fields map[string][]string
}

func newSearchCache() *searchCache {
	return &searchCache{}
}

// searchDoc returns the searchable view of a stored document: its merged form
// (a node's attribute-precedence merge when mergeAttrs is set, otherwise the
// decoded object) and its flattened field map. Results are cached and reused
// while the underlying stored bytes are unchanged. ok is false when raw is not
// decodable JSON, in which case the caller skips the document.
func (a *API) searchDoc(coll, id string, raw []byte, mergeAttrs bool) (merged map[string]any, fields map[string][]string, ok bool) {
	key := coll + "\x00" + id

	if v, hit := a.search.m.Load(key); hit {
		if e := v.(searchEntry); sameBytes(e.raw, raw) {
			return e.merged, e.fields, true
		}
	}

	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil {
		return nil, nil, false
	}
	searchable := doc
	if mergeAttrs {
		searchable = nodeSearchDoc(doc)
	}
	fields = search.Flatten(searchable)

	a.search.m.Store(key, searchEntry{raw: raw, merged: searchable, fields: fields})
	return searchable, fields, true
}

// searchDocCached returns the cached searchable view for a document if one is
// present and still current (its stored slice unchanged), without computing on a
// miss. The scan uses this for the cheap hit path so the expensive flatten of
// missing entries can be batched and parallelized separately.
func (a *API) searchDocCached(coll, id string, raw []byte) (fields map[string][]string, ok bool) {
	if v, hit := a.search.m.Load(coll + "\x00" + id); hit {
		if e := v.(searchEntry); sameBytes(e.raw, raw) {
			return e.fields, true
		}
	}
	return nil, false
}

// sameBytes reports whether two slices share the same backing array (and length),
// i.e. are the identical stored value rather than merely equal in content.
func sameBytes(a, b []byte) bool {
	return len(a) == len(b) && (len(a) == 0 || &a[0] == &b[0])
}

// match is one search hit: its id and the raw stored object (returned verbatim
// for whole-object results). A partial-search projection needs the merged view,
// but only for the rows in the result window, so it is re-fetched there from the
// flatten cache rather than carried on every match.
type match struct {
	id  string
	raw json.RawMessage
}

// collectAll returns every document in the index as a match, sorted by id,
// without decoding or flattening any of them. This is the match-all (*:*) fast
// path for whole-object results: the field map is never consulted, so the
// dominant flatten cost is skipped entirely.
func (a *API) collectAll(org *store.Org, idx searchIndex) ([]match, error) {
	var matches []match
	if err := org.Range(idx.collection, func(id string, raw []byte) bool {
		matches = append(matches, match{id: id, raw: raw})
		return true
	}); err != nil {
		return nil, err
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].id < matches[j].id })
	return matches, nil
}

// collectMatches scans an index's collection and returns the documents matching
// query, sorted by id. Cached documents are matched inline on the cheap hit path;
// the expensive part — decoding, merging, and flattening uncached documents — is
// the dominant cost of a cold scan, so it is batched and fanned out across
// workers. Documents are read copy-free and the flatten cache it populates makes
// later scans cheap. Splitting the work this way keeps warm scans free of any
// goroutine overhead while still parallelizing the cold flatten.
func (a *API) collectMatches(org *store.Org, idx searchIndex, query search.Query) ([]match, error) {
	type doc struct {
		id  string
		raw []byte
	}
	var matches []match
	var misses []doc
	if err := org.Range(idx.collection, func(id string, raw []byte) bool {
		if fields, ok := a.searchDocCached(idx.collection, id, raw); ok {
			if query.Matches(fields) {
				matches = append(matches, match{id: id, raw: raw})
			}
		} else {
			// raw is the stored backing slice (read-only); safe to flatten outside
			// the lock and concurrently, since the store never mutates it in place.
			misses = append(misses, doc{id, raw})
		}
		return true
	}); err != nil {
		return nil, err
	}

	if len(misses) > 0 {
		// len(misses) is bounded by the documents already resident in the store
		// (one bool per uncached doc), not a per-request user-controlled size, so
		// this cannot be driven to an out-of-bounds allocation.
		// nosemgrep: go-uncontrolled-allocation
		hit := make([]bool, len(misses))
		parallelFor(len(misses), func(i int) {
			_, fields, ok := a.searchDoc(idx.collection, misses[i].id, misses[i].raw, idx.mergeAttrs)
			if ok && query.Matches(fields) {
				hit[i] = true
			}
		})
		for i, d := range misses {
			if hit[i] {
				matches = append(matches, match{id: d.id, raw: d.raw})
			}
		}
	}

	sort.Slice(matches, func(i, j int) bool { return matches[i].id < matches[j].id })
	return matches, nil
}

// parallelFor runs fn for each index 0..n-1. Small scans run serially to avoid
// goroutine overhead; larger ones are fanned out across GOMAXPROCS workers
// pulling indices off a shared counter. fn must be safe to call concurrently for
// distinct indices (each writes only its own slot).
func parallelFor(n int, fn func(i int)) {
	const serialThreshold = 64
	workers := runtime.GOMAXPROCS(0)
	if n < serialThreshold || workers <= 1 {
		for i := range n {
			fn(i)
		}
		return
	}
	if workers > n {
		workers = n
	}
	var next atomic.Int64
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1)) - 1
				if i >= n {
					return
				}
				fn(i)
			}
		}()
	}
	wg.Wait()
}

// Search is served in-process: matching objects are flattened the way Chef's
// indexer would and filtered by a parsed Solr query. The built-in indexes are
// node, role, client, and environment; any other index name is treated as a
// data bag. The node index searches deep-merged attributes (default < normal <
// override < automatic) plus top-level fields, matching chef-client.

const defaultSearchRows = 1000

func (a *API) registerSearchRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /organizations/{org}/search", a.listSearchIndexes)
	mux.HandleFunc("GET /organizations/{org}/search/{index}", a.runSearch)
	mux.HandleFunc("POST /organizations/{org}/search/{index}", a.runSearch)
}

func (a *API) listSearchIndexes(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	base := requestBaseURL(r) + "/organizations/" + org.Name() + "/search/"
	out := map[string]string{
		"node":        base + "node",
		"role":        base + "role",
		"client":      base + "client",
		"environment": base + "environment",
	}
	keys, err := org.Keys(dataBagsColl)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, bag := range keys {
		out[bag] = base + bag
	}
	writeJSON(w, http.StatusOK, out)
}

// searchIndex describes where an index's documents live, how to address one,
// and which ACL governs reading them. aclType/aclObject mirror what
// classifyRequest would require of the equivalent direct read route, so search
// results can be filtered to what the actor could have fetched directly.
// aclObject is empty for indexes whose documents are governed one ACL per
// document (nodes, roles, clients, environments) and names the owning object
// for data bags, whose items all share the bag's ACL.
type searchIndex struct {
	collection string
	mergeAttrs bool // node-style attribute precedence merge
	aclType    string
	aclObject  string
	urlFor     func(r *http.Request, org, id string) string
}

func (a *API) resolveIndex(r *http.Request, org *store.Org, name string) (searchIndex, bool, error) {
	switch name {
	case "node", "role", "client", "environment":
		coll := name + "s"
		return searchIndex{
			collection: coll,
			mergeAttrs: name == "node",
			aclType:    coll,
			urlFor:     func(r *http.Request, org, id string) string { return objectURL(r, org, coll, id) },
		}, true, nil
	default:
		_, ok, err := org.View(dataBagsColl, name)
		if err != nil {
			return searchIndex{}, false, err
		}
		if !ok {
			return searchIndex{}, false, nil
		}
		return searchIndex{
			collection: dataBagItemsColl(name),
			aclType:    "data",
			aclObject:  name,
			urlFor:     func(r *http.Request, org, id string) string { return dataBagURL(r, org, name) + "/" + id },
		}, true, nil
	}
}

// searchReadFilter returns a predicate reporting whether the request's actor
// may read a matched document, or nil when no filtering applies — enforcement
// off (the permissive default), no authenticated actor, or the superuser.
//
// A search scans a whole collection, so the filter must not cost a store read
// per row. Group membership and the org's stored ACLs are each resolved once
// up front and the per-row decision is then made from memory.
func (a *API) searchReadFilter(r *http.Request, org *store.Org, idx searchIndex) (func(id string) bool, error) {
	if !a.enforceACL {
		return nil, nil
	}
	actor, ok := actorFromContext(r.Context())
	if !ok || actor.IsGlobalAdmin {
		return nil, nil
	}
	// A data bag's items all share the bag's ACL, so one check decides the
	// whole index.
	if idx.aclObject != "" {
		allowed, err := actorAllowed(org, actor, idx.aclType, idx.aclObject, "read")
		if err != nil {
			return nil, err
		}
		return func(string) bool { return allowed }, nil
	}

	member, err := actorGroups(org, actor)
	if err != nil {
		return nil, err
	}
	stored := map[string]bool{}
	prefix := idx.aclType + "/"
	if err := org.Range("acls", func(key string, raw []byte) bool {
		name, ok := strings.CutPrefix(key, prefix)
		if !ok {
			return true
		}
		// The typed decode avoids building a map[string]any per ACL document,
		// which a collection-wide scan would otherwise pay for every row on
		// every request. An unexpected shape falls back to the tolerant decode.
		if ace, ok := decodeReadACE(raw); ok {
			stored[name] = ace.allows(actor.Name, member)
			return true
		}
		var acl map[string]any
		if json.Unmarshal(raw, &acl) == nil {
			stored[name] = aceAllows(acl["read"], actor, member)
		}
		return true
	}); err != nil {
		return nil, err
	}
	// An object with no stored ACL falls back to the same permissive default
	// loadACL applies on the direct read route.
	byDefault := aceAllows(defaultACL()["read"], actor, member)
	return func(id string) bool {
		if allowed, ok := stored[id]; ok {
			return allowed
		}
		return byDefault
	}, nil
}

func (a *API) runSearch(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	indexName := r.PathValue("index")
	idx, ok, err := a.resolveIndex(r, org, indexName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "I don't know how to search for "+indexName+" data objects.")
		return
	}

	qStr := r.URL.Query().Get("q")
	if qStr == "" {
		qStr = "*:*"
	}
	query, err := search.Parse(qStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid search query: "+err.Error())
		return
	}

	// Partial search (POST body of result-key -> attribute path) is applied per
	// matching row; an empty or absent body yields whole-object results.
	var partial map[string][]string
	if r.Method == http.MethodPost {
		if err := json.NewDecoder(r.Body).Decode(&partial); err != nil && !errors.Is(err, io.EOF) {
			writeError(w, http.StatusBadRequest, "invalid partial search body")
			return
		}
	}

	// Whole-object match-all needs no field map, so skip flattening entirely and
	// return the stored documents directly; every other query (and any partial
	// projection, which needs the merged view) flattens and filters.
	var matches []match
	if partial == nil && search.IsMatchAll(query) {
		matches, err = a.collectAll(org, idx)
	} else {
		matches, err = a.collectMatches(org, idx, query)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Drop documents the actor could not have read directly, before the window
	// is taken, so neither the rows nor "total" disclose them. A query that
	// matched nothing needs no filter, so it does not pay to resolve one.
	var allow func(string) bool
	if len(matches) > 0 {
		if allow, err = a.searchReadFilter(r, org, idx); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	if allow != nil {
		readable := make([]match, 0, len(matches))
		for _, m := range matches {
			if allow(m.id) {
				readable = append(readable, m)
			}
		}
		matches = readable
	}

	start := queryInt(r, "start", 0)
	rows := queryInt(r, "rows", defaultSearchRows)
	total := len(matches)
	// Clamp the window without ever computing start+rows directly: both are
	// caller-supplied and can be near math.MaxInt, so the sum can overflow to a
	// negative value and produce an invalid (low > high) slice. rows is
	// non-negative (queryInt rejects negatives), so comparing it against the
	// remaining row count is overflow-safe.
	lo := clamp(start, 0, total)
	hi := total
	if rows <= total-lo {
		hi = lo + rows
	}
	window := matches[lo:hi]

	out := make([]any, 0, len(window))
	for _, m := range window {
		if partial != nil {
			// Re-fetch the merged view for this row only (a flatten-cache hit, since
			// collectMatches flattened every match); the full result set is not merged.
			merged, _, _ := a.searchDoc(idx.collection, m.id, m.raw, idx.mergeAttrs)
			data := map[string]any{}
			for key, path := range partial {
				if len(path) == 0 {
					data[key] = nil // empty projection: no value for this key
					continue
				}
				data[key] = traversePath(merged, path)
			}
			out = append(out, map[string]any{
				"url":  idx.urlFor(r, org.Name(), m.id),
				"data": data,
			})
		} else {
			out = append(out, m.raw)
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"total": total,
		"start": start,
		"rows":  out,
	})
}

// nodeSearchDoc produces the searchable view of a node: its attribute
// precedence levels deep-merged (default < normal < override < automatic),
// overlaid on the node's top-level fields (name, chef_environment, run_list…).
func nodeSearchDoc(node map[string]any) map[string]any {
	merged := map[string]any{}
	for _, level := range []string{"default", "normal", "override", "automatic"} {
		if attrs, ok := node[level].(map[string]any); ok {
			deepMerge(merged, attrs)
		}
	}
	out := map[string]any{}
	for k, v := range node {
		out[k] = v
	}
	for k, v := range merged {
		out[k] = v
	}
	return out
}

// deepMerge recursively merges src into dst, with src winning on scalar keys.
func deepMerge(dst, src map[string]any) {
	for k, v := range src {
		if sub, ok := v.(map[string]any); ok {
			if existing, ok := dst[k].(map[string]any); ok {
				deepMerge(existing, sub)
				continue
			}
			cp := map[string]any{}
			deepMerge(cp, sub)
			dst[k] = cp
			continue
		}
		dst[k] = v
	}
}

// traversePath walks doc following path, returning nil if any segment is absent.
func traversePath(doc map[string]any, path []string) any {
	var cur any = doc
	for _, key := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur, ok = m[key]
		if !ok {
			return nil
		}
	}
	return cur
}

func queryInt(r *http.Request, key string, def int) int {
	if v := r.URL.Query().Get(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return def
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
