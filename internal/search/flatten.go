// Package search implements Chef's in-process search: it flattens objects into
// the field map Chef's indexer produces and evaluates Solr-style queries
// against that map, matching how chef-zero serves search without an external
// search engine.
package search

import (
	"encoding/json"
	"strconv"
	"strings"
)

// maxFlattenBytes bounds the suffix keys Flatten builds for one document,
// counted as each key's length plus a slice entry. Indexing every suffix costs
// leaves x depth^2 bytes, which the request body cap does not bound: a body
// nested thousands of levels deep would cost hundreds of gigabytes. An ordinary
// node, even a large one, stays far below it.
const maxFlattenBytes = 64 << 20

// flattenEntryCost is what one indexed value costs beyond its key: a string
// header in the field's value slice.
const flattenEntryCost = 16

// Flatten produces Chef's searchable field map for a document. Every leaf value
// is indexed under each suffix of its underscore-joined key path, so a nested
// attribute foo.bar.baz can be matched as "foo_bar_baz", "bar_baz", or "baz".
// Array elements are indexed under the same key. Keys and values are lowercased
// to match Solr's default text analysis (so queries are case-insensitive).
//
// A document whose suffix keys would exceed maxFlattenBytes is indexed instead
// under each leaf's own key only ("baz"), which costs no more than the document
// itself. The whole document falls back, not the leaves past the budget, so
// what it can be found by does not depend on map iteration order. Top-level
// fields (name, chef_environment, run_list, ...) are their own leaf key, so they
// stay searchable either way.
func Flatten(doc map[string]any) map[string][]string {
	if fields, ok := flatten(doc, true); ok {
		return fields
	}
	fields, _ := flatten(doc, false)
	return fields
}

// flatten indexes doc under every path suffix (suffixes) or under each leaf's
// own key. With suffixes it gives up, reporting false, once the keys it built
// pass maxFlattenBytes.
func flatten(doc map[string]any, suffixes bool) (map[string][]string, bool) {
	fields := map[string][]string{}
	budget := maxFlattenBytes
	// path segments are already lowercased during descent, so add only lowercases
	// the value and builds each suffix key right-to-left ("baz", "bar_baz",
	// "foo_bar_baz") — reusing the shorter suffix instead of re-joining and
	// re-lowercasing the whole path for every suffix.
	add := func(path []string, val string) bool {
		val = strings.ToLower(val)
		if !suffixes {
			key := path[len(path)-1]
			fields[key] = append(fields[key], val)
			return true
		}
		key := ""
		for i := len(path) - 1; i >= 0; i-- {
			if key == "" {
				key = path[i]
			} else {
				// Charge the key before building it, so an over-budget key is
				// never allocated.
				budget -= len(path[i]) + 1 + len(key) + flattenEntryCost
				if budget < 0 {
					return false
				}
				key = path[i] + "_" + key
			}
			fields[key] = append(fields[key], val)
		}
		return true
	}
	// path is a single buffer grown and shrunk as the walk descends and returns
	// (depth-first, so siblings safely reuse the same backing array). add reads it
	// synchronously and never retains it, so no per-level copy is needed.
	var walk func(path []string, v any) bool
	walk = func(path []string, v any) bool {
		switch t := v.(type) {
		case map[string]any:
			for k, vv := range t {
				if !walk(append(path, strings.ToLower(k)), vv) {
					return false
				}
			}
		case []any:
			for _, vv := range t {
				if !walk(path, vv) {
					return false
				}
			}
		case nil:
			if len(path) > 0 {
				return add(path, "")
			}
		default:
			if len(path) > 0 {
				return add(path, scalarString(t))
			}
		}
		return true
	}
	ok := walk(make([]string, 0, 8), doc)
	return fields, ok
}

// scalarString renders a JSON scalar as its searchable string form. A number
// decoded as its literal (json.Number, as cinc-server-ng's stored documents
// are) is indexed exactly as stored, matching Chef; one decoded as float64 is
// rendered without a trailing ".0".
func scalarString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return string(t)
	case bool:
		return strconv.FormatBool(t)
	case float64:
		return strconv.FormatFloat(t, 'g', -1, 64)
	default:
		return ""
	}
}
