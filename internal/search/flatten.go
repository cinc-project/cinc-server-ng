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

// Flatten produces Chef's searchable field map for a document. Every leaf value
// is indexed under each suffix of its underscore-joined key path, so a nested
// attribute foo.bar.baz can be matched as "foo_bar_baz", "bar_baz", or "baz".
// Array elements are indexed under the same key. Keys and values are lowercased
// to match Solr's default text analysis (so queries are case-insensitive).
func Flatten(doc map[string]any) map[string][]string {
	fields := map[string][]string{}
	// path segments are already lowercased during descent, so add only lowercases
	// the value and builds each suffix key right-to-left ("baz", "bar_baz",
	// "foo_bar_baz") — reusing the shorter suffix instead of re-joining and
	// re-lowercasing the whole path for every suffix.
	add := func(path []string, val string) {
		val = strings.ToLower(val)
		key := ""
		for i := len(path) - 1; i >= 0; i-- {
			if key == "" {
				key = path[i]
			} else {
				key = path[i] + "_" + key
			}
			fields[key] = append(fields[key], val)
		}
	}
	// path is a single buffer grown and shrunk as the walk descends and returns
	// (depth-first, so siblings safely reuse the same backing array). add reads it
	// synchronously and never retains it, so no per-level copy is needed.
	var walk func(path []string, v any)
	walk = func(path []string, v any) {
		switch t := v.(type) {
		case map[string]any:
			for k, vv := range t {
				walk(append(path, strings.ToLower(k)), vv)
			}
		case []any:
			for _, vv := range t {
				walk(path, vv)
			}
		case nil:
			if len(path) > 0 {
				add(path, "")
			}
		default:
			if len(path) > 0 {
				add(path, scalarString(t))
			}
		}
	}
	walk(make([]string, 0, 8), doc)
	return fields
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
