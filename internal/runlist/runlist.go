// Package runlist puts node and role run lists into the canonical form erchef
// stores them in (chef_object_base:normalize_run_list/1, applied by chef_node
// and chef_role on every create and update): a bare item is qualified as
// "recipe[item]", "recipe[...]" and "role[...]" items are kept as sent, and
// exact duplicates are dropped, keeping the first occurrence and the order.
//
// Only exact duplicates go: "recipe[foo]" and "recipe[foo::default]" name the
// same recipe but are different items, and erchef keeps both.
package runlist

import (
	"bytes"
	"encoding/json/jsontext"
	"slices"
	"strings"

	"github.com/cinc-project/cinc-server-ng/internal/chefjson"
)

// Normalize returns items in erchef's canonical form. It always returns a new
// slice.
func Normalize(items []string) []string {
	out := make([]string, 0, len(items))
	seen := make(map[string]bool, len(items))
	for _, item := range items {
		item = qualify(item)
		if !seen[item] {
			seen[item] = true
			out = append(out, item)
		}
	}
	return out
}

// qualify is chef_object_base:normalize_item/1.
func qualify(item string) string {
	if strings.HasPrefix(item, "recipe[") || strings.HasPrefix(item, "role[") {
		return item
	}
	return "recipe[" + item + "]"
}

// NormalizeNode normalizes the run_list of the node document doc, which must
// already be in chefjson's stored form. Everything else is kept as sent; a
// document that needs no change is returned as is.
func NormalizeNode(doc []byte) ([]byte, error) {
	return normalize(doc, false)
}

// NormalizeRole normalizes the run_list and every env_run_lists entry of the
// role document doc, as NormalizeNode does for a node.
func NormalizeRole(doc []byte) ([]byte, error) {
	return normalize(doc, true)
}

// normalize rewrites doc only when a run list in it is not already canonical.
// A chef-client saves its node with a canonical run list on every run, so the
// common case is a scan with no re-encode.
//
// As in erchef, the first member of a repeated name is the one read and
// rewritten. A run list that is not a list of strings is left alone: erchef
// would have refused it, and refusing is validation's job, not this one's.
func normalize(doc []byte, role bool) ([]byte, error) {
	if !needsChange(doc, role) {
		return doc, nil
	}
	tree, err := chefjson.Parse(doc)
	if err != nil {
		return nil, err
	}
	obj, ok := tree.(*chefjson.Object)
	if !ok {
		return doc, nil
	}
	if v, ok := obj.Get("run_list"); ok {
		if items, ok := stringList(v); ok {
			obj.Set("run_list", toAny(Normalize(items)))
		}
	}
	if role {
		if v, ok := obj.Get("env_run_lists"); ok {
			if envs, ok := v.(*chefjson.Object); ok {
				// erchef maps over every pair, so a repeated environment
				// name has each of its lists normalized.
				for i := range envs.Members {
					if items, ok := stringList(envs.Members[i].Value); ok {
						envs.Members[i].Value = toAny(Normalize(items))
					}
				}
			}
		}
	}
	return chefjson.Marshal(obj), nil
}

// needsChange reports whether normalize would rewrite doc, decoding only the
// run list members and skipping everything else.
func needsChange(doc []byte, role bool) bool {
	dec := jsontext.NewDecoder(bytes.NewReader(doc), jsontext.AllowDuplicateNames(true))
	if tok, err := dec.ReadToken(); err != nil || tok.Kind() != '{' {
		return false
	}
	var seenRunList, seenEnvRunLists bool
	for dec.PeekKind() == '"' {
		key, err := dec.ReadToken()
		if err != nil {
			return false
		}
		var check func(any) bool
		switch name := key.String(); {
		case name == "run_list" && !seenRunList:
			seenRunList, check = true, listChanges
		case name == "env_run_lists" && role && !seenEnvRunLists:
			seenEnvRunLists, check = true, envListsChange
		default:
			if dec.SkipValue() != nil {
				return false
			}
			continue
		}
		val, err := dec.ReadValue()
		if err != nil {
			return false
		}
		v, err := chefjson.Parse(val)
		if err != nil {
			return false
		}
		if check(v) {
			return true
		}
	}
	return false
}

// listChanges reports whether v is a list of strings Normalize would change.
func listChanges(v any) bool {
	items, ok := stringList(v)
	return ok && !slices.Equal(Normalize(items), items)
}

// envListsChange reports whether v is an env_run_lists object holding a list
// Normalize would change.
func envListsChange(v any) bool {
	envs, ok := v.(*chefjson.Object)
	if !ok {
		return false
	}
	for _, m := range envs.Members {
		if listChanges(m.Value) {
			return true
		}
	}
	return false
}

// stringList returns v as a list of strings, or false when it is not one.
func stringList(v any) ([]string, bool) {
	arr, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, len(arr))
	for i, e := range arr {
		s, ok := e.(string)
		if !ok {
			return nil, false
		}
		out[i] = s
	}
	return out, true
}

func toAny(items []string) []any {
	out := make([]any, len(items))
	for i, s := range items {
		out[i] = s
	}
	return out
}
