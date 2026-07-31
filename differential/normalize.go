package differential

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Normalization exists because two servers cannot produce byte-identical
// responses even when they agree: they are on different hosts, they mint
// different identifiers, and they generate different keys.
//
// The risk is doing too much of it. Every rule here erases a difference, so an
// over-broad rule hides exactly the bugs this package is meant to find. The
// rules are therefore narrow and each is justified: a value is only replaced
// when it is unequal *by construction*, never merely because it happened to
// differ in some run.

// Placeholders substituted for values that cannot match by construction.
const (
	placeholderServer = "<server>"
	placeholderGUID   = "<guid>"
	placeholderTime   = "<time>"
	placeholderKey    = "<key>"
)

// volatileFields are replaced wherever they appear, because the two servers
// necessarily produce different values for them.
var volatileFields = map[string]string{
	"guid":            placeholderGUID, // per-object identifier, minted independently
	"org_guid":        placeholderGUID,
	"id":              "", // not volatile in general; handled by idIsVolatile
	"public_key":      placeholderKey,
	"private_key":     placeholderKey,
	"certificate":     placeholderKey,
	"created_at":      placeholderTime,
	"updated_at":      placeholderTime,
	"create_time":     placeholderTime,
	"last_updated_at": placeholderTime,
	"ohai_time":       placeholderTime,
}

// guidPattern matches the identifier shapes Chef mints: a 32-character hex
// string, or a hyphenated UUID.
var guidPattern = regexp.MustCompile(`\b[0-9a-fA-F]{32}\b|\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`)

// pemPattern matches an embedded PEM block, which appears inside JSON strings
// for keys and certificates.
var pemPattern = regexp.MustCompile(`(?s)-----BEGIN [^-]+-----.*?-----END [^-]+-----`)

// Normalize rewrites a decoded response so two targets are comparable. base is
// the target's own BaseURL, which is rewritten to a placeholder so URLs the
// server builds from its own hostname compare equal.
func Normalize(v any, base string) any {
	origin := originOf(base)
	return normalize(v, "", origin)
}

// originOf reduces a base URL to scheme://host, the part that differs between
// targets. The organization path is deliberately kept: a response pointing at
// the wrong organization is a real difference.
func originOf(base string) string {
	rest, ok := strings.CutPrefix(base, "https://")
	scheme := "https://"
	if !ok {
		rest, ok = strings.CutPrefix(base, "http://")
		scheme = "http://"
		if !ok {
			return ""
		}
	}
	host, _, _ := strings.Cut(rest, "/")
	return scheme + host
}

func normalize(v any, key, origin string) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = normalize(val, k, origin)
		}
		return out
	case []any:
		out := make([]any, 0, len(t))
		for _, val := range t {
			out = append(out, normalize(val, key, origin))
		}
		// Arrays whose order carries no meaning are sorted so an ordering
		// difference does not masquerade as a content difference. Ordered
		// arrays — a run list, most obviously — are left alone, because their
		// order is part of the value.
		if unorderedFields[key] {
			sortAny(out)
		}
		return out
	case string:
		return normalizeString(t, key, origin)
	default:
		return v
	}
}

// unorderedFields name arrays Chef does not define an order for. Anything not
// listed keeps its order and will report a difference if it varies, which is
// the safe default.
var unorderedFields = map[string]bool{
	"actors": true, "groups": true, "users": true, "clients": true,
	"containers": true, "recipes": true,
}

func normalizeString(s, key, origin string) string {
	if replacement, ok := volatileFields[key]; ok && replacement != "" {
		return replacement
	}
	if origin != "" {
		s = strings.ReplaceAll(s, origin, placeholderServer)
	}
	s = pemPattern.ReplaceAllString(s, placeholderKey)
	s = guidPattern.ReplaceAllString(s, placeholderGUID)
	return s
}

// sortAny orders a slice of decoded JSON values deterministically by their
// rendered form, which is enough to make set-like arrays comparable.
func sortAny(vals []any) {
	sort.Slice(vals, func(i, j int) bool {
		return fmt.Sprintf("%v", vals[i]) < fmt.Sprintf("%v", vals[j])
	})
}

// compare walks two normalized values and reports every disagreement, with a
// dotted path so a difference deep in a document is actionable.
func compare(step, path string, reference, candidate any) []Difference {
	switch ref := reference.(type) {
	case map[string]any:
		can, ok := candidate.(map[string]any)
		if !ok {
			return []Difference{{Step: step, Field: pathOr(path), Reference: typeName(reference), Candidate: typeName(candidate)}}
		}
		var diffs []Difference
		for _, key := range sortedKeys(ref, can) {
			refVal, inRef := ref[key]
			canVal, inCan := can[key]
			switch {
			case inRef && !inCan:
				diffs = append(diffs, Difference{Step: step, Field: join(path, key), Reference: refVal, Candidate: "<missing>"})
			case !inRef && inCan:
				diffs = append(diffs, Difference{Step: step, Field: join(path, key), Reference: "<missing>", Candidate: canVal})
			default:
				diffs = append(diffs, compare(step, join(path, key), refVal, canVal)...)
			}
		}
		return diffs

	case []any:
		can, ok := candidate.([]any)
		if !ok {
			return []Difference{{Step: step, Field: pathOr(path), Reference: typeName(reference), Candidate: typeName(candidate)}}
		}
		if len(ref) != len(can) {
			return []Difference{{Step: step, Field: pathOr(path) + ".length", Reference: len(ref), Candidate: len(can)}}
		}
		var diffs []Difference
		for i := range ref {
			diffs = append(diffs, compare(step, fmt.Sprintf("%s[%d]", pathOr(path), i), ref[i], can[i])...)
		}
		return diffs

	default:
		if fmt.Sprintf("%v", reference) != fmt.Sprintf("%v", candidate) {
			return []Difference{{Step: step, Field: pathOr(path), Reference: reference, Candidate: candidate}}
		}
		return nil
	}
}

func sortedKeys(a, b map[string]any) []string {
	seen := map[string]bool{}
	var keys []string
	for k := range a {
		if !seen[k] {
			seen[k], keys = true, append(keys, k)
		}
	}
	for k := range b {
		if !seen[k] {
			seen[k], keys = true, append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

func pathOr(path string) string {
	if path == "" {
		return "(body)"
	}
	return path
}

func typeName(v any) string {
	switch v.(type) {
	case map[string]any:
		return "<object>"
	case []any:
		return "<array>"
	case nil:
		return "<null>"
	case string:
		return "<string>"
	default:
		return fmt.Sprintf("%T", v)
	}
}
