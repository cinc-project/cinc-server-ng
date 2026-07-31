package api

import "encoding/json"

// Typed decoders for the two authorization documents the enforcement path reads
// in bulk: group membership and an object's ACL.
//
// Both have a fixed, server-written shape, but decoding them into
// map[string]any — as the generic object path does — boxes every value and
// builds a map per document. On a search that scans a collection, or on any
// request whose ACL grants through a group, that dominates the work: profiling
// a 512-node fleet search attributed 94% of all allocations to re-parsing ACL
// documents this way.
//
// Decoding into a fixed struct instead lets encoding/json skip the fields we do
// not read and allocate only the slices we do. Callers keep the tolerant
// map-based path as a fallback, so a document with an unexpected shape (a
// hand-written state file, say) still behaves exactly as before rather than
// being dropped.

// memberDoc is the membership of a group document.
type memberDoc struct {
	Users   []string `json:"users"`
	Clients []string `json:"clients"`
	Groups  []string `json:"groups"`
}

// decodeMembers decodes a group document's membership. ok is false when the
// document does not fit the expected shape, which tells the caller to fall back
// to the tolerant decode rather than treat the group as empty.
func decodeMembers(raw []byte) (memberDoc, bool) {
	var m memberDoc
	if json.Unmarshal(raw, &m) != nil {
		return memberDoc{}, false
	}
	return m, true
}

// aceDoc is a single access-control entry: the actors and groups a permission
// is granted to.
type aceDoc struct {
	Actors []string `json:"actors"`
	Groups []string `json:"groups"`
}

// allows reports whether the entry grants an actor with the given group
// memberships. It mirrors aceAllows, over the typed decode.
func (e aceDoc) allows(name string, member map[string]bool) bool {
	for _, a := range e.Actors {
		if a == name {
			return true
		}
	}
	for _, g := range e.Groups {
		if member[g] {
			return true
		}
	}
	return false
}

// readACEDoc is an ACL document narrowed to the one permission the search
// filter evaluates.
type readACEDoc struct {
	Read aceDoc `json:"read"`
}

// decodeReadACE decodes just the read entry of an ACL document. ok is false
// when the document does not fit the expected shape.
func decodeReadACE(raw []byte) (aceDoc, bool) {
	var doc readACEDoc
	if json.Unmarshal(raw, &doc) != nil {
		return aceDoc{}, false
	}
	return doc.Read, true
}
