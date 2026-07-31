package api

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/tas50/cinc-zero/internal/store"
)

// Membership as rows.
//
// A group document carries its whole membership, so adding one member rewrites
// a document containing every existing member. During a fleet bootstrap each
// registration joins the org's "clients" group, which makes standing up N nodes
// cost O(N²) — 8000 nodes spent 17 seconds doing nothing but rewriting that one
// document, and it gets worse from there.
//
// Incremental membership is therefore written as one row per member, which
// costs the same whether the group has ten members or a hundred thousand. The
// group document remains the representation the API reads and writes, and an
// explicit write of a group is still authoritative: it replaces the document
// and clears the rows. Effective membership is the union of the two, so data
// written either way — including a hand-authored state directory — behaves the
// same.

// groupMembersColl holds incremental membership, one key per (group, kind,
// actor).
const groupMembersColl = "group_members"

// Membership kinds, matching the group document's member arrays.
const (
	memberUsers   = "users"
	memberClients = "clients"
	memberGroups  = "groups"
)

// memberKey identifies one membership row. The separator cannot appear in a
// Chef actor or group name, so the parts are unambiguous.
func memberKey(group, kind, actor string) string {
	return group + "\x00" + kind + "\x00" + actor
}

// splitMemberKey reverses memberKey.
func splitMemberKey(key string) (group, kind, actor string, ok bool) {
	parts := strings.Split(key, "\x00")
	if len(parts) != 3 {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

// addMember records one membership row. It is a single write regardless of how
// large the group already is, which is the whole point.
func addMember(org *store.Org, group, kind, actor string) error {
	return org.Put(groupMembersColl, memberKey(group, kind, actor), []byte(`{}`))
}

// clearMembers drops every membership row for a group, used when an explicit
// write of the group replaces its membership wholesale.
func clearMembers(org *store.Org, group string) error {
	prefix := group + "\x00"
	var keys []string
	if err := org.Range(groupMembersColl, func(key string, _ []byte) bool {
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
		return true
	}); err != nil {
		return err
	}
	for _, key := range keys {
		if _, _, err := org.Delete(groupMembersColl, key); err != nil {
			return err
		}
	}
	return nil
}

// groupMembership returns a group's effective membership: what its document
// records, plus any rows added incrementally since.
func groupMembership(org *store.Org, group string) (users, clients, groups []string, err error) {
	raw, ok, err := org.Get("groups", group)
	if err != nil {
		return nil, nil, nil, err
	}
	if ok {
		var g map[string]any
		if json.Unmarshal(raw, &g) == nil {
			users, clients, groups = groupMembers(g)
		}
	}
	prefix := group + "\x00"
	err = org.Range(groupMembersColl, func(key string, _ []byte) bool {
		if !strings.HasPrefix(key, prefix) {
			return true
		}
		_, kind, actor, ok := splitMemberKey(key)
		if !ok {
			return true
		}
		switch kind {
		case memberUsers:
			if !slices.Contains(users, actor) {
				users = append(users, actor)
			}
		case memberClients:
			if !slices.Contains(clients, actor) {
				clients = append(clients, actor)
			}
		case memberGroups:
			if !slices.Contains(groups, actor) {
				groups = append(groups, actor)
			}
		}
		return true
	})
	if err != nil {
		return nil, nil, nil, err
	}
	return users, clients, groups, nil
}

// groupDocWithMembers renders a group in its API shape, with the rows folded in.
func groupDocWithMembers(org *store.Org, name string) ([]byte, bool, error) {
	_, hasDoc, err := org.Get("groups", name)
	if err != nil {
		return nil, false, err
	}
	users, clients, groups, err := groupMembership(org, name)
	if err != nil {
		return nil, false, err
	}
	// A group exists if it has a document or any membership: joining a group
	// that was never explicitly created is how association has always behaved.
	if !hasDoc && len(users)+len(clients)+len(groups) == 0 {
		return nil, false, nil
	}
	return mustEncode(groupDoc(name, users, clients, groups)), true, nil
}

// GroupMembership reports a group's effective membership — its document plus
// any rows added incrementally. Callers outside this package (the state loader
// and its tests) need it because membership is no longer readable from the
// stored group document alone.
func GroupMembership(org *store.Org, group string) (users, clients, groups []string, err error) {
	return groupMembership(org, group)
}
