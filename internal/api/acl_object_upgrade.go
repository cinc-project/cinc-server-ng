package api

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"

	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// UpgradeObjectACLs stores, for every object in org, the ACL erchef would have
// created it with, where what is stored is not that:
//
//   - An object with no stored ACL gets its container's ACL as stored now and,
//     for a client, the client itself (writeContainerACL). Versions before
//     this wrote no ACL for data bags, cookbooks, cookbook artifacts,
//     policies, policy groups or groups, and nothing writes one for an object
//     loaded from a chef-repo or state directory, or created while ACLs were
//     not enforced. Without one each reported the object default, which gives
//     every org member update. There is no creator to add: none was recorded.
//     The default groups keep erchef's org policy (fallbackACL).
//   - A client whose stored ACL is still what versions before 0.21.1 wrote for
//     every new client (isLegacyClientACL) is rewritten as a client created
//     now would be: the clients container's ACL, its creator, and itself. That
//     old ACL gave the users group update on the client, which is what
//     authorizes adding a key to it.
//
// It must run after UpgradeACLActors (it reads typed entries) and after a
// chef-repo or state directory is loaded. It is idempotent, and on an org with
// nothing to change it reads each collection once and writes nothing.
func UpgradeObjectACLs(org *store.Org) error {
	// Which objects have an ACL, and the clients' ACLs themselves.
	has := map[string]bool{}
	clientACLs := map[string][]byte{}
	if err := org.Range("acls", func(key string, raw []byte) bool {
		has[key] = true
		if strings.HasPrefix(key, "clients/") {
			clientACLs[key] = bytes.Clone(raw)
		}
		return true
	}); err != nil {
		return err
	}
	for _, typ := range aclObjectTypes {
		if typ == "containers" {
			continue // a container's ACL is its creator's, who is not recorded
		}
		names, err := objectNames(org, typ)
		if err != nil {
			return err
		}
		for _, name := range names {
			if typ == "groups" && slices.Contains(defaultGroups, name) {
				continue
			}
			key := aclKey(typ, name)
			switch {
			case !has[key]:
				err = writeContainerACL(org, typ, name)
			case typ == "clients":
				if creator, legacy := isLegacyClientACL(clientACLs[key]); legacy {
					err = rewriteLegacyClientACL(org, name, creator)
				}
			}
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// objectNames lists the names of the objects of an ACL type in org.
func objectNames(org *store.Org, typ string) ([]string, error) {
	switch typ {
	case "data":
		return org.Keys(dataBagsColl)
	case "cookbooks", "cookbook_artifacts":
		keys, err := org.Keys(typ)
		if err != nil {
			return nil, err
		}
		var names []string
		for _, k := range keys {
			if name, _, ok := strings.Cut(k, "/"); ok && !slices.Contains(names, name) {
				names = append(names, name)
			}
		}
		return names, nil
	case "policies":
		all, err := policyNames(org)
		if err != nil {
			return nil, err
		}
		var names []string
		for _, name := range all {
			if ok, err := aclObjectExists(org, "policies", name); err != nil {
				return nil, err
			} else if ok {
				names = append(names, name)
			}
		}
		return names, nil
	}
	return org.Keys(typ)
}

// isLegacyClientACL reports whether a client's stored ACL is the one versions
// before 0.21.1 wrote for every new client, which no admin has changed since:
// defaultACL() plus its creator in all five permissions. It returns the
// creator, or a zero Actor when the ACL names none.
//
// The test is exact, so an ACL an admin has edited is left alone:
//
//   - The ACL has exactly the five permissions, and each entry exactly the
//     typed users, clients and groups lists (an untyped "actors" list is
//     UpgradeACLActors's to convert).
//   - Each permission's groups are defaultACL()'s for it, as a set. Every
//     edit through the _acl endpoints rewrites one permission, so adding or
//     removing a group anywhere breaks the match.
//   - Every permission names the same actors, and they are at most one name,
//     the creator. Adding an actor to, or removing the creator from, any
//     permission but not all of them breaks the match. No actor at all is
//     accepted too: that is what is left once the validator is taken out of
//     the ACL of a client it registered.
//
// The shape a client gets now (its container's ACL) never matches: the
// clients container gives no group update and the clients group no read.
// What does match is either the untouched legacy ACL or one an admin has set,
// permission by permission, back to exactly it, which grants the same.
func isLegacyClientACL(raw []byte) (Actor, bool) {
	var acl map[string]map[string][]string
	if json.Unmarshal(raw, &acl) != nil || len(acl) != len(aclPerms) {
		return Actor{}, false
	}
	def := defaultACL()
	var first map[string][]string
	for _, perm := range aclPerms {
		ace, ok := acl[perm]
		if !ok || len(ace) != 3 {
			return Actor{}, false
		}
		for _, kind := range []string{"users", "clients", "groups"} {
			if _, ok := ace[kind]; !ok {
				return Actor{}, false
			}
		}
		want := def[perm].(map[string]any)["groups"].([]string)
		if !sameSet(ace["groups"], want) {
			return Actor{}, false
		}
		if first == nil {
			first = ace
			if len(ace["users"])+len(ace["clients"]) > 1 {
				return Actor{}, false
			}
			continue
		}
		if !slices.Equal(ace["users"], first["users"]) || !slices.Equal(ace["clients"], first["clients"]) {
			return Actor{}, false
		}
	}
	switch {
	case len(first["users"]) == 1:
		return Actor{Name: first["users"][0]}, true
	case len(first["clients"]) == 1:
		return Actor{Name: first["clients"][0], IsClient: true}, true
	}
	return Actor{}, true
}

// sameSet reports whether a and b hold the same names, ignoring order and
// repeats.
func sameSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(slices.Compact(a), slices.Compact(b))
}

// rewriteLegacyClientACL gives a client the ACL it would be created with now,
// keeping the creator its legacy ACL names, if any.
func rewriteLegacyClientACL(org *store.Org, name string, creator Actor) error {
	if creator.Name == "" {
		return writeContainerACL(org, "clients", name)
	}
	return writeCreatorACL(org, "clients", name, creator)
}
