package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// Renaming through PUT.
//
// erchef renames a client, user or group when an update's body names another
// object than the path (oc_chef_wm_base:update_from_json, handle_rename): the
// row's name changes, the reply is a 201 with a Location for the new name, and
// the old name is gone. Everything else refers to the object by its authz id
// (ACL entries, group membership) or by its row id (keys, org associations,
// invitations), so all of it follows the object.
//
// Here those references are by name, so a rename rewrites each of them from
// the old name to the new one: the object's own ACL, every ACL entry and group
// membership (document and rows) naming it, and, for a user, its keys,
// password, server-admins membership, org associations and invitations. Left
// behind, they would be grants waiting for the next object created under the
// old name. It all happens in one store transaction, under the exclusive
// membership lock a revocation takes (see groupmembers.go).
//
// erchef keeps a renamed client's keys only in principle: a client created at
// API v1 has no public_key column, and the clients update trigger
// (keys_update_trigger) deletes the "default" key of any client row updated
// with none. So a renamed client loses its default key unless the update
// itself carries one (an API v0 public_key or private_key: true). Its other
// keys move with it.

// renamedLocation answers a rename as webmachine does when update_from_json
// sets a Location: 201, with the new object's URL.
func renamedLocation(w http.ResponseWriter, url string) int {
	w.Header().Set("Location", url)
	return http.StatusCreated
}

// txScope returns the transaction's handle on the space named like scope: the
// global space for "", otherwise the organization.
func txScope(tx *store.Store, scope *store.Org) (*store.Org, error) {
	if scope.Name() == "" {
		return tx.Global(), nil
	}
	org, ok, err := tx.Org(scope.Name())
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("organization " + scope.Name() + " disappeared")
	}
	return org, nil
}

// moveKey moves one stored document from oldKey to newKey in coll, replacing
// whatever is at newKey. It does nothing when there is nothing at oldKey.
func moveKey(org *store.Org, coll, oldKey, newKey string) error {
	raw, ok, err := org.Get(coll, oldKey)
	if err != nil || !ok {
		return err
	}
	if err := org.Put(coll, newKey, raw); err != nil {
		return err
	}
	_, _, err = org.Delete(coll, oldKey)
	return err
}

// moveACL moves an object's stored ACL to its new name. Without one, the
// renamed object falls back as the old one did, and a stale ACL under the new
// name (there should be none) is dropped so it cannot take effect.
func moveACL(org *store.Org, typ, oldName, newName string) error {
	if _, ok, err := org.Get("acls", aclKey(typ, oldName)); err != nil {
		return err
	} else if !ok {
		return deleteACL(org, typ, newName)
	}
	return moveKey(org, "acls", aclKey(typ, oldName), aclKey(typ, newName))
}

// renameInACLs replaces oldName with newName in the actors or groups (kind) of
// every ACE of every ACL stored in org, as erchef's authz ids follow a renamed
// object. ACLs are collected during the scan and rewritten after it, since a
// Range callback must not write back into the store.
func renameInACLs(org *store.Org, kind, oldName, newName string) error {
	changed := map[string][]byte{}
	if err := org.Range("acls", func(key string, raw []byte) bool {
		var acl map[string]any
		if json.Unmarshal(raw, &acl) != nil {
			return true
		}
		var dirty bool
		for _, perm := range aclPerms {
			ace, ok := acl[perm].(map[string]any)
			if !ok {
				continue
			}
			if names, renamed := renamedIn(anyStrings(ace[kind]), oldName, newName); renamed {
				ace[kind] = names
				dirty = true
			}
		}
		if dirty {
			changed[key] = mustEncode(acl)
		}
		return true
	}); err != nil {
		return err
	}
	for key, raw := range changed {
		if err := org.Put("acls", key, raw); err != nil {
			return err
		}
	}
	return nil
}

// renamedIn returns names with oldName replaced by newName, in its place, or
// dropped when newName is already there, and whether oldName was there.
func renamedIn(names []string, oldName, newName string) ([]string, bool) {
	if !slices.Contains(names, oldName) {
		return names, false
	}
	has := slices.Contains(names, newName)
	out := make([]string, 0, len(names))
	for _, n := range names {
		if n == oldName {
			if has {
				continue
			}
			n, has = newName, true
		}
		out = append(out, n)
	}
	return out, true
}

// renameInGroups renames a member of kind in every group of org: both halves
// of membership, the group documents and the incremental rows (see
// groupMembership).
func renameInGroups(org *store.Org, kind, oldName, newName string) error {
	suffix := "\x00" + kind + "\x00" + oldName
	var groups []string
	if err := org.Range(groupMembersColl, func(key string, _ []byte) bool {
		if strings.HasSuffix(key, suffix) {
			groups = append(groups, strings.TrimSuffix(key, suffix))
		}
		return true
	}); err != nil {
		return err
	}
	for _, g := range groups {
		if _, _, err := org.Delete(groupMembersColl, memberKey(g, kind, oldName)); err != nil {
			return err
		}
		if err := addMember(org, g, kind, newName); err != nil {
			return err
		}
	}
	names, err := org.Keys("groups")
	if err != nil {
		return err
	}
	for _, name := range names {
		raw, ok, err := org.Get("groups", name)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		var g map[string]any
		if json.Unmarshal(raw, &g) != nil {
			continue
		}
		users, clients, groups := groupMembers(g)
		var changed bool
		switch kind {
		case memberUsers:
			users, changed = renamedIn(users, oldName, newName)
		case memberClients:
			clients, changed = renamedIn(clients, oldName, newName)
		case memberGroups:
			groups, changed = renamedIn(groups, oldName, newName)
		}
		if !changed {
			continue
		}
		if err := org.Put("groups", name, groupJSON(name, "", users, clients, groups)); err != nil {
			return err
		}
	}
	return nil
}

// renameInviter rewrites the inviter recorded on org's pending invitations
// (see createInvite), so an invitation a renamed actor issued is still judged
// by that actor's authority, and not by whoever is later created under its
// old name.
func renameInviter(org *store.Org, client bool, oldName, newName string) error {
	changed := map[string][]byte{}
	if err := org.Range(assocReqColl, func(key string, raw []byte) bool {
		var inv map[string]any
		if json.Unmarshal(raw, &inv) != nil {
			return true
		}
		isClient, _ := inv["inviter_client"].(bool)
		if inv["inviter"] == oldName && isClient == client {
			inv["inviter"] = newName
			changed[key] = mustEncode(inv)
		}
		return true
	}); err != nil {
		return err
	}
	for key, raw := range changed {
		if err := org.Put(assocReqColl, key, raw); err != nil {
			return err
		}
	}
	return nil
}

// moveActorKeys moves an actor's stored keys to its new name. dropDefault
// leaves the "default" key behind to be deleted, as a renamed client's is.
//
// Keys authenticate by actor name, so none may stay under the old name (a
// later actor of that name would inherit it) and none may already wait under
// the new one (the renamed actor would gain it): rows left at either name by
// anything else are deleted.
func moveActorKeys(org *store.Org, segment, oldName, newName string, dropDefault bool) error {
	from, to := keysColl(segment, oldName), keysColl(segment, newName)
	if err := deleteActorKeys(org, segment, newName); err != nil {
		return err
	}
	names, err := org.Keys(from)
	if err != nil {
		return err
	}
	for _, kn := range names {
		if dropDefault && kn == defaultKeyName {
			continue
		}
		raw, ok, err := org.Get(from, kn)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		if err := org.Put(to, kn, raw); err != nil {
			return err
		}
	}
	return deleteActorKeys(org, segment, oldName)
}

// renameClient moves client oldName of org to newName, storing doc as its
// record. It returns store.ErrConflict when newName is taken.
func (a *API) renameClient(r *http.Request, scope *store.Org, oldName, newName string, doc []byte) error {
	return a.store.Tx(func(tx *store.Store) error {
		org, err := txScope(tx, scope)
		if err != nil {
			return err
		}
		if err := org.As(actorID(r)).Create("clients", newName, doc); err != nil {
			return err
		}
		if _, _, err := org.Delete("clients", oldName); err != nil {
			return err
		}
		for _, step := range []func() error{
			func() error { return moveACL(org, "clients", oldName, newName) },
			func() error { return renameInACLs(org, memberClients, oldName, newName) },
			func() error { return renameInGroups(org, memberClients, oldName, newName) },
			func() error { return renameInviter(org, true, oldName, newName) },
			func() error { return moveActorKeys(org, "clients", oldName, newName, true) },
		} {
			if err := step(); err != nil {
				return err
			}
		}
		return nil
	})
}

// renameUser moves global user oldName to newName, storing doc as its record
// and, when set, password as its password: across the global space and every
// organization. It returns store.ErrConflict when newName is taken.
func (a *API) renameUser(r *http.Request, oldName, newName string, doc []byte, obj map[string]any) error {
	return a.store.Tx(func(tx *store.Store) error {
		global := tx.Global()
		if err := global.As(actorID(r)).Create("users", newName, doc); err != nil {
			return err
		}
		if _, _, err := global.Delete("users", oldName); err != nil {
			return err
		}
		for _, step := range []func() error{
			func() error { return moveACL(global, "users", oldName, newName) },
			func() error { return renameInACLs(global, memberUsers, oldName, newName) },
			func() error { return moveKey(global, PasswordsCollection, oldName, newName) },
			func() error { return moveKey(global, serverAdminsColl, oldName, newName) },
			func() error { return moveActorKeys(global, "users", oldName, newName, false) },
		} {
			if err := step(); err != nil {
				return err
			}
		}
		if _, err := StashPassword(global, newName, obj); err != nil {
			return err
		}
		orgs, err := tx.ListOrgs()
		if err != nil {
			return err
		}
		for _, name := range orgs {
			org, ok, err := tx.Org(name)
			if err != nil {
				return err
			}
			if !ok {
				continue
			}
			if err := renameUserInOrg(org, oldName, newName); err != nil {
				return err
			}
		}
		return nil
	})
}

// renameUserInOrg rewrites one organization's references to a renamed user:
// its association, its pending invitation, the invitations it issued, its
// group memberships and its ACL entries.
func renameUserInOrg(org *store.Org, oldName, newName string) error {
	if _, ok, err := org.Get(assocColl, oldName); err != nil {
		return err
	} else if ok {
		if err := org.Put(assocColl, newName, mustEncode(map[string]any{"username": newName})); err != nil {
			return err
		}
		if _, _, err := org.Delete(assocColl, oldName); err != nil {
			return err
		}
	}
	oldID, newID := inviteID(oldName, org.Name()), inviteID(newName, org.Name())
	if raw, ok, err := org.Get(assocReqColl, oldID); err != nil {
		return err
	} else if ok {
		var inv map[string]any
		if err := json.Unmarshal(raw, &inv); err != nil {
			return err
		}
		inv["id"], inv["username"] = newID, newName
		if err := org.Put(assocReqColl, newID, mustEncode(inv)); err != nil {
			return err
		}
		if _, _, err := org.Delete(assocReqColl, oldID); err != nil {
			return err
		}
	}
	if err := renameInviter(org, false, oldName, newName); err != nil {
		return err
	}
	if err := renameInGroups(org, memberUsers, oldName, newName); err != nil {
		return err
	}
	return renameInACLs(org, memberUsers, oldName, newName)
}

// renameGroup moves group oldName of org to newName, with doc (holding its
// whole membership) as its record. It returns store.ErrConflict when newName
// is taken.
func (a *API) renameGroup(r *http.Request, scope *store.Org, oldName, newName string, doc []byte) error {
	return a.store.Tx(func(tx *store.Store) error {
		org, err := txScope(tx, scope)
		if err != nil {
			return err
		}
		if err := org.As(actorID(r)).Create("groups", newName, doc); err != nil {
			return err
		}
		for _, step := range []func() error{
			func() error { _, _, err := org.Delete("groups", oldName); return err },
			// The new document records the whole membership.
			func() error { return clearMembers(org, oldName) },
			func() error { return clearMembers(org, newName) },
			func() error { return moveACL(org, "groups", oldName, newName) },
			func() error { return renameInACLs(org, memberGroups, oldName, newName) },
			func() error { return renameInGroups(org, memberGroups, oldName, newName) },
		} {
			if err := step(); err != nil {
				return err
			}
		}
		return nil
	})
}
