package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"slices"
	"strings"

	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// An org client and a global user may share a name, as on Chef Infra Server,
// so an ACL entry stores its actors typed: {"users":[...], "clients":[...],
// "groups":[...]}. A user grant never matches a client of the same name, nor
// the reverse; erchef gets the same from keying grants on authz ids.
//
// The API shows erchef's two views of an entry:
//
//   - by default, "actors" is the clients followed by the users (erchef's
//     convert_ids_to_names order), beside "groups";
//   - with ?detail=granular, "actors" is [] and the names are under "users"
//     and "clients" (oc_chef_authz_acl part_with_actors).
//
// A PUT takes either form (oc_chef_authz_acl validate_actors_clients_users,
// names_to_ids). In the merged form each name resolves to the user or the
// client it names; a name that is both a client and a member user of the org
// is ambiguous and refused with 422, as erchef refuses it.
//
// Stores written before this kept one untyped "actors" list. UpgradeACLActors
// converts it at startup; permission checks ignore an untyped "actors" list,
// so one that escaped conversion grants nothing rather than everything.

// aceMembers reads an ACL entry's typed members. Each is non-nil.
func aceMembers(ace map[string]any) (users, clients, groups []string) {
	users, clients, groups = anyStrings(ace["users"]), anyStrings(ace["clients"]), anyStrings(ace["groups"])
	if users == nil {
		users = []string{}
	}
	if clients == nil {
		clients = []string{}
	}
	if groups == nil {
		groups = []string{}
	}
	return users, clients, groups
}

// typedACE is an ACL entry in its stored form.
func typedACE(users, clients, groups []string) map[string]any {
	if users == nil {
		users = []string{}
	}
	if clients == nil {
		clients = []string{}
	}
	if groups == nil {
		groups = []string{}
	}
	return map[string]any{"users": users, "clients": clients, "groups": groups}
}

// aceNamesFor returns the entry's actor names of actor's type.
func aceNamesFor(ace map[string]any, actor Actor) []string {
	if actor.IsClient {
		return anyStrings(ace["clients"])
	}
	return anyStrings(ace["users"])
}

// mergedACE is the default API view of a stored entry.
func mergedACE(ace map[string]any) map[string]any {
	users, clients, groups := aceMembers(ace)
	return map[string]any{"actors": append(append([]string{}, clients...), users...), "groups": groups}
}

// granularACE is the ?detail=granular view of a stored entry.
func granularACE(ace map[string]any) map[string]any {
	users, clients, groups := aceMembers(ace)
	return map[string]any{"actors": []string{}, "groups": groups, "users": users, "clients": clients}
}

// aclView renders every permission of a stored ACL with view.
func aclView(acl map[string]any, view func(map[string]any) map[string]any) map[string]any {
	out := make(map[string]any, len(aclPerms))
	for _, perm := range aclPerms {
		ace, _ := acl[perm].(map[string]any)
		out[perm] = view(ace)
	}
	return out
}

// wantsGranular is erchef's test: detail=granular exactly, anything else is
// the merged form.
func wantsGranular(r *http.Request) bool {
	return r.URL.Query().Get("detail") == "granular"
}

// actorKinds reports whether name is a global user and whether it is a client
// of members (never, for a nil members).
func (a *API) actorKinds(members *store.Org, name string) (isUser, isClient bool, err error) {
	if _, isUser, err = a.store.Global().Get("users", name); err != nil {
		return false, false, err
	}
	if members != nil {
		if _, isClient, err = members.Get("clients", name); err != nil {
			return false, false, err
		}
	}
	return isUser, isClient, nil
}

// isSplitACE reports whether an ACE uses the users/clients form.
func isSplitACE(ace map[string]any) bool {
	_, users := ace["users"]
	_, clients := ace["clients"]
	return users || clients
}

// splitACEShapeError is validate_actors_clients_users: users and clients come
// together, and with them actors must be empty, so it is never unclear which
// list a request meant. It runs ahead of every other check, as erchef's
// malformed_request does.
func splitACEShapeError(ace map[string]any) string {
	_, hasUsers := ace["users"]
	_, hasClients := ace["clients"]
	switch {
	case hasClients && !hasUsers:
		return "You provided 'clients' with your request. Including this field also requires that you provide 'users'"
	case hasUsers && !hasClients:
		return "You provided 'users' with your request. Including this field also requires that you provide 'clients'"
	case hasUsers && hasClients && len(jsonStrings(ace["actors"])) > 0:
		return "When providing 'users' and 'clients' fields, the 'actors' field must have a value of []."
	}
	return ""
}

// aceRefusal is why a PUT's ACE cannot be stored: the status and messages to
// answer with.
type aceRefusal struct {
	status int
	msgs   []string
}

// resolveACE resolves a PUT's ACE, in either form, to its stored typed form.
// members is the org its names resolve in, or nil for a global user's ACL,
// whose actors are users only and whose groups are not checked. A non-nil
// refusal is the answer to give instead.
func (a *API) resolveACE(members *store.Org, ace map[string]any) (map[string]any, *aceRefusal, error) {
	var users, clients []string
	if isSplitACE(ace) {
		var msg string
		var err error
		users, clients, msg, err = a.splitMembers(members, ace)
		if err != nil {
			return nil, nil, err
		}
		if msg != "" {
			return nil, &aceRefusal{http.StatusBadRequest, []string{msg}}, nil
		}
	}

	var unknownActors, ambiguous []string
	if !isSplitACE(ace) {
		for _, name := range jsonStrings(ace["actors"]) {
			isUser, isClient, err := a.actorKinds(members, name)
			if err != nil {
				return nil, nil, err
			}
			switch {
			case isUser && isClient:
				// erchef's find_org_actors_by_name sees member users only: a
				// global user outside the org does not compete with the client.
				member, err := principalOrgMember(members, "user", name)
				if err != nil {
					return nil, nil, err
				}
				if member {
					ambiguous = append(ambiguous, name)
				} else {
					clients = append(clients, name)
				}
			case isClient:
				clients = append(clients, name)
			case isUser:
				users = append(users, name)
			default:
				unknownActors = append(unknownActors, name)
			}
		}
	}

	groups := jsonStrings(ace["groups"])
	var unknownGroups []string
	if members != nil {
		for _, name := range groups {
			_, ok, err := members.Get("groups", name)
			if err != nil {
				return nil, nil, err
			}
			if !ok {
				unknownGroups = append(unknownGroups, name)
			}
		}
	}
	if len(unknownActors) > 0 || len(unknownGroups) > 0 {
		var msgs []string
		if len(unknownActors) > 0 {
			msgs = append(msgs, "The actor(s) "+strings.Join(unknownActors, ", ")+" do not exist.")
		}
		if len(unknownGroups) > 0 {
			msgs = append(msgs, "The group(s) "+strings.Join(unknownGroups, ", ")+" do not exist in this organization.")
		}
		return nil, &aceRefusal{http.StatusBadRequest, msgs}, nil
	}
	if len(ambiguous) > 0 {
		slices.Sort(ambiguous)
		return nil, &aceRefusal{http.StatusUnprocessableEntity, []string{
			"The following actor(s) exist as both clients and users within this organization: " +
				strings.Join(slices.Compact(ambiguous), ", ") +
				". To perform this update, supply separate 'clients' and 'users' fields in your request," +
				" and use an empty array for the value of 'actors'."}}, nil
	}
	return typedACE(dedup(users), dedup(clients), groups), nil, nil
}

// splitMembers resolves a split-form ACE's users (as global users) and clients
// (as clients of members; a global user's ACL, nil members, takes none). A
// non-empty msg is the 400 to answer with, for the first list that fails,
// users before clients, as erchef's names_to_ids resolves them.
func (a *API) splitMembers(members *store.Org, ace map[string]any) (users, clients []string, msg string, err error) {
	users, clients = jsonStrings(ace["users"]), jsonStrings(ace["clients"])
	var missing []string
	for _, name := range users {
		isUser, _, err := a.actorKinds(nil, name)
		if err != nil {
			return nil, nil, "", err
		}
		if !isUser {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		switch {
		case members != nil:
			return nil, nil, "The user(s) " + strings.Join(missing, ", ") + " do not exist in this organization.", nil
		case len(missing) == 1:
			return nil, nil, "The user " + missing[0] + " does not exist.", nil
		default:
			return nil, nil, "The users " + strings.Join(missing, ", ") + " do not exist.", nil
		}
	}
	if len(clients) > 0 && members == nil {
		return nil, nil, "Clients can not be added to global ACL entries.", nil
	}
	for _, name := range clients {
		_, isClient, err := a.actorKinds(members, name)
		if err != nil {
			return nil, nil, "", err
		}
		if !isClient {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return nil, nil, "The client(s) " + strings.Join(missing, ", ") + " do not exist in this organization.", nil
	}
	return users, clients, "", nil
}

// dedup drops repeated names, keeping first occurrences in order.
func dedup(names []string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out
}

// UpgradeACLActors converts the ACLs a store from before typed entries holds
// in scope (an org, or the global space where users' own ACLs live, for a nil
// org) from one untyped "actors" list to typed users and clients. It must run
// at startup, before any request can create a client named like a user: each
// name is typed by what exists now, while that cannot yet be ambiguous for a
// reason the old store did not already share.
//
// A name that is a global user goes to users; one that is a client of org goes
// to clients. A name that is both (only a store from before the name guard
// could hold such a pair) was one principal to that version and keeps both
// grants. A name that is neither is dropped: it names nothing, and kept it
// would grant whatever is later created under it. It is idempotent: a
// converted ACL has no "actors" list left to convert.
func UpgradeACLActors(global, org *store.Org) error {
	scope := org
	if scope == nil {
		scope = global
	}
	legacy := map[string][]byte{}
	if err := scope.Range("acls", func(key string, raw []byte) bool {
		// The key, not the word: a group named "actors" is no legacy list.
		if bytes.Contains(raw, []byte(`"actors":`)) {
			legacy[key] = bytes.Clone(raw)
		}
		return true
	}); err != nil {
		return err
	}
	for key, raw := range legacy {
		var acl map[string]any
		if json.Unmarshal(raw, &acl) != nil {
			continue
		}
		for _, perm := range aclPerms {
			ace, ok := acl[perm].(map[string]any)
			if !ok {
				continue
			}
			users, clients, groups := aceMembers(ace)
			for _, name := range anyStrings(ace["actors"]) {
				if _, ok, err := global.Get("users", name); err != nil {
					return err
				} else if ok {
					users = append(users, name)
				}
				if org == nil {
					continue
				}
				if _, ok, err := org.Get("clients", name); err != nil {
					return err
				} else if ok {
					clients = append(clients, name)
				}
			}
			acl[perm] = typedACE(dedup(users), dedup(clients), groups)
		}
		if err := scope.Put("acls", key, mustEncode(acl)); err != nil {
			return err
		}
	}
	return nil
}
