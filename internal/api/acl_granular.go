package api

import (
	"net/http"
	"slices"
	"strings"

	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// An ACL here stores actors by bare name, as one merged list: that is what
// every permission check reads. erchef also keeps one merged list (bifrost
// holds actor ids), but can tell a user from a client by id, so it offers two
// views of it, both mirrored here:
//
//   - GET _acl?detail=granular reports each permission with actors [] and the
//     names split into users and clients (oc_chef_authz_acl part_with_actors).
//   - PUT _acl/<perm> takes {"actors":[],"users":[...],"clients":[...]} as
//     well as the merged form (oc_chef_authz_acl validate_actors_clients_users,
//     names_to_ids).
//
// erchef also answers a merged-form PUT with 422 (ambiguous_actor) when a name
// is both a client and a member user of the org. That state cannot arise here:
// actorNameCollision refuses it at creation, because a name is the principal.
// A store that holds such a pair from before that guard grants the name as
// both, and the granular view lists it under both.

// wantsGranular is erchef's test: detail=granular exactly, anything else is
// the merged form.
func wantsGranular(r *http.Request) bool {
	return r.URL.Query().Get("detail") == "granular"
}

// granularACL splits each permission's actors into users (global users) and
// clients (clients of members, nil for a global user's ACL). A stored name that
// resolves to neither is left out: erchef can only report ids that still
// resolve.
func (a *API) granularACL(members *store.Org, acl map[string]any) (map[string]any, error) {
	out := make(map[string]any, len(aclPerms))
	for _, perm := range aclPerms {
		ace, _ := acl[perm].(map[string]any)
		users, clients := []string{}, []string{}
		for _, name := range jsonStrings(ace["actors"]) {
			isUser, isClient, err := a.actorKinds(members, name)
			if err != nil {
				return nil, err
			}
			if isClient {
				clients = append(clients, name)
			}
			if isUser {
				users = append(users, name)
			}
		}
		groups := jsonStrings(ace["groups"])
		if groups == nil {
			groups = []string{}
		}
		out[perm] = map[string]any{"actors": []string{}, "groups": groups, "users": users, "clients": clients}
	}
	return out, nil
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

// mergeSplitACE resolves a split-form ACE and returns it in the stored, merged
// form: actors are its users then its clients, as erchef's names_to_ids orders
// them. Users resolve as global users and clients as clients of members; a
// global user's ACL (nil members) takes no clients. A non-empty msg is the
// 400 to answer with, for the first list that fails, users before clients.
func (a *API) mergeSplitACE(members *store.Org, ace map[string]any) (merged map[string]any, msg string, err error) {
	users, clients := jsonStrings(ace["users"]), jsonStrings(ace["clients"])
	var missing []string
	for _, name := range users {
		isUser, _, err := a.actorKinds(nil, name)
		if err != nil {
			return nil, "", err
		}
		if !isUser {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		switch {
		case members != nil:
			return nil, "The user(s) " + strings.Join(missing, ", ") + " do not exist in this organization.", nil
		case len(missing) == 1:
			return nil, "The user " + missing[0] + " does not exist.", nil
		default:
			return nil, "The users " + strings.Join(missing, ", ") + " do not exist.", nil
		}
	}
	if len(clients) > 0 && members == nil {
		return nil, "Clients can not be added to global ACL entries.", nil
	}
	for _, name := range clients {
		_, isClient, err := a.actorKinds(members, name)
		if err != nil {
			return nil, "", err
		}
		if !isClient {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return nil, "The client(s) " + strings.Join(missing, ", ") + " do not exist in this organization.", nil
	}

	actors := []string{}
	for _, name := range slices.Concat(users, clients) {
		if !slices.Contains(actors, name) {
			actors = append(actors, name)
		}
	}
	merged = make(map[string]any, len(ace))
	for k, v := range ace {
		if k != "users" && k != "clients" {
			merged[k] = v
		}
	}
	merged["actors"] = actors
	return merged, "", nil
}
