package api

import (
	"context"
	"net/http"

	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// Handing the authorization layer's read forward to the handler.
//
// Under enforcement, authorize checks that the target object exists before
// deciding permission, so that a missing object reports 404 rather than leaking
// 403 to an actor that also lacks access. For a read request the handler then
// wants exactly those bytes, so the naive arrangement reads the same row twice.
//
// That matters more than it looks: on a durable backend every read is a round
// trip through the driver, and the fleet check-in path is read-dominated
// already, so the duplicate is a meaningful share of the request's cost.
// authorize stashes what it read, and the read handlers take it from there.

// Distinct from actorContextKey, which is the zero value of ctxKey.
const prereadContextKey ctxKey = 1

// preread is an object the authorization layer already fetched for this
// request. It records what it identifies so a handler can only consume it for
// the exact object it names.
type preread struct {
	org, coll, key string
	raw            []byte
}

// withPreread returns a request carrying an object authorize has read.
func withPreread(r *http.Request, org, coll, key string, raw []byte) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), prereadContextKey,
		preread{org: org, coll: coll, key: key, raw: raw}))
}

// prereadFrom returns the object the authorization layer read for this request,
// if it is the one being asked for. The org is part of the match so a global
// handler can never consume an org-scoped read, or the reverse.
func prereadFrom(r *http.Request, org, coll, key string) ([]byte, bool) {
	p, ok := r.Context().Value(prereadContextKey).(preread)
	if !ok || p.org != org || p.coll != coll || p.key != key {
		return nil, false
	}
	return p.raw, true
}

// viewObject reads coll/key, reusing the bytes the authorization layer already
// fetched for this request when they are for the same object. The value is only
// ever stashed after a successful existence check, so a hit always means the
// object exists.
func viewObject(r *http.Request, org *store.Org, coll, key string) ([]byte, bool, error) {
	if raw, ok := prereadFrom(r, org.Name(), coll, key); ok {
		return raw, true, nil
	}
	return org.View(coll, key)
}
