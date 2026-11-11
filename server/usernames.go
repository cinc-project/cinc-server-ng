package server

import (
	"sync"

	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// userNames is the set of global user names, kept current from the store's
// write stream. Authentication uses it for one thing: to skip looking up a
// user when a client of the request's name exists and no user shares it,
// which is the fleet's hot path (a node signs as its client). Every other
// case still reads the user record, so the set never decides that a user is
// absent where that would lock the user out.
type userNames struct {
	mu    sync.RWMutex
	names map[string]struct{}
}

// newUserNames builds the set from st and keeps it current. It must be called
// before st serves writes from anyone else: the observer and the initial
// listing are not serialized against a concurrent write.
func newUserNames(st *store.Store) (*userNames, error) {
	u := &userNames{names: map[string]struct{}{}}
	st.Watch(u.observe)
	names, err := st.Global().Keys("users")
	if err != nil {
		return nil, err
	}
	for _, n := range names {
		u.names[n] = struct{}{}
	}
	return u, nil
}

// observe is a store.Watch observer: it runs on the writing goroutine, so it
// only updates the map.
func (u *userNames) observe(ev store.Event) {
	if ev.Org != "" || ev.Collection != "users" {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if ev.Deleted {
		delete(u.names, ev.Key)
	} else {
		u.names[ev.Key] = struct{}{}
	}
}

func (u *userNames) has(name string) bool {
	u.mu.RLock()
	defer u.mu.RUnlock()
	_, ok := u.names[name]
	return ok
}
