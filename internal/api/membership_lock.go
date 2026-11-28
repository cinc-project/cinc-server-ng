package api

import "sync"

// membershipLock orders membership changes against revocations (see
// groupmembers.go), scoped so that one organization's holders do not wait on
// another's.
//
// A group, its membership rows, and the clients and associations they name all
// belong to one org, so a group write or a client delete in one org has
// nothing to order against in another. Only the global space spans orgs:
// deleting or renaming a user rewrites its membership in every org. So there
// are two levels. Every org-scoped holder takes the global lock shared and its
// org's lock in the mode it needs; a global holder takes the global lock in
// its mode and no org lock. An exclusive global holder therefore excludes
// everyone, and an exclusive org holder excludes only that org's holders and
// exclusive global ones. The global lock is always taken first.
//
// The scope is an org name, or "" for the global space (store.Org.Name of the
// handle the holder writes through).
type membershipLock struct {
	global sync.RWMutex
	mu     sync.Mutex // guards orgs
	orgs   map[string]*sync.RWMutex
}

// org returns name's lock. An org's lock is never dropped, so every holder for
// an org name shares one, including across deleting and re-creating the org.
func (m *membershipLock) org(name string) *sync.RWMutex {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.orgs == nil {
		m.orgs = map[string]*sync.RWMutex{}
	}
	l, ok := m.orgs[name]
	if !ok {
		l = &sync.RWMutex{}
		m.orgs[name] = l
	}
	return l
}

// Lock takes scope exclusively and returns the function that releases it.
func (m *membershipLock) Lock(scope string) (unlock func()) {
	if scope == "" {
		m.global.Lock()
		return m.global.Unlock
	}
	m.global.RLock()
	l := m.org(scope)
	l.Lock()
	return func() {
		l.Unlock()
		m.global.RUnlock()
	}
}

// RLock takes scope shared and returns the function that releases it.
func (m *membershipLock) RLock(scope string) (unlock func()) {
	m.global.RLock()
	if scope == "" {
		return m.global.RUnlock
	}
	unlockOrg := m.RLockOrg(scope)
	return func() {
		unlockOrg()
		m.global.RUnlock()
	}
}

// RLockOrg takes org's lock shared, for a holder that already holds
// RLock("") and learns which org it acts in only under it.
func (m *membershipLock) RLockOrg(org string) (unlock func()) {
	l := m.org(org)
	l.RLock()
	return l.RUnlock
}
