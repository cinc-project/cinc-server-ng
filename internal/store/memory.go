package store

import (
	"maps"
	"sort"
	"sync"
)

// memoryBackend is the in-memory Backend: the default, ephemeral backend that
// keeps all state in maps. It lives in the store package (rather than a subpackage)
// so New can default to it without an import cycle, and it is the reference
// implementation the shared conformance suite is written against.
type memoryBackend struct {
	mu    sync.RWMutex
	orgs  map[string]bool                         // named orgs (for ListOrgs/HasOrg)
	data  map[string]map[string]map[string][]byte // org -> coll -> key -> body
	meta  map[string]map[string]map[string]Meta   // org -> coll -> key -> times and actor
	blobs map[string]map[string][]byte            // org -> checksum -> content
}

// NewMemoryBackend returns an empty in-memory Backend.
func NewMemoryBackend() Backend {
	return &memoryBackend{
		orgs:  map[string]bool{},
		data:  map[string]map[string]map[string][]byte{},
		meta:  map[string]map[string]map[string]Meta{},
		blobs: map[string]map[string][]byte{},
	}
}

func clone(b []byte) []byte {
	cp := make([]byte, len(b))
	copy(cp, b)
	return cp
}

func (m *memoryBackend) Get(org, coll, key string) ([]byte, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.data[org][coll][key]
	if !ok {
		return nil, false, nil
	}
	return clone(v), true, nil
}

// set stores a defensive copy of val and stamps its metadata: an existing key
// keeps its creation time. Caller holds the write lock.
func (m *memoryBackend) set(org, coll, key string, val []byte, st Stamp) {
	if m.data[org] == nil {
		m.data[org] = map[string]map[string][]byte{}
	}
	if m.data[org][coll] == nil {
		m.data[org][coll] = map[string][]byte{}
	}
	md := Meta{CreatedAt: st.At, UpdatedAt: st.At, UpdatedBy: st.By}
	if _, existed := m.data[org][coll][key]; existed {
		md.CreatedAt = m.meta[org][coll][key].CreatedAt
	}
	m.data[org][coll][key] = clone(val)
	m.putMeta(org, coll, key, md)
}

// putMeta records md for coll/key. Caller holds the write lock.
func (m *memoryBackend) putMeta(org, coll, key string, md Meta) {
	if m.meta[org] == nil {
		m.meta[org] = map[string]map[string]Meta{}
	}
	if m.meta[org][coll] == nil {
		m.meta[org][coll] = map[string]Meta{}
	}
	m.meta[org][coll][key] = md
}

func (m *memoryBackend) Put(org, coll, key string, val []byte, st Stamp) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.set(org, coll, key, val, st)
	return nil
}

func (m *memoryBackend) Create(org, coll, key string, val []byte, st Stamp) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.data[org][coll][key]; ok {
		return ErrConflict
	}
	m.set(org, coll, key, val, st)
	return nil
}

func (m *memoryBackend) Meta(org, coll, key string) (Meta, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if _, ok := m.data[org][coll][key]; !ok {
		return Meta{}, false, nil
	}
	return m.meta[org][coll][key], true, nil
}

func (m *memoryBackend) SetMeta(org, coll, key string, md Meta) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.data[org][coll][key]; !ok {
		return ErrNotFound
	}
	m.putMeta(org, coll, key, md)
	return nil
}

func (m *memoryBackend) Delete(org, coll, key string) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.data[org][coll][key]
	if !ok {
		return nil, false, nil
	}
	delete(m.data[org][coll], key)
	delete(m.meta[org][coll], key)
	return clone(v), true, nil
}

func (m *memoryBackend) Keys(org, coll string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	keys := make([]string, 0, len(m.data[org][coll]))
	for k := range m.data[org][coll] {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys, nil
}

func (m *memoryBackend) Range(org, coll string, fn func(key string, raw []byte) bool) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for k, v := range m.data[org][coll] {
		if !fn(k, v) {
			return nil
		}
	}
	return nil
}

func (m *memoryBackend) Collections(org string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	colls := make([]string, 0, len(m.data[org]))
	for c, keys := range m.data[org] {
		if len(keys) > 0 {
			colls = append(colls, c)
		}
	}
	sort.Strings(colls)
	return colls, nil
}

func (m *memoryBackend) PutBlob(org, checksum string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.blobs[org] == nil {
		m.blobs[org] = map[string][]byte{}
	}
	m.blobs[org][checksum] = clone(data)
	return nil
}

func (m *memoryBackend) Blob(org, checksum string) ([]byte, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.blobs[org][checksum]
	if !ok {
		return nil, false, nil
	}
	return clone(v), true, nil
}

func (m *memoryBackend) HasBlob(org, checksum string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.blobs[org][checksum]
	return ok, nil
}

func (m *memoryBackend) DeleteBlob(org, checksum string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.blobs[org], checksum)
	return nil
}

func (m *memoryBackend) CreateOrg(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.orgs[name] {
		return ErrConflict
	}
	m.orgs[name] = true
	return nil
}

func (m *memoryBackend) DeleteOrg(name string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.orgs[name] {
		return false, nil
	}
	delete(m.orgs, name)
	delete(m.data, name)
	delete(m.meta, name)
	delete(m.blobs, name)
	return true, nil
}

func (m *memoryBackend) ListOrgs() ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	names := make([]string, 0, len(m.orgs))
	for n := range m.orgs {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}

func (m *memoryBackend) HasOrg(name string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.orgs[name], nil
}

// Tx runs fn against this backend, taking a snapshot first and restoring it if fn
// returns an error, so the transaction's writes are discarded on rollback and kept
// on commit. The snapshot shares the immutable value slices (set always writes a
// fresh slice), so it is cheap. Rollback is not isolated against other goroutines
// writing concurrently during the transaction — fine for the bootstrap use it
// serves (org create/delete); the SQLite backend provides true isolation.
func (m *memoryBackend) Tx(fn func(tx Backend) error) error {
	m.mu.Lock()
	snapData := cloneOrgData(m.data)
	snapMeta := cloneOrgData(m.meta)
	snapBlobs := cloneBlobData(m.blobs)
	snapOrgs := maps.Clone(m.orgs)
	m.mu.Unlock()

	if err := fn(m); err != nil {
		m.mu.Lock()
		m.data, m.meta, m.blobs, m.orgs = snapData, snapMeta, snapBlobs, snapOrgs
		m.mu.Unlock()
		return err
	}
	return nil
}

func cloneOrgData[V any](src map[string]map[string]map[string]V) map[string]map[string]map[string]V {
	dst := make(map[string]map[string]map[string]V, len(src))
	for org, colls := range src {
		dc := make(map[string]map[string]V, len(colls))
		for coll, keys := range colls {
			dc[coll] = maps.Clone(keys) // value slices are immutable; safe to share
		}
		dst[org] = dc
	}
	return dst
}

func cloneBlobData(src map[string]map[string][]byte) map[string]map[string][]byte {
	dst := make(map[string]map[string][]byte, len(src))
	for org, blobs := range src {
		dst[org] = maps.Clone(blobs)
	}
	return dst
}

func (m *memoryBackend) Close() error { return nil }
