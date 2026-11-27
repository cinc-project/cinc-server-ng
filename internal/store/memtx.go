package store

import (
	"bytes"
	"errors"
	"maps"
	"sort"
)

// memTx is a memory-backend transaction: its writes go to an overlay that
// reads consult ahead of the backend, and commit applies the overlay to the
// backend in one step under the write lock. Rollback is dropping the overlay,
// so it can never undo another writer's work, and no reader outside the
// transaction sees its writes before commit. Commit is optimistic: if another
// writer changed an object the transaction writes after the transaction read
// it, the commit fails with ErrConflict rather than overwrite that change.
// Nothing is copied up front: the cost of a transaction is that of what it
// touches.
//
// A memTx belongs to the goroutine running the transaction's fn; it is not
// safe for concurrent use.
type memTx struct {
	m *memoryBackend
	// objs holds the transaction's object writes, org -> coll -> key.
	objs map[string]map[string]map[string]*txObj
	// blobs holds its blob writes, org -> checksum.
	blobs map[string]map[string]*txBlob
	// orgs records each org whose existence the transaction set.
	orgs map[string]bool
	// dropped names the orgs the transaction deleted: the backend's objects
	// and blobs of these are hidden from it, and dropped on commit.
	dropped map[string]bool
	// seen records each object as the transaction first read it from the
	// backend (every write reads first, to keep the creation time or refuse
	// a Create). Commit fails with ErrConflict if an object the transaction
	// writes has changed in the backend since: its write was derived from
	// what it read, and applying it would undo the other writer's change.
	seen map[objRef]seenObj
	// createdOrgs lists the orgs the transaction created: commit fails with
	// ErrConflict if another writer created one first.
	createdOrgs []string
}

// seenObj is an object as the transaction read it from the backend. Stored
// values are never written in place, so val stays as it was read.
type seenObj struct {
	val []byte
	ok  bool
}

type objRef struct{ org, coll, key string }

// txObj is one object as the transaction left it.
type txObj struct {
	val     []byte
	md      Meta
	deleted bool
	// metaOnly marks a SetMeta of an object the transaction did not write:
	// the body is still the backend's, and only md is the transaction's.
	metaOnly bool
}

type txBlob struct {
	data    []byte
	deleted bool
}

var errNestedTx = errors.New("store: nested transaction")

func newMemTx(m *memoryBackend) *memTx {
	return &memTx{
		m:       m,
		objs:    map[string]map[string]map[string]*txObj{},
		blobs:   map[string]map[string]*txBlob{},
		orgs:    map[string]bool{},
		dropped: map[string]bool{},
		seen:    map[objRef]seenObj{},
	}
}

// entry returns the transaction's write of org/coll/key, or nil.
func (t *memTx) entry(org, coll, key string) *txObj {
	return t.objs[org][coll][key]
}

// record stores e as the transaction's write of org/coll/key.
func (t *memTx) record(org, coll, key string, e *txObj) {
	colls := t.objs[org]
	if colls == nil {
		colls = map[string]map[string]*txObj{}
		t.objs[org] = colls
	}
	keys := colls[coll]
	if keys == nil {
		keys = map[string]*txObj{}
		colls[coll] = keys
	}
	keys[key] = e
}

// base reads org/coll/key from the backend as the transaction sees it: absent
// if the transaction dropped the org.
func (t *memTx) base(org, coll, key string) ([]byte, Meta, bool) {
	if t.dropped[org] {
		return nil, Meta{}, false
	}
	t.m.mu.RLock()
	v, ok := t.m.data[org][coll][key]
	md := t.m.meta[org][coll][key]
	t.m.mu.RUnlock()
	t.see(objRef{org, coll, key}, v, ok)
	if !ok {
		return nil, Meta{}, false
	}
	return v, md, true
}

// see records an object as the transaction read it from the backend, unless
// it already read it.
func (t *memTx) see(r objRef, val []byte, ok bool) {
	if _, done := t.seen[r]; !done {
		t.seen[r] = seenObj{val: val, ok: ok}
	}
}

// lookup returns org/coll/key as the transaction sees it. The value is shared:
// callers that hand it out clone it.
func (t *memTx) lookup(org, coll, key string) ([]byte, Meta, bool) {
	e := t.entry(org, coll, key)
	switch {
	case e == nil:
		return t.base(org, coll, key)
	case e.deleted:
		return nil, Meta{}, false
	case e.metaOnly:
		v, _, ok := t.base(org, coll, key)
		return v, e.md, ok
	}
	return e.val, e.md, true
}

func (t *memTx) Get(org, coll, key string) ([]byte, bool, error) {
	v, _, ok := t.lookup(org, coll, key)
	if !ok {
		return nil, false, nil
	}
	return clone(v), true, nil
}

// view lends the value for Org.View, as memoryBackend.view does: neither the
// backend's values nor the overlay's are ever written in place.
func (t *memTx) view(org, coll, key string) ([]byte, bool, error) {
	v, _, ok := t.lookup(org, coll, key)
	return v, ok, nil
}

// set records val as the transaction's write of org/coll/key, keeping the
// creation time of an object that exists.
func (t *memTx) set(org, coll, key string, val []byte, st Stamp) {
	md := Meta{CreatedAt: st.At, UpdatedAt: st.At, UpdatedBy: st.By}
	if _, old, ok := t.lookup(org, coll, key); ok {
		md.CreatedAt = old.CreatedAt
	}
	t.record(org, coll, key, &txObj{val: clone(val), md: md})
}

func (t *memTx) Put(org, coll, key string, val []byte, st Stamp) error {
	t.set(org, coll, key, val, st)
	return nil
}

func (t *memTx) Create(org, coll, key string, val []byte, st Stamp) error {
	if _, _, ok := t.lookup(org, coll, key); ok {
		return ErrConflict
	}
	t.set(org, coll, key, val, st)
	return nil
}

func (t *memTx) Delete(org, coll, key string) ([]byte, bool, error) {
	v, _, ok := t.lookup(org, coll, key)
	if !ok {
		return nil, false, nil
	}
	t.record(org, coll, key, &txObj{deleted: true})
	return clone(v), true, nil
}

func (t *memTx) Meta(org, coll, key string) (Meta, bool, error) {
	_, md, ok := t.lookup(org, coll, key)
	return md, ok, nil
}

func (t *memTx) SetMeta(org, coll, key string, md Meta) error {
	e := t.entry(org, coll, key)
	switch {
	case e != nil && e.deleted:
		return ErrNotFound
	case e != nil:
		e.md = md
		return nil
	}
	if _, _, ok := t.base(org, coll, key); !ok {
		return ErrNotFound
	}
	t.record(org, coll, key, &txObj{md: md, metaOnly: true})
	return nil
}

// visible returns the keys of org/coll the transaction sees, with values.
// The backend's part is copied under the read lock, so callers may call back
// into the transaction.
func (t *memTx) visible(org, coll string) map[string][]byte {
	out := map[string][]byte{}
	if !t.dropped[org] {
		t.m.mu.RLock()
		maps.Copy(out, t.m.data[org][coll])
		t.m.mu.RUnlock()
		for k, v := range out {
			t.see(objRef{org, coll, k}, v, true)
		}
	}
	for k, e := range t.objs[org][coll] {
		switch {
		case e.deleted:
			delete(out, k)
		case e.metaOnly:
			// The body is the backend's: present in out exactly when the
			// object still exists.
		default:
			out[k] = e.val
		}
	}
	return out
}

func (t *memTx) Keys(org, coll string) ([]string, error) {
	vis := t.visible(org, coll)
	keys := make([]string, 0, len(vis))
	for k := range vis {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys, nil
}

func (t *memTx) Range(org, coll string, fn func(key string, raw []byte) bool) error {
	for k, v := range t.visible(org, coll) {
		if !fn(k, v) {
			return nil
		}
	}
	return nil
}

func (t *memTx) Collections(org string) ([]string, error) {
	names := map[string]bool{}
	if !t.dropped[org] {
		t.m.mu.RLock()
		for c := range t.m.data[org] {
			names[c] = true
		}
		t.m.mu.RUnlock()
	}
	for c := range t.objs[org] {
		names[c] = true
	}
	colls := make([]string, 0, len(names))
	for c := range names {
		if len(t.visible(org, c)) > 0 {
			colls = append(colls, c)
		}
	}
	sort.Strings(colls)
	return colls, nil
}

func (t *memTx) blob(org, checksum string) ([]byte, bool) {
	if b := t.blobs[org][checksum]; b != nil {
		return b.data, !b.deleted
	}
	if t.dropped[org] {
		return nil, false
	}
	t.m.mu.RLock()
	defer t.m.mu.RUnlock()
	v, ok := t.m.blobs[org][checksum]
	return v, ok
}

func (t *memTx) recordBlob(org, checksum string, b *txBlob) {
	if t.blobs[org] == nil {
		t.blobs[org] = map[string]*txBlob{}
	}
	t.blobs[org][checksum] = b
}

func (t *memTx) PutBlob(org, checksum string, data []byte) error {
	t.recordBlob(org, checksum, &txBlob{data: clone(data)})
	return nil
}

func (t *memTx) Blob(org, checksum string) ([]byte, bool, error) {
	v, ok := t.blob(org, checksum)
	if !ok {
		return nil, false, nil
	}
	return clone(v), true, nil
}

func (t *memTx) HasBlob(org, checksum string) (bool, error) {
	_, ok := t.blob(org, checksum)
	return ok, nil
}

func (t *memTx) DeleteBlob(org, checksum string) error {
	t.recordBlob(org, checksum, &txBlob{deleted: true})
	return nil
}

func (t *memTx) HasOrg(name string) (bool, error) {
	if v, ok := t.orgs[name]; ok {
		return v, nil
	}
	return t.m.HasOrg(name)
}

func (t *memTx) CreateOrg(name string) error {
	if ok, _ := t.HasOrg(name); ok {
		return ErrConflict
	}
	t.orgs[name] = true
	t.createdOrgs = append(t.createdOrgs, name)
	return nil
}

func (t *memTx) DeleteOrg(name string) (bool, error) {
	if ok, _ := t.HasOrg(name); !ok {
		return false, nil
	}
	t.orgs[name] = false
	t.dropped[name] = true
	delete(t.objs, name)
	delete(t.blobs, name)
	return true, nil
}

func (t *memTx) ListOrgs() ([]string, error) {
	t.m.mu.RLock()
	set := maps.Clone(t.m.orgs)
	t.m.mu.RUnlock()
	for name, exists := range t.orgs {
		if exists {
			set[name] = true
		} else {
			delete(set, name)
		}
	}
	names := make([]string, 0, len(set))
	for n := range set {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}

func (t *memTx) Tx(func(tx Backend) error) error { return errNestedTx }

func (t *memTx) Close() error { return nil }

// commit applies the overlay to the backend under its write lock. It fails
// with ErrConflict, applying nothing, if another writer has meanwhile changed
// an object this transaction writes (see seen), or created an org it created.
// Objects of an org the transaction dropped are not checked: the drop
// discards them whatever they hold.
func (t *memTx) commit() error {
	m := t.m
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, name := range t.createdOrgs {
		if t.orgs[name] && !t.dropped[name] && m.orgs[name] {
			return ErrConflict
		}
	}
	for org, colls := range t.objs {
		if t.dropped[org] {
			continue
		}
		for coll, keys := range colls {
			for key := range keys {
				was, read := t.seen[objRef{org, coll, key}]
				now, ok := m.data[org][coll][key]
				if !read || was.ok != ok || !bytes.Equal(was.val, now) {
					return ErrConflict
				}
			}
		}
	}
	for name := range t.dropped {
		delete(m.data, name)
		delete(m.meta, name)
		delete(m.blobs, name)
	}
	for name, exists := range t.orgs {
		if exists {
			m.orgs[name] = true
		} else {
			delete(m.orgs, name)
		}
	}
	for org, colls := range t.objs {
		for coll, keys := range colls {
			for key, e := range keys {
				switch {
				case e.deleted:
					delete(m.data[org][coll], key)
					delete(m.meta[org][coll], key)
				case e.metaOnly:
					if _, ok := m.data[org][coll][key]; ok {
						m.putMeta(org, coll, key, e.md)
					}
				default:
					m.store(org, coll, key, e.val, e.md)
				}
			}
		}
	}
	for org, sums := range t.blobs {
		for sum, b := range sums {
			if b.deleted {
				delete(m.blobs[org], sum)
				continue
			}
			if m.blobs[org] == nil {
				m.blobs[org] = map[string][]byte{}
			}
			m.blobs[org][sum] = b.data
		}
	}
	return nil
}
