package store

import (
	"sync"
	"sync/atomic"
)

// The write stream.
//
// Anything derived from stored data — search postings, group membership — has
// to be kept current as writes land. Rebuilding it whenever something changes
// is what turns a fleet bootstrap quadratic, so instead the store reports each
// committed write and derived indexes patch themselves.
//
// The stream is defined by two properties an index can rely on:
//
//   - Every write that actually changed something is reported exactly once. A
//     Create that conflicted and a Delete that found nothing changed nothing,
//     so they report nothing.
//   - Writes made inside a transaction are reported only once it commits, in
//     order. A rolled-back transaction reports nothing, so an index can never
//     describe data that never existed.
//
// Observers are called synchronously on the writing goroutine, so they must be
// cheap and must not write back into the store.

// Event describes one committed write.
type Event struct {
	Org        string // "" for the global space
	Collection string
	Key        string
	// Value is the bytes written, or nil for a delete. It aliases the stored
	// value and must not be modified.
	Value   []byte
	Deleted bool
}

// emitter receives write events. Writes go either straight to the registered
// observers or, inside a transaction, to a buffer that releases them on commit.
type emitter interface{ emit(Event) }

// watchers fans events out to the registered observers. The observer list is
// read on every write and written approximately never, so it is swapped
// atomically rather than guarded by a mutex on the hot path.
type watchers struct {
	mu  sync.Mutex
	fns atomic.Pointer[[]func(Event)]
}

func (w *watchers) add(fn func(Event)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	var next []func(Event)
	if cur := w.fns.Load(); cur != nil {
		next = append(next, *cur...)
	}
	next = append(next, fn)
	w.fns.Store(&next)
}

func (w *watchers) emit(ev Event) {
	fns := w.fns.Load()
	if fns == nil {
		return
	}
	for _, fn := range *fns {
		fn(ev)
	}
}

// txBuffer holds a transaction's events until it commits.
type txBuffer struct {
	mu     sync.Mutex
	events []Event
}

func (b *txBuffer) emit(ev Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.events = append(b.events, ev)
}

// flushTo replays the buffered events, in order, once the transaction has
// committed.
func (b *txBuffer) flushTo(dst emitter) {
	b.mu.Lock()
	events := b.events
	b.events = nil
	b.mu.Unlock()
	for _, ev := range events {
		dst.emit(ev)
	}
}

// Watch registers fn to receive every committed write. It may be called more
// than once; observers are invoked in registration order.
//
// fn runs synchronously on the goroutine performing the write, so it must be
// cheap and must not call back into the store.
func (s *Store) Watch(fn func(Event)) {
	if s.watch != nil {
		s.watch.add(fn)
	}
}
