package sqlite

import "sync"

// blobKey names one blob. An empty checksum stands for every blob of org, for
// invalidating a dropped organization.
type blobKey struct{ org, checksum string }

// sharedBlob is one read of a blob, shared by every ViewBlob that overlaps it.
// ready is closed once data/ok/err are set; refs counts the views holding it.
type sharedBlob struct {
	ready chan struct{}
	data  []byte
	ok    bool
	err   error
	refs  int
}

// blobShares lets concurrent file-store downloads of one blob share a single
// copy. A SQLite read of a blob always materializes the whole value, and a
// download holds it until the client has read it, so without sharing N slow
// downloads of a large file hold N copies of it. An entry lives only while some
// view holds it; a write to the blob drops the entry so the next view reads the
// blob again, while views already holding the old bytes keep them.
type blobShares struct {
	mu sync.Mutex
	m  map[blobKey]*sharedBlob
}

func newBlobShares() *blobShares { return &blobShares{m: map[blobKey]*sharedBlob{}} }

// view returns the blob under k, reading it with read only when no other view
// holds it or is reading it already, and the release func for the caller.
func (s *blobShares) view(k blobKey, read func() ([]byte, bool, error)) ([]byte, func(), bool, error) {
	s.mu.Lock()
	e := s.m[k]
	if e == nil {
		e = &sharedBlob{ready: make(chan struct{})}
		s.m[k] = e
		e.refs++
		s.mu.Unlock()
		e.data, e.ok, e.err = read()
		close(e.ready)
	} else {
		e.refs++
		s.mu.Unlock()
		<-e.ready
	}
	var once sync.Once
	release := func() { once.Do(func() { s.release(k, e) }) }
	if e.err != nil || !e.ok {
		release()
		return nil, func() {}, e.ok, e.err
	}
	return e.data, release, true, nil
}

func (s *blobShares) release(k blobKey, e *sharedBlob) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e.refs--
	if e.refs == 0 && s.m[k] == e {
		delete(s.m, k)
	}
}

// forget drops the shared entry for k (every entry of k.org when k.checksum is
// empty) so the next view reads what a write left behind.
func (s *blobShares) forget(k blobKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if k.checksum != "" {
		delete(s.m, k)
		return
	}
	for key := range s.m {
		if key.org == k.org {
			delete(s.m, key)
		}
	}
}
