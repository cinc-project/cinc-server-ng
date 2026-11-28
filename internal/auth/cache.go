package auth

import (
	"container/list"
	"crypto/rsa"
	"crypto/sha256"
	"sync"
	"unsafe"
)

// DefaultPublicKeyCacheSize is how many parsed keys NewPublicKeyCache keeps.
// It covers the actors of a fleet of thousands of nodes; past it, the least
// recently used key is parsed again on its next request, which costs no more
// than the uncached path. An entry is a SHA-256 digest and a parsed key whose
// modulus is at most MaxPublicKeyBits, so a full cache stays in the low
// megabytes whatever actors store as their public_key.
const DefaultPublicKeyCacheSize = 4096

// PublicKeyCache memoizes parsed RSA public keys by their PEM encoding. Parsing
// a PEM-wrapped x509 key is one of the costlier steps on the authentication
// hot path, and a single chef-client / knife run issues many requests signed by
// the same key, so caching the parse turns a repeat lookup into a map read.
//
// Entries are keyed by the SHA-256 digest of the PEM, never the PEM itself: a
// stored public_key may carry arbitrary bytes after its PEM block, and the
// cache must not keep those alive. Keying on the PEM's digest makes
// invalidation automatic: when an actor rotates its key the stored PEM
// changes, so the next request misses the cache and the new key is parsed.
// The cache holds a bounded number of keys and evicts the least recently
// used. Parse failures are not cached.
//
// A PublicKeyCache is safe for concurrent use.
type PublicKeyCache struct {
	mu   sync.Mutex
	size int
	m    map[[sha256.Size]byte]*list.Element
	lru  *list.List // of *cacheEntry, most recently used first
}

type cacheEntry struct {
	digest [sha256.Size]byte
	key    *rsa.PublicKey
}

// NewPublicKeyCache returns an empty cache holding up to
// DefaultPublicKeyCacheSize keys.
func NewPublicKeyCache() *PublicKeyCache {
	return newPublicKeyCache(DefaultPublicKeyCacheSize)
}

func newPublicKeyCache(size int) *PublicKeyCache {
	return &PublicKeyCache{
		size: max(size, 1),
		m:    make(map[[sha256.Size]byte]*list.Element),
		lru:  list.New(),
	}
}

// Parse returns the RSA public key for the given PEM, parsing it (via
// ParsePublicKey) on a miss and caching the result. Errors are returned but not
// cached.
func (c *PublicKeyCache) Parse(pemStr string) (*rsa.PublicKey, error) {
	// Hash the string's bytes in place: copying a PEM to hash it would put an
	// allocation back on the hit path. sha256 only reads its input.
	digest := sha256.Sum256(unsafe.Slice(unsafe.StringData(pemStr), len(pemStr)))
	if key, ok := c.lookup(digest); ok {
		return key, nil
	}
	key, err := ParsePublicKey([]byte(pemStr))
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.m[digest]; ok {
		// Another request parsed the same PEM meanwhile; keep its key.
		c.lru.MoveToFront(el)
		return el.Value.(*cacheEntry).key, nil
	}
	c.m[digest] = c.lru.PushFront(&cacheEntry{digest: digest, key: key})
	for c.lru.Len() > c.size {
		oldest := c.lru.Back()
		c.lru.Remove(oldest)
		delete(c.m, oldest.Value.(*cacheEntry).digest)
	}
	return key, nil
}

func (c *PublicKeyCache) lookup(digest [sha256.Size]byte) (*rsa.PublicKey, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.m[digest]
	if !ok {
		return nil, false
	}
	c.lru.MoveToFront(el)
	return el.Value.(*cacheEntry).key, true
}

// Len reports the number of cached keys.
func (c *PublicKeyCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru.Len()
}
