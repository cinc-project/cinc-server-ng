package store

// Backend is the pluggable persistence layer beneath Store/Org. It stores opaque
// canonical-JSON object bodies keyed by (org, collection, key) and opaque blob
// content keyed by (org, checksum). The empty org string ("") addresses the
// server-global space (the users/organizations collections), mirroring
// Store.Global().
//
// Object reads and writes operate on any (org, coll, key) regardless of whether
// CreateOrg was called for that org; CreateOrg/DeleteOrg/ListOrgs/HasOrg track the
// set of *named* organizations (the global space is never listed). DeleteOrg drops
// every object and blob belonging to the org. Create and CreateOrg return
// ErrConflict when the target key or org already exists.
//
// A Backend must be safe for concurrent use by multiple goroutines.
// Implementations live in subpackages (store/memory, store/sqlite).
type Backend interface {
	// Object store.
	Get(org, coll, key string) (val []byte, ok bool, err error)
	Put(org, coll, key string, val []byte, st Stamp) error
	Create(org, coll, key string, val []byte, st Stamp) error // ErrConflict if key exists
	Delete(org, coll, key string) (old []byte, existed bool, err error)
	Keys(org, coll string) ([]string, error) // sorted
	Range(org, coll string, fn func(key string, raw []byte) bool) error
	Collections(org string) ([]string, error) // non-empty collections, sorted

	// Object metadata (see Meta). It lives with the object: Delete and DeleteOrg
	// drop it, and a transaction commits or discards it with the body.
	Meta(org, coll, key string) (m Meta, ok bool, err error)
	// SetMeta replaces an object's metadata without touching its body, for
	// importers carrying times from another server. ErrNotFound if no object.
	SetMeta(org, coll, key string, m Meta) error

	// Blob store (cookbook file content).
	PutBlob(org, checksum string, data []byte) error
	Blob(org, checksum string) (data []byte, ok bool, err error)
	HasBlob(org, checksum string) (bool, error)
	DeleteBlob(org, checksum string) error

	// Org lifecycle.
	CreateOrg(name string) error // ErrConflict if org exists
	DeleteOrg(name string) (existed bool, err error)
	ListOrgs() ([]string, error) // named orgs only, sorted
	HasOrg(name string) (bool, error)

	// Tx runs fn as a single atomic unit: the Backend passed to fn applies all of
	// its writes together when fn returns nil, and discards them when fn returns a
	// non-nil error (which Tx propagates). Implementations must not be entered
	// recursively. Reads inside fn observe fn's own prior writes.
	Tx(fn func(tx Backend) error) error

	Close() error
}
