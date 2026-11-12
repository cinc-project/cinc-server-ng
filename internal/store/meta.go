package store

import "time"

// Meta is what the store records about an object beside its body: when it was
// created and last changed, and which actor changed it last. These are the
// created_at, updated_at and last_updated_by columns erchef keeps on its object
// tables. They are kept out of the body because the body is served to clients
// as stored, and chef-client and knife send it back on their next write.
//
// A zero time means unknown: an object written before the store recorded times,
// or imported without them. UpdatedBy names the actor as "users/<name>" or
// "clients/<name>", and is empty for writes no authenticated actor made (the
// server's own bootstrap, a repo or state load, or a request with auth off).
type Meta struct {
	CreatedAt time.Time
	UpdatedAt time.Time
	UpdatedBy string
}

// Stamp is the time and actor of one write. Create, and Put of a new key, record
// it as both the creation and the last update; Put over an existing key records
// it as the last update and keeps the creation time.
type Stamp struct {
	At time.Time
	By string
}
