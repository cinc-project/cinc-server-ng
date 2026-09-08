package api

import (
	"encoding/json"
	"slices"
	"sync"

	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// Reverse index of group membership.
//
// Answering "which groups is this actor in?" by scanning every group in the org
// makes the cost of an authorization check grow with the size of the fleet: the
// org's "clients" group holds one entry per node, and Chef's default ACLs grant
// through groups, so a check-in on a 2000-node fleet paid to decode 2000
// membership entries to learn one bit.
//
// The scan is inverted once into actor -> groups, and reused until groups
// change. The store advances a generation counter on every write to a groups
// collection (see store.Org.GroupsGeneration), which is the invalidation
// signal: it sits at the single point all writes pass through, so no call site
// can forget to invalidate. The generation is sampled *before* the index is
// built, so an index built concurrently with a write is discarded rather than
// cached as current.

// groupIndex maps actors to the groups that list them, plus the nesting edges
// needed to expand membership transitively.
//
// An index is not frozen once published: observe patches membership rows into
// it in place, which is what keeps a fleet bootstrap linear. It is therefore
// read (by every authorization check) and written (by every registration)
// concurrently, so mu guards the maps. The cache's own lock is not enough — it
// only guards which index is current, not the contents of one that is.
type groupIndex struct {
	gen     uint64
	mu      sync.RWMutex
	users   map[string][]string // user -> groups listing it directly
	clients map[string][]string // client -> groups listing it directly
	nests   map[string][]string // group -> groups that list it in their groups[]
}

// buildGroupIndex reads the org's groups once and inverts them.
func buildGroupIndex(org *store.Org) (*groupIndex, error) {
	// Sampled before the read: if a write lands while we are building, the
	// generation we record is already stale and the next lookup rebuilds.
	gen := org.GroupsGeneration()
	idx := &groupIndex{
		gen:     gen,
		users:   map[string][]string{},
		clients: map[string][]string{},
		nests:   map[string][]string{},
	}
	if err := org.Range("groups", func(name string, raw []byte) bool {
		users, clients, nested := indexMembers(raw)
		idx.addAll(name, users, clients, nested)
		return true
	}); err != nil {
		return nil, err
	}
	// Membership added incrementally lives in rows rather than the document, so
	// the index has to fold those in too.
	if err := org.Range(groupMembersColl, func(key string, _ []byte) bool {
		if group, kind, actor, ok := splitMemberKey(key); ok {
			idx.addOne(group, kind, actor)
		}
		return true
	}); err != nil {
		return nil, err
	}
	return idx, nil
}

// addAll records a group's members from its document.
func (idx *groupIndex) addAll(group string, users, clients, nested []string) {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	for _, u := range users {
		idx.users[u] = append(idx.users[u], group)
	}
	for _, c := range clients {
		idx.clients[c] = append(idx.clients[c], group)
	}
	for _, g := range nested {
		idx.nests[g] = append(idx.nests[g], group)
	}
}

// addOne records a single membership row, skipping a duplicate of what the
// group document already declared.
func (idx *groupIndex) addOne(group, kind, actor string) {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	var into map[string][]string
	switch kind {
	case memberUsers:
		into = idx.users
	case memberClients:
		into = idx.clients
	case memberGroups:
		into = idx.nests
	default:
		return
	}
	if slices.Contains(into[actor], group) {
		return
	}
	into[actor] = append(into[actor], group)
}

// indexMembers pulls a group's members, preferring the typed decode and
// falling back to the tolerant map decode for an unexpected shape.
func indexMembers(raw []byte) (users, clients, groups []string) {
	if m, ok := decodeMembers(raw); ok {
		return m.Users, m.Clients, m.Groups
	}
	var g map[string]any
	if json.Unmarshal(raw, &g) != nil {
		return nil, nil, nil
	}
	return anyStrings(g["users"]), anyStrings(g["clients"]), anyStrings(g["groups"])
}

// membership expands the groups an actor belongs to, following nesting
// transitively. A group is only ever added once, so cycles terminate.
func (idx *groupIndex) membership(actor Actor) map[string]bool {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	direct := idx.users
	if actor.IsClient {
		direct = idx.clients
	}
	member := map[string]bool{}
	queue := make([]string, 0, 8)
	add := func(name string) {
		if !member[name] {
			member[name] = true
			queue = append(queue, name)
		}
	}
	for _, g := range direct[actor.Name] {
		add(g)
	}
	// Any group that nests a group we are already in, we are also in.
	for i := 0; i < len(queue); i++ {
		for _, outer := range idx.nests[queue[i]] {
			add(outer)
		}
	}
	return member
}

// groupIndexCache holds the current index per organization.
type groupIndexCache struct {
	mu sync.RWMutex
	m  map[string]*groupIndex
}

func newGroupIndexCache() *groupIndexCache {
	return &groupIndexCache{m: map[string]*groupIndex{}}
}

// get returns an index current as of the org's groups generation, rebuilding it
// if groups have been written since the cached one was built.
func (c *groupIndexCache) get(org *store.Org) (*groupIndex, error) {
	c.mu.RLock()
	idx, ok := c.m[org.Name()]
	c.mu.RUnlock()
	if ok && idx.gen == org.GroupsGeneration() {
		return idx, nil
	}

	// The rebuild runs under the cache lock, which observe also takes.
	//
	// A rebuild re-reads the membership rows, and observe folds each new row
	// into whichever index is installed. If the two could interleave, a row
	// written mid-rebuild would land in the index the rebuild is about to
	// replace and be missing from the one that replaces it — and, since rows are
	// the only record that a registered client belongs to the org's clients
	// group, that client would be denied everything the group grants until some
	// unrelated group write forced another rebuild.
	//
	// Serializing also collapses a herd of concurrent rebuilds into one, which
	// is the case that matters: every authorization check calls get.
	c.mu.Lock()
	defer c.mu.Unlock()
	if idx, ok := c.m[org.Name()]; ok && idx.gen == org.GroupsGeneration() {
		return idx, nil // rebuilt by another goroutine while we waited
	}
	built, err := buildGroupIndex(org)
	if err != nil {
		return nil, err
	}
	c.m[org.Name()] = built
	return built, nil
}

// observe applies a membership row to the cached index in place. Rebuilding on
// each row would put the fleet bootstrap back to quadratic, which is the whole
// reason membership is stored as rows. Changes to a group *document* are rare
// and still go through the generation check, which rebuilds.
func (c *groupIndexCache) observe(ev store.Event) {
	if ev.Collection != groupMembersColl {
		return
	}
	group, kind, actor, ok := splitMemberKey(ev.Key)
	if !ok {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	idx, ok := c.m[ev.Org]
	if !ok {
		return // not built yet; the build will read the row itself
	}
	if ev.Deleted {
		// A removal is rare (an explicit group write clearing rows), and the
		// membership lists are short, so drop the index and let it rebuild.
		delete(c.m, ev.Org)
		return
	}
	idx.addOne(group, kind, actor)
}

// actorGroups returns the set of group names the actor belongs to, expanding
// nested membership transitively, using the cached reverse index.
func (a *API) actorGroups(org *store.Org, actor Actor) (map[string]bool, error) {
	idx, err := a.groups.get(org)
	if err != nil {
		return nil, err
	}
	return idx.membership(actor), nil
}

// actorGroups is the uncached form: it builds the index and expands membership
// in one shot. It is the definition the cached path must agree with.
func actorGroups(org *store.Org, actor Actor) (map[string]bool, error) {
	idx, err := buildGroupIndex(org)
	if err != nil {
		return nil, err
	}
	return idx.membership(actor), nil
}
