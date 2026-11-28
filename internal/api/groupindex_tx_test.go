package api

import (
	"path/filepath"
	"testing"

	"github.com/cinc-project/cinc-server-ng/internal/store"
	"github.com/cinc-project/cinc-server-ng/internal/store/sqlite"
)

// A transaction's writes are invisible outside it until it commits, on both
// backends. An index rebuilt while a transaction that rewrites a group is
// open therefore reads the group as it was. It must not then be kept as
// current once the transaction commits: the group rename that moves an
// actor out of admins (renameClient, renameGroup) is such a transaction, and
// a stale index would go on granting admins to whatever is next registered
// under the old name.
func TestGroupIndexRebuiltDuringTxIsNotCurrentAfterCommit(t *testing.T) {
	backends := map[string]func(t *testing.T) *store.Store{
		"memory": func(t *testing.T) *store.Store { return store.New() },
		"sqlite": func(t *testing.T) *store.Store {
			be, err := sqlite.Open(filepath.Join(t.TempDir(), "x.db"))
			if err != nil {
				t.Fatal(err)
			}
			st := store.NewWithBackend(be)
			t.Cleanup(func() { st.Close() })
			return st
		},
	}
	for backend, open := range backends {
		t.Run(backend, func(t *testing.T) {
			st := open(t)
			org, err := st.CreateOrg("acme")
			if err != nil {
				t.Fatal(err)
			}
			c := newGroupIndexCache()
			st.Watch(c.observe)
			if err := org.Put("groups", "admins", groupJSON("admins", "", nil, []string{"ci-runner"}, nil)); err != nil {
				t.Fatal(err)
			}
			runner := Actor{Name: "ci-runner", IsClient: true}
			idx, err := c.get(org)
			if err != nil {
				t.Fatal(err)
			}
			// Baseline: the index reflects the committed group.
			if !idx.membership(runner)["admins"] {
				t.Fatal("baseline: ci-runner is not in admins")
			}

			if err := st.Tx(func(tx *store.Store) error {
				txOrg, _, err := tx.Org("acme")
				if err != nil {
					return err
				}
				if err := txOrg.Put("groups", "admins", groupJSON("admins", "", nil, []string{"ci-runner2"}, nil)); err != nil {
					return err
				}
				// An authorization check on another goroutine rebuilds
				// here, between the write and the commit.
				_, err = c.get(org)
				return err
			}); err != nil {
				t.Fatal(err)
			}

			idx, err = c.get(org)
			if err != nil {
				t.Fatal(err)
			}
			if idx.membership(runner)["admins"] {
				t.Error("after commit, the cached index still puts ci-runner in admins")
			}
			if !idx.membership(Actor{Name: "ci-runner2", IsClient: true})["admins"] {
				t.Error("after commit, the cached index misses ci-runner2 in admins")
			}
		})
	}
}
