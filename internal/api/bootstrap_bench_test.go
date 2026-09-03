package api

import (
	"fmt"
	"testing"

	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// Registration cost as a fleet bootstraps.
//
// Every client registration adds the client to the org's "clients" group, and
// that client's first authorized request then resolves its membership. If
// either of those is linear in the number of members already registered, a
// bootstrap is quadratic overall — the thing that decides whether standing up a
// large fleet takes seconds or an hour.
func benchBootstrap(b *testing.B, fleet int) {
	for range b.N {
		st := store.New()
		org, err := st.CreateOrg("acme")
		if err != nil {
			b.Fatal(err)
		}
		a := New(st, WithACLEnforcement(true))
		for i := range fleet {
			name := fmt.Sprintf("node%d", i)
			// What createActor does under enforcement: join the org group...
			if err := addClientToOrgGroup(org, "clients", name); err != nil {
				b.Fatal(err)
			}
			// ...then the client's first authorized request resolves membership.
			if _, err := a.actorGroups(org, Actor{Name: name, IsClient: true}); err != nil {
				b.Fatal(err)
			}
		}
	}
}

func BenchmarkBootstrap500(b *testing.B)  { benchBootstrap(b, 500) }
func BenchmarkBootstrap2000(b *testing.B) { benchBootstrap(b, 2000) }
func BenchmarkBootstrap8000(b *testing.B) { benchBootstrap(b, 8000) }
