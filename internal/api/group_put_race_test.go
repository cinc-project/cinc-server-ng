package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// A group PUT reads the group's membership, keeps the kinds its body leaves
// out, and writes the result back. Revoking an actor (deleting it, or dropping
// a user from the org) must not be able to land inside that window: the PUT
// would write the revoked actor back into the group, and since groups name
// actors by bare name, whatever is next created under that name would inherit
// the membership. Drives both through the real handlers, concurrently, and
// asserts the revoked actor never survives in the group.
func TestGroupPutRacesActorRevocation(t *testing.T) {
	st := store.New()
	org, err := st.CreateOrg("acme")
	if err != nil {
		t.Fatal(err)
	}
	if err := SeedOrg(org); err != nil {
		t.Fatal(err)
	}
	h := New(st).Handler()
	serve := func(method, path, body string) (int, string) {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	must := func(want int, method, path, body string) {
		t.Helper()
		if code, got := serve(method, path, body); code != want {
			t.Fatalf("%s %s = %d, want %d: %s", method, path, code, want, got)
		}
	}
	// One key for every actor: generating one per create would dominate the run.
	pub := jsonString(t, testPublicKey(t))
	const base = "/organizations/acme"
	must(http.StatusCreated, "POST", base+"/groups", `{"groupname":"devs"}`)

	revocations := []struct {
		kind   string
		create func(name string)
		revoke func(name string) (string, string)
		keep   string // a PUT body that leaves kind out
	}{
		{
			kind: memberClients,
			create: func(name string) {
				must(http.StatusCreated, "POST", base+"/clients", `{"name":"`+name+`","public_key":`+pub+`}`)
			},
			revoke: func(name string) (string, string) { return "DELETE", base + "/clients/" + name },
			keep:   `{"actors":{"users":[]}}`,
		},
		{
			kind: memberUsers,
			create: func(name string) {
				must(http.StatusCreated, "POST", "/users", userBody(`{"name":"`+name+`","public_key":`+pub+`}`))
			},
			revoke: func(name string) (string, string) { return "DELETE", "/users/" + name },
			keep:   `{"actors":{"clients":[]}}`,
		},
	}
	const iterations = 150
	for _, rv := range revocations {
		for i := range iterations {
			name := fmt.Sprintf("%s-%d", strings.TrimSuffix(rv.kind, "s"), i)
			rv.create(name)
			must(http.StatusOK, "PUT", base+"/groups/devs", `{"actors":{"`+rv.kind+`":["`+name+`"]}}`)
			// Baseline: the actor is a member before it is revoked.
			if members := kindMembers(t, org, rv.kind); !slices.Contains(members, name) {
				t.Fatalf("baseline: %s not in devs %s: %v", name, rv.kind, members)
			}

			var wg sync.WaitGroup
			start := make(chan struct{})
			for range 4 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					for range 3 {
						if code, got := serve("PUT", base+"/groups/devs", rv.keep); code != http.StatusOK {
							t.Errorf("PUT devs = %d: %s", code, got)
						}
					}
				}()
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				method, path := rv.revoke(name)
				if code, got := serve(method, path, ""); code != http.StatusOK {
					t.Errorf("%s %s = %d: %s", method, path, code, got)
				}
			}()
			close(start)
			wg.Wait()

			if members := kindMembers(t, org, rv.kind); slices.Contains(members, name) {
				t.Fatalf("iteration %d: revoked %s is still in devs %s: %v", i, name, rv.kind, members)
			}
		}
	}
}

func kindMembers(t *testing.T, org *store.Org, kind string) []string {
	t.Helper()
	users, clients, groups, err := groupMembership(org, "devs")
	if err != nil {
		t.Fatal(err)
	}
	switch kind {
	case memberUsers:
		return users
	case memberClients:
		return clients
	}
	return groups
}
