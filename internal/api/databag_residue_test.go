package api

import (
	"strings"
	"sync"
	"testing"

	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// Items are keyed by bag name alone, so a bag created under a name that still
// has item rows (an item written while the bag was being deleted) must not
// serve them.
func TestNewDataBagDoesNotInheritLeftoverItems(t *testing.T) {
	srv, st := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	org := acmeOrg(t, st)
	if err := org.Put(dataBagItemsColl("secrets"), "db", []byte(`{"id":"db","password":"old"}`)); err != nil {
		t.Fatal(err)
	}
	if resp, b := do(t, "POST", base+"/data", `{"name":"secrets"}`); resp.StatusCode != 201 {
		t.Fatalf("create bag = %d: %s", resp.StatusCode, b)
	}
	if resp, b := do(t, "GET", base+"/data/secrets", ""); strings.Contains(b, "db") {
		t.Errorf("new bag lists a leftover item: %d %s", resp.StatusCode, b)
	}
	if resp, _ := do(t, "GET", base+"/data/secrets/db", ""); resp.StatusCode != 404 {
		t.Errorf("leftover item readable in the new bag: %d", resp.StatusCode)
	}
}

// The bag record goes last: while the delete runs the name stays taken, so it
// cannot be created again over items that are still being removed.
func TestDataBagDeleteRemovesItemsBeforeTheBag(t *testing.T) {
	srv, st := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	do(t, "POST", base+"/data", `{"name":"secrets"}`)
	do(t, "POST", base+"/data/secrets", `{"id":"db"}`)
	var mu sync.Mutex
	var deletes []string
	st.Watch(func(ev store.Event) {
		if ev.Deleted && ev.Org == "acme" {
			mu.Lock()
			deletes = append(deletes, ev.Collection)
			mu.Unlock()
		}
	})
	if resp, b := do(t, "DELETE", base+"/data/secrets", ""); resp.StatusCode != 200 {
		t.Fatalf("delete = %d: %s", resp.StatusCode, b)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(deletes) == 0 || deletes[len(deletes)-1] != dataBagsColl {
		t.Errorf("deletes in order %v, want the bag record last", deletes)
	}
}
