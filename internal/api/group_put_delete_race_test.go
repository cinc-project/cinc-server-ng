package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// Under enforcement, authorize reads the group before the handler runs and
// hands the bytes forward (withPreread). A group PUT then waits on the
// membership lock, and a delete of the group can run to completion while it
// waits. The existence check made under the lock is what stops the PUT from
// writing the deleted group back, so it must read the store, not the bytes
// read before the lock.
//
// The request below carries the preread authorize would have left, for a
// group deleted since: exactly the state a PUT that waited out the delete
// finds when it takes the lock.
func TestGroupPutAfterConcurrentDeleteDoesNotRecreate(t *testing.T) {
	st := store.New()
	org, err := st.CreateOrg("acme")
	if err != nil {
		t.Fatal(err)
	}
	h := New(st).Handler()
	serve := func(r *http.Request) (int, string) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Code, rec.Body.String()
	}
	const path = "/organizations/acme/groups/contractors"
	put := func(body string) *http.Request {
		r := httptest.NewRequest("PUT", path, strings.NewReader(body))
		raw, ok, err := org.View("groups", "contractors")
		if err != nil || !ok {
			t.Fatalf("preread of contractors: ok=%v err=%v", ok, err)
		}
		return withPreread(r, "acme", "groups", "contractors", raw)
	}

	if code, body := serve(httptest.NewRequest("POST", "/organizations/acme/groups", strings.NewReader(`{"groupname":"contractors"}`))); code != http.StatusCreated {
		t.Fatalf("create contractors = %d: %s", code, body)
	}
	// Baseline: a PUT carrying a preread of a group that still exists succeeds.
	if code, body := serve(put(`{"actors":{"users":[]}}`)); code != http.StatusOK {
		t.Fatalf("baseline PUT = %d: %s", code, body)
	}

	for _, tc := range []struct{ name, body, target string }{
		{"update", `{"actors":{"users":[]}}`, "contractors"},
		{"rename", `{"groupname":"contractors2","actors":{"users":[]}}`, "contractors2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok, _ := org.Get("groups", "contractors"); !ok {
				if code, body := serve(httptest.NewRequest("POST", "/organizations/acme/groups", strings.NewReader(`{"groupname":"contractors"}`))); code != http.StatusCreated {
					t.Fatalf("create contractors = %d: %s", code, body)
				}
			}
			req := put(tc.body) // authorize's read, then the delete lands
			if code, body := serve(httptest.NewRequest("DELETE", path, nil)); code != http.StatusOK {
				t.Fatalf("DELETE = %d: %s", code, body)
			}
			if code, body := serve(req); code != http.StatusNotFound {
				t.Errorf("PUT after the delete = %d, want 404: %s", code, body)
			}
			if _, ok, _ := org.Get("groups", tc.target); ok {
				t.Errorf("the deleted group came back as %q", tc.target)
			}
		})
	}
}
