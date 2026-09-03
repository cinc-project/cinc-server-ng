package api

import (
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// BenchmarkListObjects measures the node-list endpoint end-to-end through the
// router for a large collection: key collection + URL building + JSON encoding.
func BenchmarkListObjects(b *testing.B) {
	st := store.New()
	org, err := st.CreateOrg("acme")
	if err != nil {
		b.Fatal(err)
	}
	a := New(st)
	for i := range 500 {
		if err := org.Put("nodes", fmt.Sprintf("node%d", i), []byte(`{"name":"x"}`)); err != nil {
			b.Fatal(err)
		}
	}
	h := a.Handler()
	req := httptest.NewRequest("GET", "http://127.0.0.1/organizations/acme/nodes", nil)

	b.ReportAllocs()
	for b.Loop() {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 200 {
			b.Fatalf("status %d", rec.Code)
		}
	}
}
