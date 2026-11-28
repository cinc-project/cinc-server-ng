package api

import (
	"crypto/md5"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// A file-store transfer is authorized by the pre-signed URL the server issued,
// and the auth layer that checks the grant attaches no actor. A request that
// reaches the file store carrying a signed actor was authenticated as an
// ordinary request instead, so the grant was never checked: it is refused,
// whatever path form let it through.
func TestFileStoreRefusesASignedActor(t *testing.T) {
	st := store.New()
	if _, err := CreateOrganization(st, "acme", "acme"); err != nil {
		t.Fatal(err)
	}
	org, _, err := st.Org("acme")
	if err != nil {
		t.Fatal(err)
	}
	const content = "cookbook file body"
	sum := md5.Sum([]byte(content))
	checksum := hex.EncodeToString(sum[:])
	h := New(st).Handler()
	url := "http://x/organizations/acme/file_store/" + checksum

	// Baseline: with no actor (the grant path), the transfer goes through.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("PUT", url, strings.NewReader(content)))
	if rec.Code != http.StatusOK {
		t.Fatalf("upload without an actor = %d, want 200: %s", rec.Code, rec.Body)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", url, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("download without an actor = %d, want 200: %s", rec.Code, rec.Body)
	}
	if err := org.DeleteBlob(checksum); err != nil {
		t.Fatal(err)
	}

	for _, method := range []string{"PUT", "GET"} {
		req := httptest.NewRequest(method, url, strings.NewReader(content))
		req = req.WithContext(WithActor(req.Context(), Actor{Name: "mallory"}))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s with a signed actor = %d, want 401", method, rec.Code)
		}
	}
	if ok, err := org.HasBlob(checksum); err != nil || ok {
		t.Fatalf("blob stored for a signed actor (ok=%v, err=%v)", ok, err)
	}
}
