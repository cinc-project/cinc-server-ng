package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// classifyRequest is an allowlist, and an unrecognized route used to be
// *permitted*. That is how five separate privilege-escalation paths reached
// production: nobody added a case, and nothing said so.
//
// Two mechanisms close it. At build time, every registered mutating route must
// be either classified or listed as a deliberate exception — so forgetting is a
// test failure at the moment the route is added. At run time, a mutating
// request that matched a real route but no classification is refused.

// concreteRoute turns a registered pattern into a request path by filling in
// its wildcards.
func concreteRoute(pattern string) string {
	path := pattern
	for _, seg := range []struct{ placeholder, value string }{
		{"{org}", "acme"},
		{"{name}", "thing"},
		{"{user}", "someone"},
		{"{key}", "default"},
		{"{checksum}", "abc123"},
		{"{version}", "1.0.0"},
		{"{bag}", "bag"},
		{"{item}", "item"},
		{"{group}", "group"},
		{"{policy}", "policy"},
		{"{rev}", "rev"},
		{"{perm}", "read"},
		{"{index}", "node"},
		{"{id}", "id"},
	} {
		path = strings.ReplaceAll(path, seg.placeholder, seg.value)
	}
	return path
}

// Every mutating route the server registers must be a deliberate decision:
// classified, or named as an exception with a reason.
func TestEveryMutatingRouteIsAuthorized(t *testing.T) {
	a := New(store.New())
	a.Handler()

	if len(a.routes) == 0 {
		t.Fatal("no routes recorded; the registration hook is not wired up")
	}
	var checked int
	for _, pattern := range a.routes {
		method, rawPath, ok := strings.Cut(pattern, " ")
		if !ok || !mutatingMethod(method) {
			continue
		}
		checked++
		path := concreteRoute(rawPath)
		if _, classified := classifyRequest(method, path); classified {
			continue
		}
		if reason := openWriteReason(method, path); reason != "" {
			continue
		}
		t.Errorf("%s is neither classified nor a declared exception.\n"+
			"    Add a case to classifyRequest, or an entry to openWrites saying why it is open.", pattern)
	}
	if checked < 20 {
		t.Errorf("only %d mutating routes examined; the scan is probably broken", checked)
	}
}

// A mutating route that exists but carries no classification must be refused
// rather than quietly permitted.
func TestUnclassifiedMutatingRouteIsRefused(t *testing.T) {
	st := store.New()
	if _, err := CreateOrganization(st, "acme", "acme"); err != nil {
		t.Fatal(err)
	}
	a := New(st, WithACLEnforcement(true))
	h := a.Handler()
	// Register a route the classifier knows nothing about, standing in for one
	// somebody adds later without thinking about authorization.
	a.mux.HandleFunc("POST /organizations/{org}/experimental", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("POST", "http://x/organizations/acme/experimental", strings.NewReader("{}"))
	req = req.WithContext(WithActor(req.Context(), Actor{Name: "mallory"}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("unclassified mutating route = %d, want 403; it is open to any authenticated actor", rec.Code)
	}
}

// Failing closed must not turn "no such route" into "forbidden": a request that
// matches nothing still reports what Chef reports.
func TestUnroutedRequestsKeepTheirStatus(t *testing.T) {
	st := store.New()
	if _, err := CreateOrganization(st, "acme", "acme"); err != nil {
		t.Fatal(err)
	}
	a := New(st, WithACLEnforcement(true))
	h := a.Handler()

	for _, tc := range []struct {
		name, method, path string
		want               int
	}{
		{"unknown path", "POST", "http://x/organizations/acme/no-such-thing", http.StatusNotFound},
		{"wrong method on a real route", "DELETE", "http://x/organizations/acme/search", http.StatusMethodNotAllowed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader("{}"))
			req = req.WithContext(WithActor(req.Context(), Actor{Name: "mallory"}))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Errorf("%s %s = %d, want %d", tc.method, tc.path, rec.Code, tc.want)
			}
		})
	}
}

// Reads are unaffected: only mutating requests fail closed, so a read of an
// unclassified route behaves as before.
func TestUnclassifiedReadsStillPass(t *testing.T) {
	st := store.New()
	if _, err := CreateOrganization(st, "acme", "acme"); err != nil {
		t.Fatal(err)
	}
	a := New(st, WithACLEnforcement(true))
	h := a.Handler()

	req := httptest.NewRequest("GET", "http://x/organizations/acme/search", nil)
	req = req.WithContext(WithActor(req.Context(), Actor{Name: "mallory"}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusForbidden {
		t.Fatalf("search became forbidden; only mutating routes should fail closed")
	}
}
