package server

import (
	"encoding/json"
	"net/http"
	"testing"
)

// Key rows left under a client name with no client (by an older version that
// let a key write outlive a concurrent delete, or a state directory) must not
// authenticate the client registered under that name next, as a re-bootstrap
// after `knife client delete` does.
func TestReregisteredClientDoesNotInheritLeftoverKeys(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	base := srv.URL() + "/organizations/acme"
	probe := base + "/nodes"
	org, _, err := srv.Store().Org("acme")
	if err != nil {
		t.Fatal(err)
	}
	stalePriv, stalePub := newKeyPair(t)
	row, _ := json.Marshal(map[string]string{"name": "stale", "public_key": stalePub, "expiration_date": "infinity"})

	// Baseline: a row of this shape authenticates the client it is stored
	// under, so the assertion below is about the leftover, not the row.
	createClientAndKey(t, srv, base, "other")
	if err := org.Put("clients_keys:other", "stale", row); err != nil {
		t.Fatal(err)
	}
	wantAuth(t, "row stored under an existing client", statusOf(t, signedAs(t, "other", stalePriv, "GET", probe, "")), http.StatusOK)

	if err := org.Put("clients_keys:web", "stale", row); err != nil {
		t.Fatal(err)
	}
	webKey := createClientAndKey(t, srv, base, "web")
	wantAuth(t, "registered client's own key", statusOf(t, signedAs(t, "web", webKey, "GET", probe, "")), http.StatusOK)
	wantAuth(t, "leftover key", statusOf(t, signedAs(t, "web", stalePriv, "GET", probe, "")), http.StatusUnauthorized)
}
