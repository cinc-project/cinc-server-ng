package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// The superuser may answer an invitation on a user's behalf, as it can on Chef
// Infra Server: that is how `knife org user add` (and chef-server-ctl
// org-user-add) puts a user in an org in one step. Anyone else still may not.
func TestSuperuserMayAcceptAnInvitationForAUser(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	createUserKey(t, srv, "bob")
	carolKey := createUserKey(t, srv, "carol")

	invite := func() string {
		t.Helper()
		resp, err := http.DefaultClient.Do(signed(t, srv, "POST", srv.URL()+"/organizations/acme/association_requests", `{"user":"bob"}`))
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var created struct {
			URI string `json:"uri"`
		}
		if resp.StatusCode != http.StatusCreated || json.Unmarshal(raw, &created) != nil {
			t.Fatalf("invite = %d: %s", resp.StatusCode, raw)
		}
		return created.URI[strings.LastIndex(created.URI, "/")+1:]
	}
	id := invite()
	accept := srv.URL() + "/users/bob/association_requests/" + id

	// Baseline: another user may not answer bob's invitation.
	if code := statusOf(t, signedAs(t, "carol", carolKey, "PUT", accept, `{"response":"accept"}`)); code != http.StatusForbidden {
		t.Fatalf("carol accepting bob's invitation = %d, want 403", code)
	}
	if code := statusOf(t, signed(t, srv, "PUT", accept, `{"response":"accept"}`)); code != http.StatusOK {
		t.Fatalf("superuser accepting bob's invitation = %d, want 200", code)
	}
	if code := statusOf(t, signed(t, srv, "GET", srv.URL()+"/organizations/acme/users/bob", "")); code != http.StatusOK {
		t.Fatalf("bob is not a member after the superuser accepted = %d", code)
	}
}
