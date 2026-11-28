package api

import "testing"

// A user associated directly while an invitation was pending, then removed,
// must not rejoin by accepting that old invitation.
func TestRemovalConsumesPendingInvitation(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	id := invite(t, srv.URL, "alice")
	if resp, b := do(t, "POST", base+"/users", `{"username":"alice"}`); resp.StatusCode != 201 {
		t.Fatalf("associate = %d: %s", resp.StatusCode, b)
	}
	if resp, b := do(t, "DELETE", base+"/users/alice", ""); resp.StatusCode != 200 {
		t.Fatalf("remove = %d: %s", resp.StatusCode, b)
	}
	if resp, b := do(t, "PUT", srv.URL+"/users/alice/association_requests/"+id, `{"response":"accept"}`); resp.StatusCode == 200 {
		t.Errorf("accepting the old invitation = 200 %s, want it gone", b)
	}
	if resp, _ := do(t, "GET", base+"/users/alice", ""); resp.StatusCode != 404 {
		t.Errorf("alice after accepting = %d, want 404 (not a member)", resp.StatusCode)
	}
}
