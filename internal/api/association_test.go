package api

import (
	"encoding/json"
	"testing"
)

func TestUserOrgAssociation(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"

	// bob must exist as a global user before being associated.
	do(t, "POST", srv.URL+"/users", userBody(`{"name":"bob"}`))

	// Associating an unknown user fails.
	resp, _ := do(t, "POST", base+"/users", `{"username":"ghost"}`)
	if resp.StatusCode != 404 {
		t.Fatalf("associate unknown user = %d, want 404", resp.StatusCode)
	}

	// Associate bob with the org.
	resp, body := do(t, "POST", base+"/users", `{"username":"bob"}`)
	if resp.StatusCode != 201 {
		t.Fatalf("associate = %d: %s", resp.StatusCode, body)
	}

	// bob shows up in the org's user list.
	_, body = do(t, "GET", base+"/users", "")
	var list []struct {
		User struct {
			Username string `json:"username"`
		} `json:"user"`
	}
	json.Unmarshal([]byte(body), &list)
	found := false
	for _, e := range list {
		if e.User.Username == "bob" {
			found = true
		}
	}
	if !found {
		t.Fatalf("org user list missing bob: %s", body)
	}

	// And the org shows up in bob's organization list.
	_, body = do(t, "GET", srv.URL+"/users/bob/organizations", "")
	var orgs []struct {
		Organization struct {
			Name string `json:"name"`
		} `json:"organization"`
	}
	json.Unmarshal([]byte(body), &orgs)
	if len(orgs) != 1 || orgs[0].Organization.Name != "acme" {
		t.Fatalf("bob's organizations = %s", body)
	}

	// Fetch the single association.
	resp, body = do(t, "GET", base+"/users/bob", "")
	if resp.StatusCode != 200 {
		t.Fatalf("get association = %d: %s", resp.StatusCode, body)
	}

	// Remove it.
	resp, _ = do(t, "DELETE", base+"/users/bob", "")
	if resp.StatusCode != 200 {
		t.Fatalf("disassociate = %d", resp.StatusCode)
	}
	resp, _ = do(t, "GET", base+"/users/bob", "")
	if resp.StatusCode != 404 {
		t.Fatalf("get removed association = %d, want 404", resp.StatusCode)
	}
}
