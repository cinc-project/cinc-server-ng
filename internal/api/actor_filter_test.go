package api

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestUserListFiltering covers the Chef Infra Server query-parameter filters on
// GET /users: exact-match by email and external_authentication_uid, an empty
// map for no match, and the full list when no filter is given.
func TestUserListFiltering(t *testing.T) {
	srv, _ := newTestAPI(t)

	do(t, "POST", srv.URL+"/users", userBody(`{"name":"alice","email":"alice@example.com"}`))
	do(t, "POST", srv.URL+"/users", userBody(`{"name":"bob","email":"bob@example.com","external_authentication_uid":"ldap-bob"}`))

	decode := func(body string) map[string]string {
		t.Helper()
		var m map[string]string
		if err := json.Unmarshal([]byte(body), &m); err != nil {
			t.Fatalf("body not a JSON map: %v (%s)", err, body)
		}
		return m
	}

	// No filter → all users present.
	_, body := do(t, "GET", srv.URL+"/users", "")
	all := decode(body)
	if _, ok := all["alice"]; !ok {
		t.Fatalf("unfiltered list missing alice: %s", body)
	}
	if _, ok := all["bob"]; !ok {
		t.Fatalf("unfiltered list missing bob: %s", body)
	}

	// Filter by email → exactly that user.
	_, body = do(t, "GET", srv.URL+"/users?email=alice@example.com", "")
	got := decode(body)
	if len(got) != 1 || got["alice"] == "" {
		t.Fatalf("email filter = %s, want only alice", body)
	}

	// Filter by external_authentication_uid → exactly that user.
	_, body = do(t, "GET", srv.URL+"/users?external_authentication_uid=ldap-bob", "")
	got = decode(body)
	if len(got) != 1 || got["bob"] == "" {
		t.Fatalf("uid filter = %s, want only bob", body)
	}

	// Non-existent email → {} (200, not an error).
	resp, body := do(t, "GET", srv.URL+"/users?email=nobody@example.com", "")
	if resp.StatusCode != 200 {
		t.Fatalf("unknown email status = %d, want 200", resp.StatusCode)
	}
	if strings.TrimSpace(body) != "{}" {
		t.Fatalf("unknown email body = %q, want {}", body)
	}

	// Non-existent external_authentication_uid → {}.
	_, body = do(t, "GET", srv.URL+"/users?external_authentication_uid=missing", "")
	if strings.TrimSpace(body) != "{}" {
		t.Fatalf("unknown uid body = %q, want {}", body)
	}
}
