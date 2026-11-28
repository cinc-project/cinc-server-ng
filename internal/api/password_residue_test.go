package api

import "testing"

// A deleted user's password must not outlive it: the next user created or
// renamed under that name without a password of its own (an externally
// authenticated user) would otherwise log in with the old one.
func TestDeletedUserPasswordIsNotInherited(t *testing.T) {
	const extAlice = `{"username":"alice","display_name":"A","email":"alice@example.test","external_authentication_uid":"alice"}`
	login := func(t *testing.T, base string) int {
		t.Helper()
		resp, _ := do(t, "POST", base+"/authenticate_user", `{"username":"alice","password":"old-secret"}`)
		return resp.StatusCode
	}
	setup := func(t *testing.T) string {
		t.Helper()
		srv, _ := newTestAPI(t)
		if resp, b := do(t, "POST", srv.URL+"/users", userBody(`{"name":"alice","password":"old-secret"}`)); resp.StatusCode != 201 {
			t.Fatalf("create alice = %d: %s", resp.StatusCode, b)
		}
		if code := login(t, srv.URL); code != 200 {
			t.Fatalf("baseline login = %d, want 200", code)
		}
		if resp, b := do(t, "DELETE", srv.URL+"/users/alice", ""); resp.StatusCode != 200 {
			t.Fatalf("delete alice = %d: %s", resp.StatusCode, b)
		}
		return srv.URL
	}

	t.Run("recreated", func(t *testing.T) {
		base := setup(t)
		if resp, b := do(t, "POST", base+"/users", extAlice); resp.StatusCode != 201 {
			t.Fatalf("create external alice = %d: %s", resp.StatusCode, b)
		}
		if code := login(t, base); code != 401 {
			t.Errorf("login with the deleted user's password = %d, want 401", code)
		}
	})
	t.Run("renamed onto", func(t *testing.T) {
		base := setup(t)
		if resp, b := do(t, "POST", base+"/users", `{"username":"bob","display_name":"B","email":"bob@example.test","external_authentication_uid":"bob"}`); resp.StatusCode != 201 {
			t.Fatalf("create bob = %d: %s", resp.StatusCode, b)
		}
		if resp, b := do(t, "PUT", base+"/users/bob", extAlice); resp.StatusCode != 201 {
			t.Fatalf("rename bob to alice = %d: %s", resp.StatusCode, b)
		}
		if code := login(t, base); code != 401 {
			t.Errorf("login with the deleted user's password = %d, want 401", code)
		}
	})
}

// A stale row (from before deletes removed it) is cleared when a user is
// created without a password.
func TestUserCreateWithoutPasswordClearsStaleRow(t *testing.T) {
	srv, st := newTestAPI(t)
	h, err := HashPassword("old-secret")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Global().Put(PasswordsCollection, "alice", h); err != nil {
		t.Fatal(err)
	}
	if resp, b := do(t, "POST", srv.URL+"/users", `{"username":"alice","display_name":"A","email":"alice@example.test","external_authentication_uid":"alice"}`); resp.StatusCode != 201 {
		t.Fatalf("create = %d: %s", resp.StatusCode, b)
	}
	if resp, _ := do(t, "POST", srv.URL+"/authenticate_user", `{"username":"alice","password":"old-secret"}`); resp.StatusCode != 401 {
		t.Errorf("login with a stale password row = %d, want 401", resp.StatusCode)
	}
}
