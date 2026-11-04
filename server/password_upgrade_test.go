package server

import (
	"net/http"
	"path/filepath"
	"testing"

	"github.com/cinc-project/cinc-server-ng/internal/api"
)

// TestLegacyPlaintextPasswordHashedOnStart covers a SQLite database written by
// a version that stored passwords as plain text. Restarting on it must replace
// the stored value with a hash, and the user's password must keep working.
func TestLegacyPlaintextPasswordHashedOnStart(t *testing.T) {
	db := filepath.Join(t.TempDir(), "legacy.db")
	opts := Options{Orgs: []string{"acme"}, Storage: "sqlite", DB: db}

	srv1, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv1.Start(); err != nil {
		t.Fatal(err)
	}
	createUser(t, srv1, `{"name":"erin","password":"placeholder"}`)
	// What an older version left in the database.
	if err := srv1.Store().Global().Put(api.PasswordsCollection, "erin", []byte("er1n-pw")); err != nil {
		t.Fatal(err)
	}
	stopServer(t, srv1)

	srv2, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv2.Start(); err != nil {
		t.Fatal(err)
	}
	defer stopServer(t, srv2)

	stored, ok, err := srv2.Store().Global().Get(api.PasswordsCollection, "erin")
	if err != nil || !ok {
		t.Fatalf("password missing after restart: %v %v", ok, err)
	}
	if !api.IsPasswordHash(stored) {
		t.Fatalf("password still stored as plain text after restart: %q", stored)
	}

	login := func(pw string) int {
		return statusOf(t, signed(t, srv2, "POST", srv2.URL()+"/authenticate_user",
			`{"username":"erin","password":"`+pw+`"}`))
	}
	if code := login("er1n-pw"); code != http.StatusOK {
		t.Fatalf("authenticate after upgrade = %d, want 200", code)
	}
	if code := login("wrong"); code != http.StatusUnauthorized {
		t.Fatalf("authenticate with wrong password = %d, want 401", code)
	}
}
