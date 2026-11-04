package api

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/cinc-project/cinc-server-ng/internal/store"
	"github.com/cinc-project/cinc-server-ng/internal/store/sqlite"
)

// The production cost: OWASP's 2023 guidance for PBKDF2-HMAC-SHA256.
func TestDefaultPasswordIterations(t *testing.T) {
	if DefaultPasswordIterations != 600_000 {
		t.Fatalf("DefaultPasswordIterations = %d, want 600000", DefaultPasswordIterations)
	}
}

func TestHashPasswordRoundTrip(t *testing.T) {
	h, err := HashPassword("s3cret")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(h), "s3cret") {
		t.Fatalf("hash contains the password: %s", h)
	}
	if !strings.HasPrefix(string(h), "pbkdf2-sha256$") {
		t.Fatalf("hash is not self-describing: %s", h)
	}
	if !IsPasswordHash(h) {
		t.Fatalf("IsPasswordHash(%s) = false", h)
	}
	if !VerifyPassword(h, "s3cret") {
		t.Fatal("correct password rejected")
	}
	if VerifyPassword(h, "s3cret ") || VerifyPassword(h, "") {
		t.Fatal("wrong password accepted")
	}
}

func TestHashPasswordIsSalted(t *testing.T) {
	a, _ := HashPassword("same")
	b, _ := HashPassword("same")
	if string(a) == string(b) {
		t.Fatalf("two hashes of the same password are identical: %s", a)
	}
}

// A hash records its own cost, so changing the cost for new hashes never
// locks out a user hashed under the old one.
func TestVerifyPasswordUsesStoredIterations(t *testing.T) {
	h, _ := HashPassword("pw")
	restore := SetPasswordIterations(2 * passwordIterations())
	defer restore()
	if !VerifyPassword(h, "pw") {
		t.Fatal("hash made under the previous cost no longer verifies")
	}
}

// A stored value that is not a well-formed hash is a plain-text password
// written by an older version, and still verifies until it is upgraded.
func TestVerifyPasswordLegacyPlaintext(t *testing.T) {
	for _, stored := range []string{"old-password", "pbkdf2-sha256$not-a-hash"} {
		if IsPasswordHash([]byte(stored)) {
			t.Fatalf("IsPasswordHash(%q) = true", stored)
		}
		if !VerifyPassword([]byte(stored), stored) {
			t.Fatalf("legacy %q rejected", stored)
		}
		if VerifyPassword([]byte(stored), stored+"x") {
			t.Fatalf("wrong password accepted for legacy %q", stored)
		}
	}
}

func TestVerifyPasswordRejectsExcessiveIterations(t *testing.T) {
	stored := []byte("pbkdf2-sha256$2000000000$c2FsdHNhbHRzYWx0c2FsdA$a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2U")
	if IsPasswordHash(stored) {
		t.Fatal("a hash with an absurd iteration count must not parse")
	}
}

func TestStashPasswordStoresHash(t *testing.T) {
	st := store.New()
	obj := map[string]any{"name": "alice", "password": "s3cret"}
	if ok, err := StashPassword(st.Global(), "alice", obj); err != nil || !ok {
		t.Fatalf("StashPassword = %v, %v", ok, err)
	}
	stored, ok, err := st.Global().Get(PasswordsCollection, "alice")
	if err != nil || !ok {
		t.Fatalf("password not stored: %v %v", ok, err)
	}
	if !IsPasswordHash(stored) || strings.Contains(string(stored), "s3cret") {
		t.Fatalf("stored password is not a hash: %s", stored)
	}
	if !VerifyPassword(stored, "s3cret") {
		t.Fatal("stored hash does not verify")
	}
	if _, leaked := obj["password"]; leaked {
		t.Fatal("password left on the actor object")
	}
}

func TestUpgradePasswords(t *testing.T) {
	backends := map[string]func(t *testing.T) *store.Store{
		"memory": func(t *testing.T) *store.Store { return store.New() },
		"sqlite": func(t *testing.T) *store.Store {
			be, err := sqlite.Open(filepath.Join(t.TempDir(), "pw.db"))
			if err != nil {
				t.Fatal(err)
			}
			st := store.NewWithBackend(be)
			t.Cleanup(func() { st.Close() })
			return st
		},
	}
	for name, open := range backends {
		t.Run(name, func(t *testing.T) {
			st := open(t)
			g := st.Global()
			if err := g.Put(PasswordsCollection, "legacy", []byte("plain-pw")); err != nil {
				t.Fatal(err)
			}
			already, _ := HashPassword("hashed-pw")
			if err := g.Put(PasswordsCollection, "modern", already); err != nil {
				t.Fatal(err)
			}

			n, err := UpgradePasswords(g)
			if err != nil {
				t.Fatal(err)
			}
			if n != 1 {
				t.Fatalf("upgraded %d passwords, want 1", n)
			}
			got, _, _ := g.Get(PasswordsCollection, "legacy")
			if !IsPasswordHash(got) || !VerifyPassword(got, "plain-pw") {
				t.Fatalf("legacy password not upgraded to a verifying hash: %s", got)
			}
			kept, _, _ := g.Get(PasswordsCollection, "modern")
			if string(kept) != string(already) {
				t.Fatal("an existing hash was rewritten")
			}

			if n, err := UpgradePasswords(g); err != nil || n != 0 {
				t.Fatalf("second upgrade = %d, %v; want 0, nil", n, err)
			}
		})
	}
}

// A password set before the upgrade still authenticates through the endpoint.
func TestAuthenticateUserLegacyPlaintext(t *testing.T) {
	srv, st := newTestAPI(t)
	resp, body := do(t, "POST", srv.URL+"/users", userBody(`{"name":"dora","password":"placeholder-pw"}`))
	if resp.StatusCode != 201 {
		t.Fatalf("create user = %d: %s", resp.StatusCode, body)
	}
	if err := st.Global().Put(PasswordsCollection, "dora", []byte("old-password")); err != nil {
		t.Fatal(err)
	}
	resp, body = do(t, "POST", srv.URL+"/authenticate_user", `{"name":"dora","password":"old-password"}`)
	if resp.StatusCode != 200 {
		t.Fatalf("authenticate (legacy) = %d: %s", resp.StatusCode, body)
	}
	resp, _ = do(t, "POST", srv.URL+"/authenticate_user", `{"name":"dora","password":"placeholder-pw"}`)
	if resp.StatusCode != 401 {
		t.Fatalf("authenticate (stale) = %d, want 401", resp.StatusCode)
	}
}
