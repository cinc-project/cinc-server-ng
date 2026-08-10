package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/tas50/cinc-server-ng/internal/api"
	"github.com/tas50/cinc-server-ng/internal/store"
)

// A global user loaded with a "password" field has it stashed out-of-band (so
// authenticate_user can validate it) and stripped from the stored record (so it
// is never returned) — matching POST /users.
func TestLoadStashesUserPassword(t *testing.T) {
	dir := t.TempDir()
	usersDir := filepath.Join(dir, "users")
	if err := os.MkdirAll(usersDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(usersDir, "dana.json"),
		[]byte(`{"username":"dana","password":"d4na","public_key":"x"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	st := store.New()
	if _, err := Load(st, dir); err != nil {
		t.Fatalf("load: %v", err)
	}

	pw, ok, err := st.Global().Get(api.PasswordsCollection, "dana")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || string(pw) != "d4na" {
		t.Fatalf("password not stashed: ok=%v pw=%q", ok, pw)
	}

	raw, ok, err := st.Global().Get("users", "dana")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("user not stored")
	}
	var u map[string]any
	if err := json.Unmarshal(raw, &u); err != nil {
		t.Fatal(err)
	}
	if _, leaked := u["password"]; leaked {
		t.Fatal("password leaked into stored user record")
	}
}
