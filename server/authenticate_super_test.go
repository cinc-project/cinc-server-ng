package server

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// TestAuthenticateUserSuperuserOnly verifies that POST /authenticate_user is
// restricted to the superuser. The bootstrap admin can validate a user's
// password, but a request signed by an ordinary (non-admin) user is forbidden.
func TestAuthenticateUserSuperuserOnly(t *testing.T) {
	srv := startServer(t, Options{})

	// As the admin, create a global user with a password and capture the
	// generated private key so we can sign requests as that user.
	resp, err := http.DefaultClient.Do(signed(t, srv, "POST", srv.URL()+"/users",
		validUserBody(t, `{"name":"bob","password":"b0b-pw"}`)))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create user = %d: %s", resp.StatusCode, raw)
	}
	var created struct {
		ChefKey struct {
			PrivateKey string `json:"private_key"`
		} `json:"chef_key"`
	}
	json.Unmarshal(raw, &created)
	if created.ChefKey.PrivateKey == "" {
		t.Fatalf("create user returned no private key: %s", raw)
	}

	// The superuser authenticates the user with the correct password.
	resp, err = http.DefaultClient.Do(signed(t, srv, "POST", srv.URL()+"/authenticate_user",
		`{"username":"bob","password":"b0b-pw"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin authenticate = %d, want 200", resp.StatusCode)
	}

	// A non-admin caller (bob signing for himself) is forbidden.
	resp, err = http.DefaultClient.Do(signedAs(t, "bob", []byte(created.ChefKey.PrivateKey),
		"POST", srv.URL()+"/authenticate_user", `{"username":"bob","password":"b0b-pw"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("non-admin authenticate = %d, want 403", resp.StatusCode)
	}
}
