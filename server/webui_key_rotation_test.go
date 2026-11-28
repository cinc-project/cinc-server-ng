package server

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

// With no WebUIKey configured, the webui key is the bootstrap admin's key: the
// keys the admin can currently sign with, read when the request arrives. So a
// key the admin rotates away, deletes or lets expire stops verifying web
// requests too, and a console moved to the admin's new key keeps working.
func TestDefaultWebUIKeyFollowsAdminKeyRotation(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}})
	createUser(t, srv, `{"name":"bob"}`)
	probe := srv.URL() + "/organizations/acme/nodes"
	oldKey := srv.AdminKey()

	// Baseline: the admin's key signs web requests for any user.
	wantAuth(t, "web as bob, admin key", statusOf(t, webuiSignedWith(t, oldKey, "bob", "GET", probe, "")), 200)
	wantAuth(t, "web as pivotal, admin key", statusOf(t, webuiSignedWith(t, oldKey, "pivotal", "GET", probe, "")), 200)
	if !srv.AdminKeyCurrent() {
		t.Fatal("AdminKeyCurrent = false before any rotation")
	}

	// Rotate: add a new key, then delete the bootstrap one.
	newKey := addKey(t, srv, srv.URL()+"/users/pivotal/keys", `{"name":"k2","create_key":true,"expiration_date":"infinity"}`)
	if code, raw := adminDo(t, srv, "DELETE", srv.URL()+"/users/pivotal/keys/default", ""); code != 200 {
		t.Fatalf("delete default key = %d: %s", code, raw)
	}

	wantAuth(t, "web as bob, retired key", statusOf(t, webuiSignedWith(t, oldKey, "bob", "GET", probe, "")), 401)
	wantAuth(t, "web as pivotal, retired key", statusOf(t, webuiSignedWith(t, oldKey, "pivotal", "GET", probe, "")), 401)
	wantAuth(t, "web as bob, new key", statusOf(t, webuiSignedWith(t, newKey, "bob", "GET", probe, "")), 200)
	if srv.AdminKeyCurrent() {
		t.Error("AdminKeyCurrent = true after the admin's bootstrap key was deleted")
	}
}

// An expired admin key no longer verifies web requests.
func TestDefaultWebUIKeyStopsAtExpiry(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}})
	createUser(t, srv, `{"name":"bob"}`)
	probe := srv.URL() + "/organizations/acme/nodes"
	oldKey := srv.AdminKey()
	wantAuth(t, "web as bob, admin key", statusOf(t, webuiSignedWith(t, oldKey, "bob", "GET", probe, "")), 200)

	newKey := addKey(t, srv, srv.URL()+"/users/pivotal/keys", `{"name":"k2","create_key":true,"expiration_date":"infinity"}`)
	past := time.Now().Add(-time.Hour).UTC().Format("2006-01-02T15:04:05Z")
	body, _ := json.Marshal(map[string]string{"expiration_date": past})
	if code, raw := adminDo(t, srv, "PUT", srv.URL()+"/users/pivotal/keys/default", string(body)); code != 200 && code != 201 {
		t.Fatalf("expire default key = %d: %s", code, raw)
	}

	wantAuth(t, "web as bob, expired key", statusOf(t, webuiSignedWith(t, oldKey, "bob", "GET", probe, "")), 401)
	wantAuth(t, "web as bob, new key", statusOf(t, webuiSignedWith(t, newKey, "bob", "GET", probe, "")), 200)
	if srv.AdminKeyCurrent() {
		t.Error("AdminKeyCurrent = true after the admin's bootstrap key expired")
	}
}

// A v0 PUT /users/pivotal with private_key: true replaces the admin's key; the
// key it replaced stops verifying web requests and the one it returns starts.
func TestDefaultWebUIKeyFollowsV0KeyRegeneration(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}})
	createUser(t, srv, `{"name":"bob"}`)
	probe := srv.URL() + "/organizations/acme/nodes"
	oldKey := srv.AdminKey()
	wantAuth(t, "web as bob, admin key", statusOf(t, webuiSignedWith(t, oldKey, "bob", "GET", probe, "")), 200)

	resp, err := http.DefaultClient.Do(signedAt(t, srv, "0", "PUT", srv.URL()+"/users/pivotal",
		validUserBody(t, `{"name":"pivotal","private_key":true}`)))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		PrivateKey string `json:"private_key"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	if resp.StatusCode != 200 || out.PrivateKey == "" {
		t.Fatalf("regenerate admin key = %d, private key returned: %v", resp.StatusCode, out.PrivateKey != "")
	}

	wantAuth(t, "web as bob, replaced key", statusOf(t, webuiSignedWith(t, oldKey, "bob", "GET", probe, "")), 401)
	wantAuth(t, "web as bob, regenerated key", statusOf(t, webuiSignedWith(t, []byte(out.PrivateKey), "bob", "GET", probe, "")), 200)
}

// An explicitly configured webui key is unaffected by the admin's keys: it
// keeps verifying after the admin rotates, and the admin's keys never do.
func TestExplicitWebUIKeyIgnoresAdminKeys(t *testing.T) {
	webuiPriv, webuiPub := newKeyPair(t)
	srv := startServer(t, Options{Orgs: []string{"acme"}, WebUIKey: []byte(webuiPub)})
	createUser(t, srv, `{"name":"bob"}`)
	probe := srv.URL() + "/organizations/acme/nodes"
	adminKey := srv.AdminKey()

	wantAuth(t, "web as bob, webui key", statusOf(t, webuiSignedWith(t, webuiPriv, "bob", "GET", probe, "")), 200)
	wantAuth(t, "web as bob, admin key", statusOf(t, webuiSignedWith(t, adminKey, "bob", "GET", probe, "")), 401)

	newKey := addKey(t, srv, srv.URL()+"/users/pivotal/keys", `{"name":"k2","create_key":true,"expiration_date":"infinity"}`)
	if code, raw := adminDo(t, srv, "DELETE", srv.URL()+"/users/pivotal/keys/default", ""); code != 200 {
		t.Fatalf("delete default key = %d: %s", code, raw)
	}
	wantAuth(t, "web as bob, webui key after rotation", statusOf(t, webuiSignedWith(t, webuiPriv, "bob", "GET", probe, "")), 200)
	wantAuth(t, "web as bob, admin's new key", statusOf(t, webuiSignedWith(t, newKey, "bob", "GET", probe, "")), 401)
}

// The default webui key is the superuser's: once the admin user loses its
// superuser flag, its keys stop verifying web requests.
func TestDefaultWebUIKeyRequiresSuperuser(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}})
	createUser(t, srv, `{"name":"bob"}`)
	probe := srv.URL() + "/organizations/acme/nodes"
	key := srv.AdminKey()
	wantAuth(t, "web as bob, admin key", statusOf(t, webuiSignedWith(t, key, "bob", "GET", probe, "")), 200)

	if code, raw := adminDo(t, srv, "PUT", srv.URL()+"/users/pivotal",
		validUserBody(t, `{"name":"pivotal","admin":false}`)); code != 200 {
		t.Fatalf("drop admin flag = %d: %s", code, raw)
	}
	wantAuth(t, "web as bob, demoted admin's key", statusOf(t, webuiSignedWith(t, key, "bob", "GET", probe, "")), 401)
}
