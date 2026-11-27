package server

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// A user may rename itself (PUT /users/{self}), so it can take the name of
// any client. These tests pin that answering to a client's name gives a user
// none of that client's identity: not through the web UI, and not by holding
// the client's public key, which anyone may read.

// statusBody sends req and returns its status and body.
func statusBody(t *testing.T, req *http.Request) (int, string) {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

// A web-UI request acts for a user, never for a client: when no user of the
// name can sign, it is refused rather than run as the same-named client.
func TestWebUIRequestNeverRunsAsClient(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	acme := srv.URL() + "/organizations/acme"
	malloryKey := []byte(createUser(t, srv, `{"name":"mallory"}`))

	// Baseline: mallory is in no org, so the console cannot act for her in
	// acme.
	mustStatus(t, webuiSignedAs(t, srv, "mallory", "GET", acme+"/clients", ""), http.StatusForbidden)

	// A web request naming only a client is refused, as erchef refuses a
	// requestor it cannot find.
	code, body := statusBody(t, webuiSignedAs(t, srv, "acme-validator", "GET", acme+"/clients", ""))
	if code != http.StatusUnauthorized {
		t.Fatalf("webui as client acme-validator = %d (%s), want 401", code, body)
	}
	want := `{"error":["Failed to authenticate as 'acme-validator'. Ensure that your node_name and client key are correct."]}`
	if !jsonEqual(t, body, want) {
		t.Errorf("webui as client body = %s, want %s", body, want)
	}

	// mallory takes the validator's name and drops her key.
	mustStatus(t, signedAs(t, "mallory", malloryKey, "PUT", srv.URL()+"/users/mallory",
		validUserBody(t, `{"name":"acme-validator"}`)), http.StatusCreated)
	mustStatus(t, signedAs(t, "acme-validator", malloryKey, "DELETE",
		srv.URL()+"/users/acme-validator/keys/default", ""), http.StatusOK)

	// Her console session must not become the validator client.
	for _, req := range []*http.Request{
		webuiSignedAs(t, srv, "acme-validator", "GET", acme+"/clients", ""),
		webuiSignedAs(t, srv, "acme-validator", "POST", acme+"/clients", `{"name":"rogue","create_key":true}`),
	} {
		if code, body := statusBody(t, req); code != http.StatusUnauthorized {
			t.Errorf("webui %s %s as keyless user named like the validator = %d (%s), want 401",
				req.Method, req.URL.Path, code, body)
		}
	}
	mustStatus(t, signed(t, srv, "GET", acme+"/clients/rogue", ""), http.StatusNotFound)

	// The validator itself still works.
	createClientAndKey(t, srv, acme, "web01")
}

func jsonEqual(t *testing.T, got, want string) bool {
	t.Helper()
	var g, w any
	if err := json.Unmarshal([]byte(got), &g); err != nil {
		return false
	}
	if err := json.Unmarshal([]byte(want), &w); err != nil {
		t.Fatal(err)
	}
	gb, _ := json.Marshal(g)
	wb, _ := json.Marshal(w)
	return string(gb) == string(wb)
}

// keyBody is a keys-API body giving key name the public key pub.
func keyBody(t *testing.T, name, pub string) string {
	t.Helper()
	b, err := json.Marshal(map[string]string{"name": name, "public_key": pub, "expiration_date": "infinity"})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A user renamed onto a client's name may not take the client's public key, or
// every request the client signs would authenticate as the user (users are
// tried first).
func TestUserCannotTakeSameNamedClientsKey(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	acme := srv.URL() + "/organizations/acme"
	clientKey := createClientAndKey(t, srv, acme, "web01")
	clientPub := publicKeyOf(t, srv, acme+"/clients/web01")
	malloryKey := []byte(createUser(t, srv, `{"name":"mallory"}`))

	// Baseline: the client authenticates as itself.
	mustStatus(t, signedAs(t, "web01", clientKey, "GET", acme+"/clients/web01", ""), http.StatusOK)

	mustStatus(t, signedAs(t, "mallory", malloryKey, "PUT", srv.URL()+"/users/mallory",
		validUserBody(t, `{"name":"web01"}`)), http.StatusCreated)
	users := srv.URL() + "/users/web01"

	// Adding the client's key, or rotating a key to it, is refused.
	mustStatus(t, signedAs(t, "web01", malloryKey, "POST", users+"/keys", keyBody(t, "stolen", clientPub)), http.StatusConflict)
	mustStatus(t, signedAs(t, "web01", malloryKey, "PUT", users+"/keys/default", `{"public_key":`+jsonString(clientPub)+`}`), http.StatusConflict)
	mustStatus(t, signedV0(t, "web01", malloryKey, "PUT", users,
		validUserBody(t, `{"name":"web01","public_key":`+jsonString(clientPub)+`}`)), http.StatusConflict)

	// The client still signs as itself, with its own grants.
	mustStatus(t, signedAs(t, "web01", clientKey, "GET", acme+"/clients/web01", ""), http.StatusOK)
	mustStatus(t, signedAs(t, "web01", clientKey, "POST", acme+"/nodes", `{"name":"web01"}`), http.StatusCreated)
}

// The other orders: taking the key under another name and then the client's
// name, or creating a user with the client's name and key, are refused too.
func TestUserCannotRenameOrCreateOntoClientsKey(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	acme := srv.URL() + "/organizations/acme"
	clientKey := createClientAndKey(t, srv, acme, "web01")
	clientPub := publicKeyOf(t, srv, acme+"/clients/web01")
	malloryKey := []byte(createUser(t, srv, `{"name":"mallory"}`))

	// Holding the key under an unrelated name is harmless, so it is allowed.
	mustStatus(t, signedAs(t, "mallory", malloryKey, "POST", srv.URL()+"/users/mallory/keys",
		keyBody(t, "stolen", clientPub)), http.StatusCreated)
	// The rename that would make it the client's is refused.
	code, body := statusBody(t, signedAs(t, "mallory", malloryKey, "PUT", srv.URL()+"/users/mallory", validUserBody(t, `{"name":"web01"}`)))
	if code != http.StatusConflict {
		t.Fatalf("rename onto a client holding one of the user's keys = %d (%s), want 409", code, body)
	}
	mustStatus(t, signedAs(t, "web01", clientKey, "GET", acme+"/clients/web01", ""), http.StatusOK)

	// Nor may a user be created with the client's name and key.
	mustStatus(t, signed(t, srv, "POST", srv.URL()+"/users",
		validUserBody(t, `{"name":"web01","public_key":`+jsonString(clientPub)+`}`)), http.StatusConflict)

	// A user of the name with a key of its own is fine.
	createUser(t, srv, `{"name":"web01"}`)
	mustStatus(t, signedAs(t, "web01", clientKey, "GET", acme+"/clients/web01", ""), http.StatusOK)
}

// Symmetrically, a client may not be given a same-named user's key, and a
// client may not be renamed onto a user holding one of its keys.
func TestClientCannotTakeSameNamedUsersKey(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	acme := srv.URL() + "/organizations/acme"
	createUser(t, srv, `{"name":"alice"}`)
	alicePub := publicKeyOf(t, srv, srv.URL()+"/users/alice")

	mustStatus(t, signed(t, srv, "POST", acme+"/clients",
		`{"name":"alice","public_key":`+jsonString(alicePub)+`}`), http.StatusConflict)

	createClientAndKey(t, srv, acme, "alice")
	mustStatus(t, signed(t, srv, "POST", acme+"/clients/alice/keys", keyBody(t, "stolen", alicePub)), http.StatusConflict)
	mustStatus(t, signed(t, srv, "PUT", acme+"/clients/alice/keys/default",
		`{"public_key":`+jsonString(alicePub)+`}`), http.StatusConflict)

	// A client holding alice's key under another name may not take hers. (A
	// renamed client keeps its keys other than the default.)
	mustStatus(t, signed(t, srv, "DELETE", acme+"/clients/alice", ""), http.StatusOK)
	createClientAndKey(t, srv, acme, "bob")
	mustStatus(t, signed(t, srv, "POST", acme+"/clients/bob/keys", keyBody(t, "extra", alicePub)), http.StatusCreated)
	mustStatus(t, signed(t, srv, "PUT", acme+"/clients/bob", `{"name":"alice"}`), http.StatusConflict)
	mustStatus(t, signed(t, srv, "PUT", acme+"/clients/bob", `{"name":"carol"}`), http.StatusCreated)
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
