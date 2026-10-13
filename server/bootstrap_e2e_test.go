package server

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

func mustStatus(t *testing.T, req *http.Request, want int) {
	t.Helper()
	got := statusOf(t, req)
	if got != want {
		t.Fatalf("%s %s = %d, want %d", req.Method, req.URL.Path, got, want)
	}
}

// createClientAndKey registers a client via the validator and returns its
// generated private key — the chef-client "first contact" step.
func createClientAndKey(t *testing.T, srv *Server, base, name string) []byte {
	t.Helper()
	resp, err := http.DefaultClient.Do(
		signedAs(t, "acme-validator", srv.ValidatorKey("acme"), "POST", base+"/clients", `{"name":"`+name+`","create_key":true}`))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("validator create client %q = %d: %s", name, resp.StatusCode, body)
	}
	var created struct {
		ChefKey struct {
			PrivateKey string `json:"private_key"`
		} `json:"chef_key"`
	}
	if err := json.Unmarshal(body, &created); err != nil || created.ChefKey.PrivateKey == "" {
		t.Fatalf("no client key in create response: %s", body)
	}
	return []byte(created.ChefKey.PrivateKey)
}

// TestZeroToWorkingClientBootstrap is the end-to-end "zero to working" flow with
// ACL enforcement ON (the secured posture): from a freshly created organization,
// a validator registers a client, and that client runs the full chef-client
// lifecycle — create its node, read it, update it (save), and read the org data
// it needs to converge — while still being denied access to objects it does not
// own. If this passes, ACL enforcement is safe to run by default.
func TestZeroToWorkingClientBootstrap(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	base := srv.URL() + "/organizations/acme"

	// The admin seeds org data the client will read while converging.
	mustStatus(t, signed(t, srv, "POST", base+"/roles", `{"name":"web"}`), 201)
	mustStatus(t, signed(t, srv, "POST", base+"/environments", `{"name":"staging"}`), 201)

	// 1. Validator registers the client (first contact).
	clientKey := createClientAndKey(t, srv, base, "node1")

	// 2. The client creates its own node...
	mustStatus(t, signedAs(t, "node1", clientKey, "POST", base+"/nodes", `{"name":"node1"}`), 201)
	// 3. ...reads it back...
	mustStatus(t, signedAs(t, "node1", clientKey, "GET", base+"/nodes/node1", ""), 200)
	// 4. ...and updates it, as chef-client does at the end of every run.
	mustStatus(t, signedAs(t, "node1", clientKey, "PUT", base+"/nodes/node1",
		`{"name":"node1","run_list":["role[web]"],"normal":{"k":"v"}}`), 200)

	// 5. The client reads the org data it needs to converge.
	mustStatus(t, signedAs(t, "node1", clientKey, "GET", base+"/roles/web", ""), 200)
	mustStatus(t, signedAs(t, "node1", clientKey, "GET", base+"/environments/staging", ""), 200)

	// 6. Enforcement is real: the client is not a superuser and cannot modify a
	//    node it does not own.
	mustStatus(t, signed(t, srv, "POST", base+"/nodes", `{"name":"other"}`), 201) // admin makes another node
	mustStatus(t, signedAs(t, "node1", clientKey, "PUT", base+"/nodes/other",
		`{"name":"other","normal":{"x":1}}`), 403)
}
