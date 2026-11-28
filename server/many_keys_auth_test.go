package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

// An actor may hold any number of keys, as on Chef Infra Server, including one
// public key under many names. Each request is checked against all of them,
// and must authenticate on whichever one signed it, wherever it sits in the
// list, and on none of them fail with the one authentication message.
func TestActorWithManyKeysAuthenticatesOnAnyOfThem(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}})
	base := srv.URL() + "/organizations/acme"
	defKey := createClientAndKey(t, srv, base, "web01")
	keys := base + "/clients/web01/keys"

	sharedPriv, sharedPub := newKeyPair(t)
	for i := range 20 {
		body, _ := json.Marshal(map[string]string{
			"name": fmt.Sprintf("shared%02d", i), "public_key": sharedPub, "expiration_date": "infinity",
		})
		addKey(t, srv, keys, string(body))
	}
	last := addKey(t, srv, keys, `{"name":"zz-last","create_key":true,"expiration_date":"infinity"}`)
	stranger, _ := newKeyPair(t)

	// A body well past the size of the headers, so it is the signing string's
	// dominant input.
	payload := `{"name":"n1","json_class":"Chef::Node","chef_type":"node","normal":{"pad":"` +
		strings.Repeat("x", 512<<10) + `"}}`

	// Baseline: a key the client does not hold is refused, with the one
	// message every failed authentication gets.
	resp, err := http.DefaultClient.Do(signedAs(t, "web01", stranger, "POST", base+"/nodes", payload))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	wantAuth(t, "unregistered key", resp.StatusCode, 401)
	want := `{"error":["Failed to authenticate as 'web01'. Ensure that your node_name and client key are correct."]}` + "\n"
	if string(raw) != want {
		t.Fatalf("refusal body = %q, want %q", raw, want)
	}

	wantAuth(t, "default key", statusOf(t, signedAs(t, "web01", defKey, "GET", base+"/nodes", "")), 200)
	wantAuth(t, "key held under many names", statusOf(t, signedAs(t, "web01", sharedPriv, "GET", base+"/nodes", "")), 200)
	wantAuth(t, "last key, with a body",
		statusOf(t, signedAs(t, "web01", last, "POST", base+"/nodes", payload)), 201)
}
