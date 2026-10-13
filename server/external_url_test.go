package server

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestExternalURLNamesEveryReturnedURL(t *testing.T) {
	srv := startServer(t, Options{ExternalURL: "https://chef.example.com/"})

	resp, err := http.DefaultClient.Do(signed(t, srv, "POST", srv.URL()+"/organizations/acme/nodes", `{"name":"web1"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body struct{ URI string }
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	// The trailing slash is dropped so paths join without doubling it.
	if want := "https://chef.example.com/organizations/acme/nodes/web1"; body.URI != want {
		t.Fatalf("uri = %q, want %q", body.URI, want)
	}
}

func TestExternalURLMustBeASchemeAndHost(t *testing.T) {
	for _, bad := range []string{
		"chef.example.com",              // no scheme
		"ftp://chef.example.com",        // a scheme the server is not reached on
		"https://",                      // no host
		"https://chef.example.com/chef", // a path prefix breaks signing: clients sign the path they request
		"https://chef.example.com?x=1",
		"https://chef.example.com#frag",
		"https://user:pw@chef.example.com",
	} {
		if _, err := New(Options{ExternalURL: bad}); err == nil {
			t.Errorf("New(ExternalURL: %q) succeeded, want an error", bad)
		}
	}
}
