package server

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// TestServerAPIVersionRequiresSignature pins erchef's
// oc_chef_wm_server_api_version: it mixes in oc_chef_wm_base's is_authorized
// with allow_all, so any signed requestor gets the supported range, and an
// unsigned request is refused like on any other API route.
func TestServerAPIVersionRequiresSignature(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})

	resp, err := http.Get(srv.URL() + "/server_api_version")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unsigned /server_api_version = %d, want 401; body %s", resp.StatusCode, body)
	}

	code, got := signedBody(t, signed(t, srv, "GET", srv.URL()+"/server_api_version", ""))
	if code != http.StatusOK || strings.TrimSpace(string(got)) != `{"min_api_version":0,"max_api_version":2}` {
		t.Fatalf("signed /server_api_version = %d %s", code, got)
	}

	// Any requestor: a user in no org and no group, too.
	key := createUserKey(t, srv, "mallory")
	code, got = signedBody(t, signedAs(t, "mallory", key, "GET", srv.URL()+"/server_api_version", ""))
	if code != http.StatusOK {
		t.Fatalf("plain user /server_api_version = %d %s", code, got)
	}

	// /_status stays unauthenticated.
	resp, err = http.Get(srv.URL() + "/_status")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unsigned /_status = %d, want 200", resp.StatusCode)
	}
}

// TestAPIVersionCheckedBeforeSignature pins erchef's order: the version header
// is judged in service_available, which webmachine runs ahead of
// malformed_request and is_authorized, where the signature is checked. An
// unsigned request with an unacceptable version is a 406, not a 401, and every
// response, a 401 included, carries the negotiation header.
func TestAPIVersionCheckedBeforeSignature(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}})

	for _, version := range []string{"abc", "99"} {
		req, _ := http.NewRequest("GET", srv.URL()+"/organizations/acme/nodes", nil)
		req.Header.Set("X-Ops-Server-API-Version", version)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotAcceptable {
			t.Fatalf("unsigned, version %q = %d, want 406; body %s", version, resp.StatusCode, body)
		}
	}

	req, _ := http.NewRequest("GET", srv.URL()+"/organizations/acme/nodes", nil)
	req.Header.Set("X-Ops-Server-API-Version", "1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unsigned, version 1 = %d, want 401", resp.StatusCode)
	}
	want := `{"min_version":"0","max_version":"2","request_version":"1","response_version":"1"}`
	if got := resp.Header.Get("X-Ops-Server-API-Version"); got != want {
		t.Fatalf("401 version header = %s, want %s", got, want)
	}
}
