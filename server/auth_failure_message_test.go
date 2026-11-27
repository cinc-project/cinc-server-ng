package server

import (
	"bytes"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// Every authentication failure that turns on whether the named actor exists
// answers with one body, so an unsigned or garbage-signed request cannot tell
// a real user or client from a name nobody holds. Each case asks the same
// question about one name before and after the actor exists, so the bodies
// must match byte for byte.
func TestAuthFailuresDoNotRevealWhetherActorExists(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	acme := srv.URL() + "/organizations/acme"
	garbage, _ := newKeyPair(t)

	failure := func(name string, req *http.Request) string {
		t.Helper()
		code, body := statusBody(t, req)
		if code != http.StatusUnauthorized {
			t.Fatalf("%s: status = %d (%s), want 401", name, code, body)
		}
		return body
	}
	want := func(name string) string {
		return `{"error":["Failed to authenticate as '` + name + `'. Ensure that your node_name and client key are correct."]}` + "\n"
	}
	same := func(what, before, after, name string) {
		t.Helper()
		if before != after {
			t.Errorf("%s: body before the actor exists %q, after %q; want them identical", what, before, after)
		}
		if after != want(name) {
			t.Errorf("%s: body = %q, want %q", what, after, want(name))
		}
	}

	// A global user, asked about on an org route and at the server root.
	userOrgBefore := failure("alice before", signedAs(t, "alice", garbage, "GET", acme+"/nodes", ""))
	userRootBefore := failure("alice root before", signedAs(t, "alice", garbage, "GET", srv.URL()+"/users", ""))
	createUser(t, srv, `{"name":"alice"}`)
	same("user, bad signature", userOrgBefore,
		failure("alice after", signedAs(t, "alice", garbage, "GET", acme+"/nodes", "")), "alice")
	same("user at the root, bad signature", userRootBefore,
		failure("alice root after", signedAs(t, "alice", garbage, "GET", srv.URL()+"/users", "")), "alice")

	// An org client, and a web-UI request naming it (which acts only for users).
	clientBefore := failure("web01 before", signedAs(t, "web01", garbage, "GET", acme+"/nodes", ""))
	webBefore := failure("webui web01 before", webuiSignedAs(t, srv, "web01", "GET", acme+"/nodes", ""))
	createClientAndKey(t, srv, acme, "web01")
	same("client, bad signature", clientBefore,
		failure("web01 after", signedAs(t, "web01", garbage, "GET", acme+"/nodes", "")), "web01")
	same("web UI naming a client", webBefore,
		failure("webui web01 after", webuiSignedAs(t, srv, "web01", "GET", acme+"/nodes", "")), "web01")

	// A web-UI request for a real user, signed with something other than the
	// webui key: refused the way a name nobody holds is, whichever of the
	// name and the webui signature is checked first.
	webBad := func(name string) *http.Request {
		req := signedAs(t, name, garbage, "GET", acme+"/nodes", "")
		req.Header.Set("X-Ops-Request-Source", "web")
		return req
	}
	webBadBefore := failure("webui erin before", webBad("erin"))
	createUser(t, srv, `{"name":"erin"}`)
	same("web UI, bad webui signature", webBadBefore, failure("webui erin after", webBad("erin")), "erin")

	// A client whose every key has expired, signing with one of them.
	expiredBefore := failure("db01 before", signedAs(t, "db01", garbage, "GET", acme+"/nodes", ""))
	createClientAndKey(t, srv, acme, "db01")
	expired := addKey(t, srv, acme+"/clients/db01/keys", `{"name":"old","create_key":true,"expiration_date":"2020-01-01T00:00:00Z"}`)
	if code, raw := adminDo(t, srv, "DELETE", acme+"/clients/db01/keys/default", ""); code != http.StatusOK {
		t.Fatalf("delete db01 default key = %d: %s", code, raw)
	}
	same("client with only expired keys", expiredBefore,
		failure("db01 after", signedAs(t, "db01", expired, "GET", acme+"/nodes", "")), "db01")

	// A request with a body: the body is read and hashed whether or not the
	// actor exists, and the answer is still the same.
	postBefore := failure("bob post before", signedAs(t, "bob", garbage, "POST", acme+"/nodes", `{"name":"n1"}`))
	createUser(t, srv, `{"name":"bob"}`)
	same("user, bad signature with a body", postBefore,
		failure("bob post after", signedAs(t, "bob", garbage, "POST", acme+"/nodes", `{"name":"n1"}`)), "bob")
}

// Valid signatures still authenticate, for a user and a client alike.
func TestUniformAuthFailureKeepsValidSignaturesWorking(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}})
	acme := srv.URL() + "/organizations/acme"
	carolKey := []byte(createUser(t, srv, `{"name":"carol"}`))
	webKey := createClientAndKey(t, srv, acme, "web02")

	mustStatus(t, signedAs(t, "carol", carolKey, "GET", srv.URL()+"/users/carol", ""), http.StatusOK)
	mustStatus(t, signedAs(t, "web02", webKey, "GET", acme+"/nodes", ""), http.StatusOK)
	mustStatus(t, signedAs(t, "web02", webKey, "POST", acme+"/nodes", `{"name":"n2"}`), http.StatusCreated)
}

// The specific reason a request failed to authenticate goes to the server's
// log, since the client is no longer told.
func TestAuthFailureReasonIsLogged(t *testing.T) {
	var mu sync.Mutex
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&lockedWriter{mu: &mu, w: &buf}, nil))
	srv := startServer(t, Options{Orgs: []string{"acme"}, Logger: logger})
	acme := srv.URL() + "/organizations/acme"
	garbage, _ := newKeyPair(t)
	createUser(t, srv, `{"name":"dave"}`)

	mustStatus(t, signedAs(t, "nobody", garbage, "GET", acme+"/nodes", ""), http.StatusUnauthorized)
	mustStatus(t, signedAs(t, "dave", garbage, "GET", acme+"/nodes", ""), http.StatusUnauthorized)

	mu.Lock()
	logged := buf.String()
	mu.Unlock()
	for _, want := range []string{"actor=nobody", "no such actor", "actor=dave", "signature did not verify"} {
		if !strings.Contains(logged, want) {
			t.Errorf("log lacks %q:\n%s", want, logged)
		}
	}
}

type lockedWriter struct {
	mu *sync.Mutex
	w  *bytes.Buffer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}
