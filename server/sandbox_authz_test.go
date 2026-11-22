package server

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// A cookbook file is stored when it is uploaded, before any cookbook write, so
// the sandbox that hands out the upload URL is what has to be authorized.
// erchef requires create on the sandboxes container for both halves of the
// handshake: POST /sandboxes ({create_in_container, sandbox} in
// chef_wm_sandboxes) and PUT /sandboxes/<id> ({container, sandbox, create} in
// chef_wm_named_sandbox). The default container ACL grants that to admins and
// users only, so a client (the validator included) can't upload files.

// sandboxBody is the body knife sends: every checksum maps to null.
func sandboxBody(sums ...string) string {
	parts := make([]string, len(sums))
	for i, s := range sums {
		parts[i] = `"` + s + `":null`
	}
	return `{"checksums":{` + strings.Join(parts, ",") + `}}`
}

func md5Hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// doJSON sends req and returns its status and body.
func doJSON(t *testing.T, req *http.Request) (int, []byte) {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

type sandboxResponse struct {
	SandboxID string `json:"sandbox_id"`
	Checksums map[string]struct {
		URL         string `json:"url"`
		NeedsUpload bool   `json:"needs_upload"`
	} `json:"checksums"`
}

// adminSandbox has the superuser announce sums and returns the sandbox id.
func adminSandbox(t *testing.T, srv *Server, base string, sums ...string) sandboxResponse {
	t.Helper()
	code, raw := doJSON(t, signed(t, srv, "POST", base+"/sandboxes", sandboxBody(sums...)))
	if code != http.StatusCreated {
		t.Fatalf("superuser create sandbox = %d: %s", code, raw)
	}
	var sb sandboxResponse
	if err := json.Unmarshal(raw, &sb); err != nil {
		t.Fatalf("decode sandbox: %v: %s", err, raw)
	}
	return sb
}

func TestSandboxRefusedToValidatorAndClients(t *testing.T) {
	srv, base, bob := memberSetup(t)
	vkey := srv.ValidatorKey("acme")
	nodeKey := createClientAndKey(t, srv, base, "web01")
	sum := md5Hex("payload a validator should not be able to store")

	// Baseline: the request is well formed and a member may make it, so the
	// refusals below are about who asks.
	mustStatus(t, signedAs(t, "bob", bob, "POST", base+"/sandboxes", sandboxBody(md5Hex("baseline"))), http.StatusCreated)

	sb := adminSandbox(t, srv, base, sum)
	for _, actor := range []struct {
		name string
		key  []byte
	}{{"acme-validator", vkey}, {"web01", nodeKey}} {
		code, raw := doJSON(t, signedAs(t, actor.name, actor.key, "POST", base+"/sandboxes", sandboxBody(sum)))
		if code != http.StatusForbidden {
			t.Errorf("%s POST /sandboxes = %d, want 403: %s", actor.name, code, raw)
		}
		code, raw = doJSON(t, signedAs(t, actor.name, actor.key, "PUT", base+"/sandboxes/"+sb.SandboxID, `{"is_completed":true}`))
		if code != http.StatusForbidden {
			t.Errorf("%s PUT /sandboxes/<id> = %d, want 403: %s", actor.name, code, raw)
		}
	}
}

func TestSandboxNeedsCreateOnContainer(t *testing.T) {
	srv, base, bob := memberSetup(t)
	boss := createUserKey(t, srv, "boss")
	mustStatus(t, signed(t, srv, "POST", base+"/users", `{"username":"boss"}`), http.StatusCreated)
	mustStatus(t, signed(t, srv, "PUT", base+"/groups/admins",
		`{"groupname":"admins","actors":{"users":["boss"],"clients":[],"groups":[]}}`), http.StatusOK)

	// With the default container ACL, a member may announce and commit.
	mustStatus(t, signedAs(t, "bob", bob, "POST", base+"/sandboxes", sandboxBody(md5Hex("one"))), http.StatusCreated)

	sb := adminSandbox(t, srv, base, md5Hex("two"))
	narrowCreate(t, srv, base, "sandboxes")
	mustStatus(t, signedAs(t, "bob", bob, "POST", base+"/sandboxes", sandboxBody(md5Hex("two"))), http.StatusForbidden)
	mustStatus(t, signedAs(t, "bob", bob, "PUT", base+"/sandboxes/"+sb.SandboxID, `{"is_completed":true}`), http.StatusForbidden)
	// An org admin still holds create.
	mustStatus(t, signedAs(t, "boss", boss, "POST", base+"/sandboxes", sandboxBody(md5Hex("two"))), http.StatusCreated)
}

// A member and an org admin each upload a cookbook the way knife does:
// sandbox, file store, commit, manifest.
func TestSandboxCookbookUploadByMembersAndAdmins(t *testing.T) {
	srv, base, bob := memberSetup(t)
	boss := createUserKey(t, srv, "boss")
	mustStatus(t, signed(t, srv, "POST", base+"/users", `{"username":"boss"}`), http.StatusCreated)
	mustStatus(t, signed(t, srv, "PUT", base+"/groups/admins",
		`{"groupname":"admins","actors":{"users":["boss"],"clients":[],"groups":[]}}`), http.StatusOK)

	for _, u := range []struct {
		name string
		key  []byte
	}{{"bob", bob}, {"boss", boss}} {
		recipe := "package '" + u.name + "'\n"
		sum := md5Hex(recipe)
		code, raw := doJSON(t, signedAs(t, u.name, u.key, "POST", base+"/sandboxes", sandboxBody(sum)))
		if code != http.StatusCreated {
			t.Fatalf("%s create sandbox = %d: %s", u.name, code, raw)
		}
		var sb sandboxResponse
		if err := json.Unmarshal(raw, &sb); err != nil {
			t.Fatal(err)
		}
		if code, body := rawRequest(t, "PUT", sb.Checksums[sum].URL, recipe); code != http.StatusOK {
			t.Fatalf("%s upload = %d: %s", u.name, code, body)
		}
		mustStatus(t, signedAs(t, u.name, u.key, "PUT", base+"/sandboxes/"+sb.SandboxID, `{"is_completed":true}`), http.StatusOK)
		manifest := `{"name":"cb-` + u.name + `-1.0.0","cookbook_name":"cb-` + u.name + `","version":"1.0.0","metadata":{"version":"1.0.0"},` +
			`"recipes":[{"name":"default.rb","path":"recipes/default.rb","checksum":"` + sum + `","specificity":"default"}]}`
		mustStatus(t, signedAs(t, u.name, u.key, "PUT", base+"/cookbooks/cb-"+u.name+"/1.0.0", manifest), http.StatusCreated)
	}
}

// chef_sandbox:valid_checksum_hash: at least one checksum, each 32 hex
// digits, each mapped to null. chef_wm_malformed renders every failure as
// "Bad checksums!" (the fun_match message), and a body without the field as
// "Field 'checksums' missing" (oc-chef-pedant's sandboxes spec).
func TestSandboxValidatesChecksums(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	base := srv.URL() + "/organizations/acme"
	good := md5Hex("x")
	bad := `{"error":["Bad checksums!"]}`
	cases := []struct {
		name, body, want string
	}{
		{"missing field", `{}`, `{"error":["Field 'checksums' missing"]}`},
		{"empty", `{"checksums":{}}`, bad},
		{"path traversal", `{"checksums":{"../../not-a-checksum":null}}`, bad},
		{"too short", `{"checksums":{"` + good[:31] + `":null}}`, bad},
		{"too long", `{"checksums":{"` + good + `0":null}}`, bad},
		{"not hex", `{"checksums":{"` + strings.Repeat("g", 32) + `":null}}`, bad},
		{"non-null value", `{"checksums":{"` + good + `":"foo"}}`, bad},
		{"true value", `{"checksums":{"` + good + `":true}}`, bad},
		{"one bad among good", `{"checksums":{"` + good + `":null,"nope":null}}`, bad},
		{"array", `{"checksums":["` + good + `"]}`, bad},
		{"null", `{"checksums":null}`, bad},
		{"invalid JSON", `{"checksums":`, `{"error":["invalid JSON"]}`},
	}
	for _, c := range cases {
		code, raw := doJSON(t, signed(t, srv, "POST", base+"/sandboxes", c.body))
		if code != http.StatusBadRequest || strings.TrimSpace(string(raw)) != c.want {
			t.Errorf("%s: = %d %s, want 400 %s", c.name, code, raw, c.want)
		}
	}
	// Upper-case hex digits are hex digits to erchef too.
	mustStatus(t, signed(t, srv, "POST", base+"/sandboxes", sandboxBody(strings.ToUpper(good))), http.StatusCreated)
}

// A sandbox lives in the organization that created it.
func TestSandboxFromAnotherOrgCannotBeCommitted(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme", "globex"}, EnforceACL: true})
	acme := srv.URL() + "/organizations/acme"
	globex := srv.URL() + "/organizations/globex"
	sum := md5Hex("acme only")
	sb := adminSandbox(t, srv, acme, sum)
	if code, body := rawRequest(t, "PUT", sb.Checksums[sum].URL, "acme only"); code != http.StatusOK {
		t.Fatalf("upload = %d: %s", code, body)
	}
	// Baseline: it commits in its own org.
	mustStatus(t, signed(t, srv, "PUT", acme+"/sandboxes/"+sb.SandboxID, `{"is_completed":true}`), http.StatusOK)
	mustStatus(t, signed(t, srv, "PUT", globex+"/sandboxes/"+sb.SandboxID, `{"is_completed":true}`), http.StatusNotFound)

	// And its upload URL is no grant in another org.
	other := strings.Replace(sb.Checksums[sum].URL, "/organizations/acme/", "/organizations/globex/", 1)
	if code, _ := rawRequest(t, "PUT", other, "acme only"); code != http.StatusUnauthorized {
		t.Fatalf("acme upload URL used in globex = %d, want 401", code)
	}
}
