package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cinc-project/cinc-server-ng/internal/auth"
	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// erchef's messages for chef_key_base:validate_public_key_fields, as
// chef_wm_malformed renders them.
const (
	wantBothKeysMessage       = "You must specify either create_key or public_key, but not both"
	wantKeyManagementMessage  = "Since Server API v1, all keys must be updated via the keys endpoint. "
	wantPrivateKeyFlagMessage = "Please use create_key: true instead of private_key: true"
)

// actorCase is one of the two actor collections that share the create and
// update handlers: an org's clients and the global users.
type actorCase struct {
	segment string
	base    func(srv *httptest.Server) string
	body    func(name, extra string) string
	read    func(st *store.Store, name string) map[string]any
}

func actorCases() []actorCase {
	readFrom := func(scope func(st *store.Store) *store.Org, segment string) func(*store.Store, string) map[string]any {
		return func(st *store.Store, name string) map[string]any {
			raw, ok, err := scope(st).Get(segment, name)
			if err != nil || !ok {
				return nil
			}
			var doc map[string]any
			_ = json.Unmarshal(raw, &doc)
			return doc
		}
	}
	join := func(name, extra string) string {
		if extra == "" {
			return `{"name":"` + name + `"}`
		}
		return `{"name":"` + name + `",` + extra + `}`
	}
	return []actorCase{
		{
			segment: "clients",
			base:    func(srv *httptest.Server) string { return srv.URL + "/organizations/acme/clients" },
			body:    join,
			read: readFrom(func(st *store.Store) *store.Org {
				org, _, _ := st.Org("acme")
				return org
			}, "clients"),
		},
		{
			segment: "users",
			base:    func(srv *httptest.Server) string { return srv.URL + "/users" },
			body:    func(name, extra string) string { return userBody(join(name, extra)) },
			read:    readFrom(func(st *store.Store) *store.Org { return st.Global() }, "users"),
		},
	}
}

func testPublicKeyJSON(t *testing.T) (string, string) {
	t.Helper()
	key, err := auth.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := auth.EncodePublicKeyPEM(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	quoted, _ := json.Marshal(string(pub))
	return string(pub), string(quoted)
}

// Under API v1 erchef creates an actor with no key at all unless the request
// asks for one with create_key or supplies a public_key
// (oc_chef_wm_key_base:create_object({undefined, undefined}, ...)).
func TestActorCreateV1WithoutKeyFieldsIsKeyless(t *testing.T) {
	for _, c := range actorCases() {
		t.Run(c.segment, func(t *testing.T) {
			srv, st := newTestAPI(t)
			resp, body := doAt(t, "1", "POST", c.base(srv), c.body("keyless", ""))
			if resp.StatusCode != 201 {
				t.Fatalf("create = %d: %s", resp.StatusCode, body)
			}
			var out map[string]any
			_ = json.Unmarshal([]byte(body), &out)
			if _, ok := out["chef_key"]; ok {
				t.Fatalf("keyless create returned a chef_key: %s", body)
			}
			if privateKeyFrom(t, out) != "" {
				t.Fatalf("keyless create returned a private key: %s", body)
			}
			doc := c.read(st, "keyless")
			if doc == nil {
				t.Fatal("actor not stored")
			}
			if pub, _ := doc["public_key"].(string); pub != "" {
				t.Fatalf("keyless actor stored a public key: %v", doc)
			}
			if resp, body := doAt(t, "1", "GET", c.base(srv)+"/keyless/keys/default", ""); resp.StatusCode != 404 {
				t.Fatalf("GET keys/default = %d, want 404: %s", resp.StatusCode, body)
			}
			if resp, body := doAt(t, "1", "GET", c.base(srv)+"/keyless/keys", ""); resp.StatusCode != 200 || strings.TrimSpace(body) != "[]" {
				t.Fatalf("GET keys = %d %s, want 200 []", resp.StatusCode, body)
			}
		})
	}
}

func TestActorCreateV1CreateKeyGeneratesKey(t *testing.T) {
	for _, c := range actorCases() {
		t.Run(c.segment, func(t *testing.T) {
			srv, st := newTestAPI(t)
			resp, body := doAt(t, "1", "POST", c.base(srv), c.body("keyed", `"create_key":true`))
			if resp.StatusCode != 201 {
				t.Fatalf("create = %d: %s", resp.StatusCode, body)
			}
			var out map[string]any
			_ = json.Unmarshal([]byte(body), &out)
			ck, _ := out["chef_key"].(map[string]any)
			priv, _ := ck["private_key"].(string)
			if _, err := auth.ParsePrivateKey([]byte(priv)); err != nil {
				t.Fatalf("create_key returned no usable chef_key.private_key (%v): %s", err, body)
			}
			doc := c.read(st, "keyed")
			if pub, _ := doc["public_key"].(string); pub == "" {
				t.Fatalf("generated key not stored: %v", doc)
			}
			if _, ok := doc["create_key"]; ok {
				t.Fatalf("create_key was stored on the actor: %v", doc)
			}
			if resp, body := doAt(t, "1", "GET", c.base(srv)+"/keyed/keys/default", ""); resp.StatusCode != 200 {
				t.Fatalf("GET keys/default = %d: %s", resp.StatusCode, body)
			}
		})
	}
}

func TestActorCreateV1PublicKeyStoresIt(t *testing.T) {
	for _, c := range actorCases() {
		t.Run(c.segment, func(t *testing.T) {
			srv, st := newTestAPI(t)
			pub, quoted := testPublicKeyJSON(t)
			// create_key false alongside a public key is not a conflict.
			resp, body := doAt(t, "1", "POST", c.base(srv), c.body("byo", `"public_key":`+quoted+`,"create_key":false`))
			if resp.StatusCode != 201 {
				t.Fatalf("create = %d: %s", resp.StatusCode, body)
			}
			var out map[string]any
			_ = json.Unmarshal([]byte(body), &out)
			if privateKeyFrom(t, out) != "" {
				t.Fatalf("server returned a private key for a supplied public key: %s", body)
			}
			doc := c.read(st, "byo")
			if doc["public_key"] != pub {
				t.Fatalf("supplied public key not stored: %v", doc)
			}
			if _, ok := doc["create_key"]; ok {
				t.Fatalf("create_key was stored on the actor: %v", doc)
			}
		})
	}
}

func TestActorCreateV1RejectsCreateKeyWithPublicKey(t *testing.T) {
	for _, c := range actorCases() {
		t.Run(c.segment, func(t *testing.T) {
			srv, st := newTestAPI(t)
			_, quoted := testPublicKeyJSON(t)
			resp, body := doAt(t, "1", "POST", c.base(srv), c.body("both", `"public_key":`+quoted+`,"create_key":true`))
			if resp.StatusCode != 400 || !strings.Contains(body, wantBothKeysMessage) {
				t.Fatalf("create = %d %s, want 400 %q", resp.StatusCode, body, wantBothKeysMessage)
			}
			if c.read(st, "both") != nil {
				t.Fatal("refused actor was stored")
			}
		})
	}
}

func TestActorCreateV1RejectsPrivateKeyFlag(t *testing.T) {
	for _, c := range actorCases() {
		t.Run(c.segment, func(t *testing.T) {
			srv, st := newTestAPI(t)
			resp, body := doAt(t, "1", "POST", c.base(srv), c.body("legacy", `"private_key":true`))
			if resp.StatusCode != 400 || !strings.Contains(body, wantPrivateKeyFlagMessage) {
				t.Fatalf("create = %d %s, want 400 %q", resp.StatusCode, body, wantPrivateKeyFlagMessage)
			}
			if c.read(st, "legacy") != nil {
				t.Fatal("refused actor was stored")
			}
		})
	}
}

// API v0 predates create_key: the server always generates a key unless one is
// supplied, and the flag is never stored.
func TestActorCreateV0AlwaysGeneratesKey(t *testing.T) {
	for _, c := range actorCases() {
		t.Run(c.segment, func(t *testing.T) {
			srv, st := newTestAPI(t)
			for _, extra := range []string{"", `"create_key":true`, `"create_key":false`} {
				name := "v0" + strings.NewReplacer(`"`, "", ":", "", "_", "").Replace(extra)
				resp, body := doAt(t, "0", "POST", c.base(srv), c.body(name, extra))
				if resp.StatusCode != 201 {
					t.Fatalf("create %s = %d: %s", extra, resp.StatusCode, body)
				}
				var out map[string]any
				_ = json.Unmarshal([]byte(body), &out)
				if privateKeyFrom(t, out) == "" {
					t.Fatalf("v0 create %s returned no private key: %s", extra, body)
				}
				doc := c.read(st, name)
				if _, ok := doc["create_key"]; ok {
					t.Fatalf("create_key was stored on the actor: %v", doc)
				}
			}
		})
	}
}

// From API v1 on, an actor's keys are managed only through its keys endpoint,
// so an update naming create_key, public_key or private_key is refused
// (chef_key_base:validate_public_key_fields(_, _, _, update)).
func TestActorUpdateV1RejectsKeyFields(t *testing.T) {
	for _, c := range actorCases() {
		t.Run(c.segment, func(t *testing.T) {
			srv, st := newTestAPI(t)
			if resp, body := doAt(t, "1", "POST", c.base(srv), c.body("upd", `"create_key":true`)); resp.StatusCode != 201 {
				t.Fatalf("create = %d: %s", resp.StatusCode, body)
			}
			before := c.read(st, "upd")
			_, quoted := testPublicKeyJSON(t)
			for _, tc := range []struct{ extra, want string }{
				{`"create_key":true`, wantKeyManagementMessage},
				{`"create_key":false`, wantKeyManagementMessage},
				{`"public_key":` + quoted, wantKeyManagementMessage},
				{`"private_key":true`, wantPrivateKeyFlagMessage},
			} {
				resp, body := doAt(t, "1", "PUT", c.base(srv)+"/upd", c.body("upd", tc.extra))
				if resp.StatusCode != 400 || !strings.Contains(body, tc.want) {
					t.Errorf("PUT %s = %d %s, want 400 %q", tc.extra, resp.StatusCode, body, tc.want)
				}
			}
			after := c.read(st, "upd")
			if after["public_key"] != before["public_key"] {
				t.Fatal("a refused update changed the actor's key")
			}
			if _, ok := after["create_key"]; ok {
				t.Fatalf("create_key was stored on the actor: %v", after)
			}
			// An update without key fields still goes through.
			if resp, body := doAt(t, "1", "PUT", c.base(srv)+"/upd", c.body("upd", "")); resp.StatusCode != 200 {
				t.Fatalf("plain PUT = %d: %s", resp.StatusCode, body)
			}
		})
	}
}

// API v0 still accepts a public_key on update, which replaces the default
// key; create_key means nothing there and is not stored.
func TestActorUpdateV0AcceptsPublicKey(t *testing.T) {
	for _, c := range actorCases() {
		t.Run(c.segment, func(t *testing.T) {
			srv, st := newTestAPI(t)
			if resp, body := doAt(t, "0", "POST", c.base(srv), c.body("upd0", "")); resp.StatusCode != 201 {
				t.Fatalf("create = %d: %s", resp.StatusCode, body)
			}
			pub, quoted := testPublicKeyJSON(t)
			resp, body := doAt(t, "0", "PUT", c.base(srv)+"/upd0", c.body("upd0", `"public_key":`+quoted+`,"create_key":true`))
			if resp.StatusCode != 200 {
				t.Fatalf("PUT = %d: %s", resp.StatusCode, body)
			}
			if strings.Contains(body, "create_key") {
				t.Fatalf("PUT echoed create_key: %s", body)
			}
			doc := c.read(st, "upd0")
			if doc["public_key"] != pub {
				t.Fatalf("v0 PUT did not replace the key: %v", doc)
			}
			if _, ok := doc["create_key"]; ok {
				t.Fatalf("create_key was stored on the actor: %v", doc)
			}
		})
	}
}

// From API v1 an actor's keys live only behind its keys endpoint, and erchef's
// chef_client:assemble_client_ejson and chef_user:assemble_user_ejson add
// public_key to the actor document only at v0. So a v1 read carries no key,
// and an edit that sends the read back (knife client/user edit) is not a key
// change the update refuses.
func TestActorReadV1OmitsPublicKey(t *testing.T) {
	for _, c := range actorCases() {
		t.Run(c.segment, func(t *testing.T) {
			srv, _ := newTestAPI(t)
			if resp, body := doAt(t, "1", "POST", c.base(srv), c.body("shown", `"create_key":true`)); resp.StatusCode != 201 {
				t.Fatalf("create = %d: %s", resp.StatusCode, body)
			}
			resp, body := doAt(t, "0", "GET", c.base(srv)+"/shown", "")
			if resp.StatusCode != 200 || !strings.Contains(body, `"public_key"`) {
				t.Fatalf("v0 GET = %d %s, want the public_key", resp.StatusCode, body)
			}
			resp, body = doAt(t, "1", "GET", c.base(srv)+"/shown", "")
			if resp.StatusCode != 200 || strings.Contains(body, `"public_key"`) {
				t.Fatalf("v1 GET = %d %s, want no public_key", resp.StatusCode, body)
			}
			// The edit round trip: the v1 read, sent back as the update.
			resp, put := doAt(t, "1", "PUT", c.base(srv)+"/shown", body)
			if resp.StatusCode != 200 {
				t.Fatalf("v1 PUT of the v1 read = %d: %s", resp.StatusCode, put)
			}
			if strings.Contains(put, `"public_key"`) {
				t.Fatalf("v1 PUT response carries the public_key: %s", put)
			}
			// The key the actor authenticates with is untouched by that edit.
			if resp, body := doAt(t, "1", "GET", c.base(srv)+"/shown/keys/default", ""); resp.StatusCode != 200 {
				t.Fatalf("GET keys/default after edit = %d: %s", resp.StatusCode, body)
			}
			resp, del := doAt(t, "1", "DELETE", c.base(srv)+"/shown", "")
			if resp.StatusCode != 200 || strings.Contains(del, `"public_key"`) {
				t.Fatalf("v1 DELETE = %d %s, want no public_key", resp.StatusCode, del)
			}
		})
	}
}
