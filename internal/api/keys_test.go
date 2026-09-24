package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cinc-project/cinc-server-ng/internal/auth"
)

type keyListEntry struct {
	Name string `json:"name"`
	URI  string `json:"uri"`
}

func TestClientKeyLifecycle(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"

	// Creating a client generates its default key pair.
	resp, body := do(t, "POST", base+"/clients", `{"name":"web01"}`)
	if resp.StatusCode != 201 {
		t.Fatalf("create client = %d: %s", resp.StatusCode, body)
	}

	// The default key is listed.
	_, body = do(t, "GET", base+"/clients/web01/keys", "")
	var list []keyListEntry
	json.Unmarshal([]byte(body), &list)
	if !hasKey(list, "default") {
		t.Fatalf("keys list missing default: %s", body)
	}

	// The default key exposes the client's public key.
	_, body = do(t, "GET", base+"/clients/web01/keys/default", "")
	var def map[string]any
	json.Unmarshal([]byte(body), &def)
	if pk, _ := def["public_key"].(string); !strings.Contains(pk, "PUBLIC KEY") {
		t.Fatalf("default key missing public_key: %s", body)
	}

	// Add a second key with no public_key; the server generates one and returns
	// the private key exactly once.
	resp, body = do(t, "POST", base+"/clients/web01/keys", `{"name":"key2","expiration_date":"infinity"}`)
	if resp.StatusCode != 201 {
		t.Fatalf("add key = %d: %s", resp.StatusCode, body)
	}
	var added map[string]any
	json.Unmarshal([]byte(body), &added)
	if pk, _ := added["private_key"].(string); !strings.Contains(pk, "PRIVATE KEY") {
		t.Fatalf("generated key did not return a private_key: %s", body)
	}

	// Both keys are now listed.
	_, body = do(t, "GET", base+"/clients/web01/keys", "")
	json.Unmarshal([]byte(body), &list)
	if !hasKey(list, "default") || !hasKey(list, "key2") {
		t.Fatalf("keys list = %s", body)
	}

	// Fetch the named key.
	resp, body = do(t, "GET", base+"/clients/web01/keys/key2", "")
	if resp.StatusCode != 200 {
		t.Fatalf("get key2 = %d: %s", resp.StatusCode, body)
	}

	// Delete it.
	resp, _ = do(t, "DELETE", base+"/clients/web01/keys/key2", "")
	if resp.StatusCode != 200 {
		t.Fatalf("delete key2 = %d", resp.StatusCode)
	}
	resp, _ = do(t, "GET", base+"/clients/web01/keys/key2", "")
	if resp.StatusCode != 404 {
		t.Fatalf("get deleted key2 = %d", resp.StatusCode)
	}
}

func TestClientKeyAddDuplicate(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	do(t, "POST", base+"/clients", `{"name":"web01"}`)
	do(t, "POST", base+"/clients/web01/keys", `{"name":"key2"}`)
	resp, _ := do(t, "POST", base+"/clients/web01/keys", `{"name":"key2"}`)
	if resp.StatusCode != 409 {
		t.Fatalf("duplicate key = %d, want 409", resp.StatusCode)
	}
}

func TestKeysForMissingActor404(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	resp, _ := do(t, "GET", base+"/clients/ghost/keys", "")
	if resp.StatusCode != 404 {
		t.Fatalf("keys for missing client = %d, want 404", resp.StatusCode)
	}
}

func TestUserKeyLifecycle(t *testing.T) {
	srv, _ := newTestAPI(t)

	resp, body := do(t, "POST", srv.URL+"/users", userBody(`{"name":"alice"}`))
	if resp.StatusCode != 201 {
		t.Fatalf("create user = %d: %s", resp.StatusCode, body)
	}
	// Users are global; their keys live under /users/{name}/keys.
	_, body = do(t, "GET", srv.URL+"/users/alice/keys", "")
	var list []keyListEntry
	json.Unmarshal([]byte(body), &list)
	if !hasKey(list, "default") {
		t.Fatalf("user keys list missing default: %s", body)
	}
}

// A key PUT with {"create_key": true} regenerates the key: the server makes a
// new pair, stores its public half, and returns the private half once. The
// flag itself is never stored.
func TestKeyPutCreateKeyRegenerates(t *testing.T) {
	for _, keyName := range []string{"rotating", "default"} {
		t.Run(keyName, func(t *testing.T) {
			srv, _ := newTestAPI(t)
			base := srv.URL + "/organizations/acme/clients/web01/keys"
			do(t, "POST", srv.URL+"/organizations/acme/clients", `{"name":"web01"}`)
			if keyName != "default" {
				do(t, "POST", base, `{"name":"rotating","expiration_date":"infinity"}`)
			}
			_, raw := do(t, "GET", base+"/"+keyName, "")
			var before map[string]any
			json.Unmarshal([]byte(raw), &before)

			resp, body := do(t, "PUT", base+"/"+keyName, `{"name":"`+keyName+`","create_key":true}`)
			if resp.StatusCode != 200 {
				t.Fatalf("PUT create_key = %d: %s", resp.StatusCode, body)
			}
			var out map[string]any
			json.Unmarshal([]byte(body), &out)
			priv, _ := out["private_key"].(string)
			if !strings.Contains(priv, "PRIVATE KEY") {
				t.Fatalf("PUT create_key returned no private_key: %s", body)
			}
			if _, ok := out["create_key"]; ok {
				t.Fatalf("PUT create_key echoed the flag: %s", body)
			}

			_, raw = do(t, "GET", base+"/"+keyName, "")
			var after map[string]any
			json.Unmarshal([]byte(raw), &after)
			if _, ok := after["create_key"]; ok {
				t.Fatalf("create_key was stored on the key: %s", raw)
			}
			if _, ok := after["private_key"]; ok {
				t.Fatalf("the private key was stored on the key: %s", raw)
			}
			pub, _ := after["public_key"].(string)
			if pub == "" || pub == before["public_key"] {
				t.Fatalf("public_key after create_key = %q, want a new key", pub)
			}
			key, err := auth.ParsePrivateKey([]byte(priv))
			if err != nil {
				t.Fatal(err)
			}
			want, _ := auth.EncodePublicKeyPEM(&key.PublicKey)
			if pub != string(want) {
				t.Fatalf("stored public_key does not match the returned private_key")
			}
		})
	}
}

// create_key and public_key together ask for two different keys; erchef
// refuses the request (create_and_pubkey_specified).
func TestKeyPutCreateKeyWithPublicKeyIsRejected(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme/clients/web01/keys"
	do(t, "POST", srv.URL+"/organizations/acme/clients", `{"name":"web01"}`)
	do(t, "POST", base, `{"name":"rotating","expiration_date":"infinity"}`)
	_, before := do(t, "GET", base+"/rotating", "")

	key, _ := auth.GenerateKey()
	pub, _ := auth.EncodePublicKeyPEM(&key.PublicKey)
	pubJSON, _ := json.Marshal(string(pub))
	resp, body := do(t, "PUT", base+"/rotating", `{"name":"rotating","create_key":true,"public_key":`+string(pubJSON)+`}`)
	if resp.StatusCode != 400 {
		t.Fatalf("PUT create_key with public_key = %d, want 400: %s", resp.StatusCode, body)
	}
	if _, after := do(t, "GET", base+"/rotating", ""); after != before {
		t.Fatalf("a refused PUT changed the key:\nbefore %s\nafter  %s", before, after)
	}
}

// A false create_key is not stored either.
func TestKeyPutCreateKeyFalseIsNotStored(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme/clients/web01/keys"
	do(t, "POST", srv.URL+"/organizations/acme/clients", `{"name":"web01"}`)
	do(t, "POST", base, `{"name":"rotating","expiration_date":"infinity"}`)
	_, raw := do(t, "GET", base+"/rotating", "")
	var before map[string]any
	json.Unmarshal([]byte(raw), &before)
	pub, _ := json.Marshal(before["public_key"])
	do(t, "PUT", base+"/rotating", `{"name":"rotating","public_key":`+string(pub)+`,"expiration_date":"infinity","create_key":false}`)
	if _, raw = do(t, "GET", base+"/rotating", ""); strings.Contains(raw, "create_key") {
		t.Fatalf("create_key was stored on the key: %s", raw)
	}
}

func hasKey(list []keyListEntry, name string) bool {
	for _, k := range list {
		if k.Name == name {
			return true
		}
	}
	return false
}

// testPublicKeyPEM returns a freshly generated RSA public key in PEM form.
func testPublicKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := auth.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := auth.EncodePublicKeyPEM(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pub)
}

// badDateMessage is erchef's BAD_DATE_MESSAGE for expiration_date, as it
// appears JSON-encoded in a response body.
const badDateMessage = `Field expiration_date is invalid. All dates must be a valid date in ISO8601 form of exactly YYYY-MM-DDThh:mm:ss, eg 2099-02-28T01:00:00, or the string \"infinity\". All times are assumed UTC, so do not include a Z on the end of your date.`

// erchef (chef_key:parse_binary_json) validates a new key's name against
// chef_regex key_name, its public_key as a PEM public key, and its
// expiration_date as "infinity" or an ISO 8601 UTC timestamp, answering 400
// and storing nothing otherwise. It runs for client and user keys alike.
func TestAddKeyRejectsInvalidFields(t *testing.T) {
	srv, _ := newTestAPI(t)
	do(t, "POST", srv.URL+"/users", `{"username":"alice"}`)
	do(t, "POST", srv.URL+"/organizations/acme/clients", `{"name":"web01"}`)
	for _, owner := range []string{"/organizations/acme/clients/web01", "/users/alice"} {
		cases := []struct {
			body map[string]any
			want string
		}{
			{map[string]any{"name": "bad^name", "create_key": true, "expiration_date": "infinity"}, "Field 'name' invalid"},
			{map[string]any{"name": "bad name", "create_key": true, "expiration_date": "infinity"}, "Field 'name' invalid"},
			{map[string]any{"name": "junk1", "public_key": "garbage", "expiration_date": "infinity"}, "Public Key must be a valid key."},
			{map[string]any{"name": "junk2", "public_key": "-----BEGIN PUBLIC KEY-----\ninvalid_key\n-----END PUBLIC KEY-----", "expiration_date": "infinity"}, "Public Key must be a valid key."},
			{map[string]any{"name": "junk3", "create_key": true, "expiration_date": "next tuesday"}, badDateMessage},
			{map[string]any{"name": "junk4", "create_key": true, "expiration_date": "2099-02-28T01:00:00"}, badDateMessage},
			{map[string]any{"name": "junk5", "create_key": true, "expiration_date": "2099-02-30T01:00:00Z"}, badDateMessage},
		}
		for _, c := range cases {
			body, _ := json.Marshal(c.body)
			resp, out := do(t, "POST", srv.URL+owner+"/keys", string(body))
			if resp.StatusCode != 400 || !strings.Contains(out, c.want) {
				t.Errorf("POST %s/keys %s = %d %s, want 400 %q", owner, body, resp.StatusCode, out, c.want)
			}
		}
		_, out := do(t, "GET", srv.URL+owner+"/keys", "")
		var list []keyListEntry
		json.Unmarshal([]byte(out), &list)
		if len(list) != 1 || list[0].Name != "default" {
			t.Errorf("refused keys were stored for %s: %s", owner, out)
		}

		good, _ := json.Marshal(map[string]any{"name": "rot:1.a_b-c", "public_key": testPublicKeyPEM(t), "expiration_date": "2099-02-28T01:00:00Z"})
		if resp, out := do(t, "POST", srv.URL+owner+"/keys", string(good)); resp.StatusCode != 201 {
			t.Errorf("valid key for %s = %d %s, want 201", owner, resp.StatusCode, out)
		}
	}
}

// The same checks apply on key PUT, to whichever fields the body carries.
func TestPutKeyRejectsInvalidFields(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme/clients/web01"
	do(t, "POST", srv.URL+"/organizations/acme/clients", `{"name":"web01"}`)
	do(t, "POST", base+"/keys", `{"name":"key2","create_key":true,"expiration_date":"infinity"}`)
	_, before := do(t, "GET", base+"/keys/key2", "")

	for _, key := range []string{"key2", "default"} {
		for _, c := range []struct{ body, want string }{
			{`{"name":"bad name"}`, "Field 'name' invalid"},
			{`{"public_key":"garbage"}`, "Public Key must be a valid key."},
			{`{"expiration_date":"next tuesday"}`, badDateMessage},
		} {
			resp, out := do(t, "PUT", base+"/keys/"+key, c.body)
			if resp.StatusCode != 400 || !strings.Contains(out, c.want) {
				t.Errorf("PUT keys/%s %s = %d %s, want 400 %q", key, c.body, resp.StatusCode, out, c.want)
			}
		}
	}
	if _, after := do(t, "GET", base+"/keys/key2", ""); after != before {
		t.Errorf("a refused PUT changed key2:\nbefore %s\nafter  %s", before, after)
	}
}
