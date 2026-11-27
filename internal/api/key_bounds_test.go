package api

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"

	"github.com/cinc-project/cinc-server-ng/internal/auth"
)

// boundsKeyPEM marshals an RSA public key with the given modulus size and
// exponent without generating a key pair (the modulus is 2^(bits-1)+1),
// JSON-encoded for a request body.
func boundsKeyPEM(t *testing.T, bits, e int) string {
	t.Helper()
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	n.Add(n, big.NewInt(1))
	der, err := x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: n, E: e})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})))
	return string(b)
}

// unusableKeys are public keys that parse but are outside the bounds
// auth.CheckPublicKey sets: every request naming their owner would be
// verified against them, so storing one lets anyone burn CPU with a fake
// signature.
func unusableKeys(t *testing.T) map[string]string {
	return map[string]string{
		"oversized modulus": boundsKeyPEM(t, auth.MaxPublicKeyBits+1, 65537),
		"huge exponent":     boundsKeyPEM(t, 2048, 1<<40+1),
		"even exponent":     boundsKeyPEM(t, 2048, 65536),
		"small modulus":     boundsKeyPEM(t, 512, 65537),
	}
}

const invalidKeyBody = `{"error":["Public Key must be a valid key."]}`

func TestKeysAPIRefusesUnusableKey(t *testing.T) {
	srv, _ := newTestAPI(t)
	do(t, "POST", srv.URL+"/users", userBody(`{"username":"alice"}`))
	do(t, "POST", srv.URL+"/organizations/acme/clients", `{"name":"web01"}`)
	for _, owner := range []string{srv.URL + "/organizations/acme/clients/web01", srv.URL + "/users/alice"} {
		do(t, "POST", owner+"/keys", `{"name":"k2","create_key":true,"expiration_date":"infinity"}`)
		for what, pub := range unusableKeys(t) {
			resp, out := do(t, "POST", owner+"/keys", `{"name":"bad","public_key":`+pub+`,"expiration_date":"infinity"}`)
			if resp.StatusCode != 400 || strings.TrimSpace(out) != invalidKeyBody {
				t.Errorf("POST %s/keys with %s = %d %s, want 400 %s", owner, what, resp.StatusCode, out, invalidKeyBody)
			}
			if resp, _ := do(t, "GET", owner+"/keys/bad", ""); resp.StatusCode != 404 {
				t.Errorf("%s: refused key was stored: GET = %d", what, resp.StatusCode)
			}
			_, before := do(t, "GET", owner+"/keys/k2", "")
			resp, out = do(t, "PUT", owner+"/keys/k2", `{"public_key":`+pub+`}`)
			if resp.StatusCode != 400 || strings.TrimSpace(out) != invalidKeyBody {
				t.Errorf("PUT %s/keys/k2 with %s = %d %s, want 400 %s", owner, what, resp.StatusCode, out, invalidKeyBody)
			}
			if _, after := do(t, "GET", owner+"/keys/k2", ""); after != before {
				t.Errorf("%s: refused PUT changed the key", what)
			}
		}
		// The bounds still admit the keys Chef clients use.
		resp, out := do(t, "POST", owner+"/keys", `{"name":"big","public_key":`+boundsKeyPEM(t, 4096, 65537)+`,"expiration_date":"infinity"}`)
		if resp.StatusCode != 201 {
			t.Errorf("POST %s/keys with a 4096-bit key = %d %s, want 201", owner, resp.StatusCode, out)
		}
	}
}

func TestActorCreateRefusesUnusableKey(t *testing.T) {
	srv, _ := newTestAPI(t)
	clients := srv.URL + "/organizations/acme/clients"
	for what, pub := range unusableKeys(t) {
		for _, c := range []struct{ url, body, get string }{
			{clients, `{"name":"c1","public_key":` + pub + `}`, clients + "/c1"},
			{clients, `{"name":"c1","chef_key":{"public_key":` + pub + `}}`, clients + "/c1"},
			{srv.URL + "/users", userBody(`{"username":"u1","public_key":` + pub + `}`), srv.URL + "/users/u1"},
		} {
			resp, out := do(t, "POST", c.url, c.body)
			if resp.StatusCode != 400 || strings.TrimSpace(out) != invalidKeyBody {
				t.Errorf("POST %s with %s = %d %s, want 400 %s", c.url, what, resp.StatusCode, out, invalidKeyBody)
			}
			if resp, _ := do(t, "GET", c.get, ""); resp.StatusCode != 404 {
				t.Errorf("%s: refused actor was stored: GET %s = %d", what, c.get, resp.StatusCode)
			}
		}
	}
}

// At API v0 an actor update may set its public_key, which erchef checks as it
// does on create (chef_key_base:validate_public_key_fields).
func TestActorV0UpdateRefusesUnusableKey(t *testing.T) {
	srv, _ := newTestAPI(t)
	do(t, "POST", srv.URL+"/users", userBody(`{"username":"alice"}`))
	do(t, "POST", srv.URL+"/organizations/acme/clients", `{"name":"web01"}`)
	client := srv.URL + "/organizations/acme/clients/web01"
	user := srv.URL + "/users/alice"
	bad := unusableKeys(t)
	bad["garbage"] = `"this is not a public key\n"`
	for what, pub := range bad {
		for _, c := range []struct{ url, body string }{
			{client, `{"name":"web01","public_key":` + pub + `}`},
			{client, `{"name":"web01","chef_key":{"public_key":` + pub + `}}`},
			{user, userBody(`{"username":"alice","public_key":` + pub + `}`)},
		} {
			_, before := doAt(t, "0", "GET", c.url, "")
			resp, out := doAt(t, "0", "PUT", c.url, c.body)
			if resp.StatusCode != 400 || strings.TrimSpace(out) != invalidKeyBody {
				t.Errorf("v0 PUT %s with %s = %d %s, want 400 %s", c.url, what, resp.StatusCode, out, invalidKeyBody)
			}
			if _, after := doAt(t, "0", "GET", c.url, ""); after != before {
				t.Errorf("%s: refused v0 PUT changed %s", what, c.url)
			}
		}
	}
	// A usable key is still accepted.
	pub := boundsKeyPEM(t, 4096, 65537)
	if resp, out := doAt(t, "0", "PUT", client, `{"name":"web01","public_key":`+pub+`}`); resp.StatusCode != 200 {
		t.Errorf("v0 PUT with a 4096-bit key = %d %s, want 200", resp.StatusCode, out)
	}
}
