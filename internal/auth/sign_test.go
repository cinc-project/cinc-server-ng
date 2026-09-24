package auth

import (
	"net/http"
	"strings"
	"testing"
)

func TestSignThenVerifyRoundTrip(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"name":"web01"}`)
	req, _ := http.NewRequest("POST", "http://localhost/organizations/acme/nodes", strings.NewReader(string(body)))
	req.Header.Set("X-Ops-Server-API-Version", "1")

	if err := SignRequest(req, "node1", "2024-01-02T03:04:05Z", body, key); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}
	if err := VerifyRequest(req.Method, req.URL.Path, body, req.Header, &key.PublicKey); err != nil {
		t.Fatalf("VerifyRequest rejected a freshly signed request: %v", err)
	}
}

// TestSignRequestSignsEscapedPath: Mixlib clients (Chef::HTTP::Authenticator
// passes `url.path`) sign the path as it goes on the wire, percent escapes
// included. SignRequest must do the same, or its signatures only verify
// against the decoded path.
func TestSignRequestSignsEscapedPath(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	for _, rawURL := range []string{
		"http://localhost/organizations/acme/data/t%20bad%2095bd2c97",
		"http://localhost/organizations/acme/data/a%7eb",
	} {
		req, _ := http.NewRequest("GET", rawURL, nil)
		if err := SignRequest(req, "node1", "2024-01-02T03:04:05Z", nil, key); err != nil {
			t.Fatal(err)
		}
		wire := strings.TrimPrefix(rawURL, "http://localhost")
		if err := VerifyRequest("GET", wire, nil, req.Header, &key.PublicKey); err != nil {
			t.Errorf("%s: signature does not cover the escaped path: %v", wire, err)
		}
	}
}

func TestSignedRequestRejectedByWrongKey(t *testing.T) {
	key, _ := GenerateKey()
	other, _ := GenerateKey()
	body := []byte("")
	req, _ := http.NewRequest("GET", "http://localhost/organizations/acme/nodes", nil)
	if err := SignRequest(req, "node1", "2024-01-02T03:04:05Z", body, key); err != nil {
		t.Fatal(err)
	}
	if err := VerifyRequest(req.Method, req.URL.Path, body, req.Header, &other.PublicKey); err == nil {
		t.Fatal("expected verification to fail with wrong key")
	}
}
