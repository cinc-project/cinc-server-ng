package auth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
)

type vectorFile struct {
	PublicKey  string   `json:"public_key"`
	PrivateKey string   `json:"private_key"`
	Cases      []vector `json:"cases"`
}

type vector struct {
	ProtoVersion     string            `json:"proto_version"`
	HTTPMethod       string            `json:"http_method"`
	Path             string            `json:"path"`
	Body             string            `json:"body"`
	Timestamp        string            `json:"timestamp"`
	UserID           string            `json:"user_id"`
	ServerAPIVersion string            `json:"server_api_version"`
	Headers          map[string]string `json:"headers"`
}

func loadVectors(t *testing.T) (*vectorFile, *rsa.PublicKey) {
	t.Helper()
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vf vectorFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	pub, err := ParsePublicKey([]byte(vf.PublicKey))
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	return &vf, pub
}

func header(v vector) http.Header {
	h := http.Header{}
	for k, val := range v.Headers {
		h.Set(k, val)
	}
	h.Set("X-Ops-Server-API-Version", v.ServerAPIVersion)
	return h
}

// TestVerifyGoldenVectors proves byte-for-byte compatibility with real
// chef-client/knife request signing across protocol versions 1.0, 1.1, 1.3.
func TestVerifyGoldenVectors(t *testing.T) {
	vf, pub := loadVectors(t)
	if len(vf.Cases) == 0 {
		t.Fatal("no vectors")
	}
	for _, v := range vf.Cases {
		name := v.ProtoVersion + "_" + v.HTTPMethod + "_" + v.Path
		t.Run(name, func(t *testing.T) {
			err := VerifyRequest(v.HTTPMethod, v.Path, []byte(v.Body), header(v), pub)
			if err != nil {
				t.Fatalf("VerifyRequest failed for valid signature: %v", err)
			}
		})
	}
}

// TestGoldenVectorsSignEscapedPath: the gem signs the path it is handed, and
// Chef::HTTP::Authenticator hands it `url.path`, escapes included. So an
// escaped-path vector verifies only against the escaped path; the decoded
// path a Go server finds in r.URL.Path is a different signing string.
func TestGoldenVectorsSignEscapedPath(t *testing.T) {
	vf, pub := loadVectors(t)
	n := 0
	for _, v := range vf.Cases {
		if !strings.Contains(v.Path, "%") {
			continue
		}
		n++
		decoded, err := url.PathUnescape(v.Path)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyRequest(v.HTTPMethod, decoded, []byte(v.Body), header(v), pub); err == nil {
			t.Errorf("%s %s: signature verified against the decoded path %q", v.ProtoVersion, v.Path, decoded)
		}
	}
	if n == 0 {
		t.Fatal("no escaped-path vectors; regenerate testdata/vectors.json with gen_vectors.rb")
	}
}

func TestParseExtractsUserID(t *testing.T) {
	vf, _ := loadVectors(t)
	v := vf.Cases[0]
	p, err := Parse(header(v))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.UserID != v.UserID {
		t.Fatalf("UserID = %q, want %q", p.UserID, v.UserID)
	}
	if p.Version != v.ProtoVersion {
		t.Fatalf("Version = %q, want %q", p.Version, v.ProtoVersion)
	}
}

func TestVerifyRejectsTamperedBody(t *testing.T) {
	vf, pub := loadVectors(t)
	var v vector
	for _, c := range vf.Cases {
		if c.Body != "" {
			v = c
			break
		}
	}
	tampered := []byte(v.Body + " ")
	if err := VerifyRequest(v.HTTPMethod, v.Path, tampered, header(v), pub); err == nil {
		t.Fatal("expected verification to fail for tampered body")
	}
}

func TestVerifyRejectsTamperedSignature(t *testing.T) {
	vf, pub := loadVectors(t)
	v := vf.Cases[0]
	h := header(v)
	// flip a character in the first signature chunk
	sig := h.Get("X-Ops-Authorization-1")
	if sig == "" {
		t.Fatal("no signature header")
	}
	b := []byte(sig)
	if b[0] == 'A' {
		b[0] = 'B'
	} else {
		b[0] = 'A'
	}
	h.Set("X-Ops-Authorization-1", string(b))
	if err := VerifyRequest(v.HTTPMethod, v.Path, []byte(v.Body), h, pub); err == nil {
		t.Fatal("expected verification to fail for tampered signature")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	vf, _ := loadVectors(t)
	v := vf.Cases[0]
	// a different key
	other := mustParsePub(t, generateOtherPubPEM(t))
	if err := VerifyRequest(v.HTTPMethod, v.Path, []byte(v.Body), header(v), other); err == nil {
		t.Fatal("expected verification to fail with wrong key")
	}
}

func TestCanonicalPath(t *testing.T) {
	cases := map[string]string{
		"/":                          "/",
		"/organizations/acme/nodes":  "/organizations/acme/nodes",
		"/organizations/acme/nodes/": "/organizations/acme/nodes",
		"/organizations/acme//nodes": "/organizations/acme/nodes",
		"//a///b//":                  "/a/b",
		"":                           "/",
	}
	for in, want := range cases {
		if got := canonicalPath(in); got != want {
			t.Errorf("canonicalPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseErrors(t *testing.T) {
	cases := []struct {
		name string
		h    http.Header
	}{
		{"missing sign", http.Header{}},
		{"bad version", http.Header{"X-Ops-Sign": {"version=9.9"}}},
		{"missing userid", http.Header{
			"X-Ops-Sign":            {"version=1.0"},
			"X-Ops-Authorization-1": {"abc"},
		}},
		{"missing signature", http.Header{
			"X-Ops-Sign":   {"version=1.0"},
			"X-Ops-Userid": {"bob"},
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Parse(c.h); err == nil {
				t.Fatal("expected parse error")
			}
		})
	}
}

func TestParseDefaultsAlgorithmFromVersion(t *testing.T) {
	h := http.Header{
		"X-Ops-Sign":            {"version=1.3"},
		"X-Ops-Userid":          {"bob"},
		"X-Ops-Authorization-1": {"YWJj"},
	}
	p, err := Parse(h)
	if err != nil {
		t.Fatal(err)
	}
	if p.Algorithm != "sha256" {
		t.Fatalf("algorithm = %q, want sha256", p.Algorithm)
	}
}

func mustParsePub(t *testing.T, pemBytes []byte) *rsa.PublicKey {
	t.Helper()
	pub, err := ParsePublicKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func generateOtherPubPEM(t *testing.T) []byte {
	t.Helper()
	// A fresh, unrelated key must not validate the golden signature.
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}
