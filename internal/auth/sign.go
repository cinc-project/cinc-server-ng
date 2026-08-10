package auth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
)

// SignRequest signs an HTTP request using Mixlib::Authentication protocol
// version 1.3 (SHA256 / RSASSA-PKCS1-v1.5), setting the X-Ops-* headers the
// way a real chef-client would. It is the signing counterpart to Verify and is
// used both for end-to-end tests and as a convenience for library callers that
// want to talk to a cinc-server-ng server.
func SignRequest(r *http.Request, userID, timestamp string, body []byte, key *rsa.PrivateKey) error {
	p := &Parsed{
		Version:     "1.3",
		Algorithm:   "sha256",
		UserID:      userID,
		Timestamp:   timestamp,
		ContentHash: hashB64(sha256.New(), body),
	}
	serverAPIVersion := r.Header.Get("X-Ops-Server-API-Version")
	signingString := canonicalString(r.Method, r.URL.Path, body, p, serverAPIVersion)

	sum := sha256.Sum256([]byte(signingString))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return err
	}

	r.Header.Set("X-Ops-Sign", "algorithm=sha256;version=1.3;")
	r.Header.Set("X-Ops-Userid", userID)
	r.Header.Set("X-Ops-Timestamp", timestamp)
	r.Header.Set("X-Ops-Content-Hash", p.ContentHash)
	setSignatureHeaders(r, sig)
	return nil
}

// setSignatureHeaders base64-encodes sig and splits it into 60-character
// X-Ops-Authorization-N chunks, matching Mixlib's header layout.
func setSignatureHeaders(r *http.Request, sig []byte) {
	encoded := base64.StdEncoding.EncodeToString(sig)
	const chunk = 60
	for i, n := 0, 1; i < len(encoded); i, n = i+chunk, n+1 {
		end := min(i+chunk, len(encoded))
		r.Header.Set("X-Ops-Authorization-"+itoa(n), encoded[i:end])
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
