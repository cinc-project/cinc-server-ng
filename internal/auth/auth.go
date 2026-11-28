// Package auth implements verification of Chef's Mixlib::Authentication
// signed-header protocol (versions 1.0, 1.1, and 1.3), so unmodified
// chef-client / knife / cinc clients can authenticate to cinc-server-ng with real
// RSA key pairs.
package auth

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"net/http"
	"strconv"
	"strings"
)

// Parsed holds the values extracted from a request's X-Ops-* headers.
type Parsed struct {
	Version     string // "1.0", "1.1", "1.3"
	Algorithm   string // "sha1" or "sha256"
	UserID      string
	Timestamp   string
	ContentHash string
	Signature   []byte // base64-decoded signature bytes
}

// Parse extracts and validates the structure of the X-Ops-* authentication
// headers. It does not perform cryptographic verification.
func Parse(h http.Header) (*Parsed, error) {
	sign := h.Get("X-Ops-Sign")
	if sign == "" {
		return nil, errors.New("auth: missing X-Ops-Sign header")
	}
	algorithm, version := parseSignDescription(sign)
	if version == "" {
		return nil, fmt.Errorf("auth: could not parse version from X-Ops-Sign %q", sign)
	}
	switch version {
	case "1.0", "1.1":
		if algorithm == "" {
			algorithm = "sha1"
		}
	case "1.3":
		if algorithm == "" {
			algorithm = "sha256"
		}
	default:
		return nil, fmt.Errorf("auth: unsupported signing version %q", version)
	}

	userID := h.Get("X-Ops-Userid")
	if userID == "" {
		return nil, errors.New("auth: missing X-Ops-Userid header")
	}

	sig, err := joinSignature(h)
	if err != nil {
		return nil, err
	}

	return &Parsed{
		Version:     version,
		Algorithm:   algorithm,
		UserID:      userID,
		Timestamp:   h.Get("X-Ops-Timestamp"),
		ContentHash: h.Get("X-Ops-Content-Hash"),
		Signature:   sig,
	}, nil
}

// VerifyRequest parses the auth headers and verifies the signature against pub.
// It returns nil only if the signature is valid for the given request. Clock
// skew is intentionally not checked here; that is enforced separately as
// server policy.
func VerifyRequest(method, path string, body []byte, h http.Header, pub *rsa.PublicKey) error {
	p, err := Parse(h)
	if err != nil {
		return err
	}
	return Verify(method, path, body, p, h.Get("X-Ops-Server-API-Version"), pub)
}

// Verify checks a parsed request's signature against pub. path must be the
// request path exactly as received, percent escapes included, never the
// decoded path: Mixlib clients sign the path they send
// (Chef::HTTP::Authenticator passes `url.path`), and erchef verifies against
// the raw request path.
//
// A key outside the bounds CheckPublicKey enforces is refused before any RSA
// arithmetic: ParsePublicKey already refuses one, but a key can also reach
// here parsed some other way.
//
// To try one request against several keys, Prepare it once instead.
func Verify(method, path string, body []byte, p *Parsed, serverAPIVersion string, pub *rsa.PublicKey) error {
	if err := CheckPublicKey(pub); err != nil {
		return fmt.Errorf("auth: signature verification failed: %w", err)
	}
	prep, err := Prepare(method, path, body, p, serverAPIVersion)
	if err != nil {
		return err
	}
	return prep.verify(pub)
}

// Prepared is a request's signing input, built once: the canonical string,
// with the body hashed into it, and for 1.3 the digest that is signed. Trying
// it against a key repeats only the RSA step, so what a request costs to check
// against an actor with many keys does not grow with its body.
type Prepared struct {
	version       string
	signingString []byte
	sum           [sha256.Size]byte // 1.3 only
	signature     []byte
}

// Prepare builds the signing input for a parsed request, with arguments as
// for Verify. It reads body once and does not keep it.
func Prepare(method, path string, body []byte, p *Parsed, serverAPIVersion string) (*Prepared, error) {
	switch p.Version {
	case "1.0", "1.1", "1.3":
	default:
		return nil, fmt.Errorf("auth: unsupported signing version %q", p.Version)
	}
	prep := &Prepared{
		version:       p.Version,
		signingString: []byte(canonicalString(method, path, body, p, serverAPIVersion)),
		signature:     p.Signature,
	}
	if p.Version == "1.3" {
		prep.sum = sha256.Sum256(prep.signingString)
	}
	return prep, nil
}

// Verify checks the prepared request's signature against pub, refusing a key
// outside CheckPublicKey's bounds before any RSA arithmetic.
func (v *Prepared) Verify(pub *rsa.PublicKey) error {
	if err := CheckPublicKey(pub); err != nil {
		return fmt.Errorf("auth: signature verification failed: %w", err)
	}
	return v.verify(pub)
}

// VerifyAny reports whether the signature verifies against any of pubs, tried
// in order, as erchef tries each of a requestor's unexpired keys. A key
// outside CheckPublicKey's bounds is passed over, and the same public key
// listed more than once (under several key names, say) is tried once.
func (v *Prepared) VerifyAny(pubs []*rsa.PublicKey) bool {
	for _, pub := range distinctKeys(pubs) {
		if v.verify(pub) == nil {
			return true
		}
	}
	return false
}

// verify is Verify for a key already within CheckPublicKey's bounds.
func (v *Prepared) verify(pub *rsa.PublicKey) error {
	switch v.version {
	case "1.0", "1.1":
		// v1.0/1.1 sign by RSA private_encrypt of the raw signing string.
		// Verification recovers the string via the public key and compares.
		recovered, err := rsaPublicDecrypt(pub, v.signature)
		if err != nil {
			return fmt.Errorf("auth: signature verification failed: %w", err)
		}
		if subtle.ConstantTimeCompare(recovered, v.signingString) != 1 {
			return errors.New("auth: signature does not match request")
		}
		return nil
	case "1.3":
		// v1.3 uses RSASSA-PKCS1-v1.5 over SHA256 of the signing string.
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, v.sum[:], v.signature); err != nil {
			return fmt.Errorf("auth: signature verification failed: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("auth: unsupported signing version %q", v.version)
	}
}

// distinctKeys returns the keys of pubs within CheckPublicKey's bounds, in
// order, each public key (modulus and exponent) once.
func distinctKeys(pubs []*rsa.PublicKey) []*rsa.PublicKey {
	type id struct {
		n string
		e int
	}
	out := make([]*rsa.PublicKey, 0, len(pubs))
	seen := make(map[id]struct{}, len(pubs))
	for _, pub := range pubs {
		if CheckPublicKey(pub) != nil {
			continue
		}
		k := id{string(pub.N.Bytes()), pub.E}
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, pub)
	}
	return out
}

// canonicalString builds the Mixlib signing string for the given version.
func canonicalString(method, path string, body []byte, p *Parsed, serverAPIVersion string) string {
	digest := newDigest(p.Algorithm)
	cpath := canonicalPath(path)
	contentHash := hashB64(digest, body)

	switch p.Version {
	case "1.3":
		userID := p.UserID
		if serverAPIVersion == "" {
			// Matches mixlib's DEFAULT_SERVER_API_VERSION when the client
			// sends no X-Ops-Server-API-Version header.
			serverAPIVersion = "0"
		}
		return strings.Join([]string{
			"Method:" + strings.ToUpper(method),
			"Path:" + cpath,
			"X-Ops-Content-Hash:" + contentHash,
			"X-Ops-Sign:version=" + p.Version,
			"X-Ops-Timestamp:" + p.Timestamp,
			"X-Ops-UserId:" + userID,
			"X-Ops-Server-API-Version:" + serverAPIVersion,
		}, "\n")
	default: // 1.0 and 1.1
		userID := p.UserID
		if p.Version == "1.1" {
			userID = hashB64(newDigest(p.Algorithm), []byte(p.UserID))
		}
		hashedPath := hashB64(newDigest(p.Algorithm), []byte(cpath))
		return strings.Join([]string{
			"Method:" + strings.ToUpper(method),
			"Hashed Path:" + hashedPath,
			"X-Ops-Content-Hash:" + contentHash,
			"X-Ops-Timestamp:" + p.Timestamp,
			"X-Ops-UserId:" + userID,
		}, "\n")
	}
}

// canonicalPath collapses repeated slashes and strips a trailing slash unless
// the path is just "/", matching mixlib's canonical_path.
func canonicalPath(path string) string {
	for strings.Contains(path, "//") {
		path = strings.ReplaceAll(path, "//", "/")
	}
	if len(path) > 1 {
		path = strings.TrimSuffix(path, "/")
	}
	if path == "" {
		return "/"
	}
	return path
}

func newDigest(algorithm string) hash.Hash {
	if algorithm == "sha256" {
		return sha256.New()
	}
	return sha1.New()
}

// hashB64 returns the standard base64 encoding of digest(data), matching
// mixlib's Digester.hash_string. Chef inputs are small enough that the encoded
// form never wraps.
func hashB64(h hash.Hash, data []byte) string {
	h.Write(data)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// parseSignDescription parses "algorithm=sha1;version=1.0;" into its parts.
func parseSignDescription(s string) (algorithm, version string) {
	for part := range strings.SplitSeq(s, ";") {
		part = strings.TrimSpace(part)
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "algorithm":
			algorithm = strings.TrimSpace(v)
		case "version":
			version = strings.TrimSpace(v)
		}
	}
	return algorithm, version
}

// joinSignature concatenates the X-Ops-Authorization-N header chunks in order
// and base64-decodes the result.
func joinSignature(h http.Header) ([]byte, error) {
	var b strings.Builder
	for i := 1; ; i++ {
		chunk := h.Get("X-Ops-Authorization-" + strconv.Itoa(i))
		if chunk == "" {
			break
		}
		b.WriteString(strings.TrimSpace(chunk))
	}
	if b.Len() == 0 {
		return nil, errors.New("auth: missing X-Ops-Authorization headers")
	}
	sig, err := base64.StdEncoding.DecodeString(b.String())
	if err != nil {
		return nil, fmt.Errorf("auth: decode signature: %w", err)
	}
	return sig, nil
}

// rsaPublicDecrypt performs the RSA public-key operation (c^e mod n) and strips
// PKCS#1 v1.5 type-1 padding, recovering the message that was signed with
// OpenSSL's private_encrypt (used by Mixlib auth versions 1.0 and 1.1). Go's
// standard library has no public_decrypt, so this is implemented directly.
//
// The key must be within CheckPublicKey's bounds, and the signature exactly as
// long as the modulus, as RSA_private_encrypt always makes it (and as
// rsa.VerifyPKCS1v15 requires for 1.3), before any exponentiation.
func rsaPublicDecrypt(pub *rsa.PublicKey, sig []byte) ([]byte, error) {
	if err := CheckPublicKey(pub); err != nil {
		return nil, err
	}
	k := (pub.N.BitLen() + 7) / 8
	if len(sig) != k {
		return nil, errors.New("signature length does not match the key")
	}
	c := new(big.Int).SetBytes(sig)
	if c.Cmp(pub.N) >= 0 {
		return nil, errors.New("signature out of range")
	}
	m := new(big.Int).Exp(c, big.NewInt(int64(pub.E)), pub.N)

	// Left-pad to the modulus size.
	em := m.Bytes()
	if len(em) > k {
		return nil, errors.New("decrypted block too large")
	}
	block := make([]byte, k)
	copy(block[k-len(em):], em)

	// Expect EMSA-PKCS1 type 1: 0x00 0x01 0xFF...0xFF 0x00 || M
	if block[0] != 0x00 || block[1] != 0x01 {
		return nil, errors.New("invalid PKCS#1 padding header")
	}
	i := 2
	for ; i < len(block); i++ {
		if block[i] != 0xFF {
			break
		}
	}
	if i < 10 || i == len(block) || block[i] != 0x00 {
		return nil, errors.New("invalid PKCS#1 padding")
	}
	return block[i+1:], nil
}
