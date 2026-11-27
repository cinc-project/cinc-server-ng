package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
)

// GenerateKey creates a new 2048-bit RSA key pair, the size Chef uses for
// client and user keys.
func GenerateKey() (*rsa.PrivateKey, error) {
	return GenerateKeyFrom(rand.Reader)
}

// GenerateKeyFrom creates a 2048-bit RSA key pair drawing entropy from r. It
// exists so callers generating several keys in parallel can give each goroutine
// its own buffered reader over crypto/rand, avoiding lock contention on the
// global rand.Reader during prime search. r must be a cryptographically secure
// source (e.g. crypto/rand.Reader, optionally wrapped in a bufio.Reader).
func GenerateKeyFrom(r io.Reader) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(r, 2048)
}

// Bounds on the RSA public keys cinc-server-ng stores and verifies with.
//
// Every RSA operation costs time that grows with the modulus and the
// exponent, and a request is checked against each of the named actor's keys
// before anything shows its signature is genuine. An unbounded key (a request
// body can carry a modulus of millions of bits, or a 63-bit exponent) would
// let anyone pin a CPU per request with a fake signature naming its owner.
//
//   - Modulus: 1024 to 16384 bits. chef-client, knife and Chef Infra Server
//     generate 2048-bit keys and some sites use 4096; 1024 is the floor Go's
//     crypto/rsa enforces anyway (so a smaller key could never verify a 1.3
//     signature), and 16384 is OpenSSL's OPENSSL_RSA_MAX_MODULUS_BITS, past
//     which OpenSSL, and so erchef, refuses the public-key operation.
//   - Exponent: odd, 3 to 2^31-1, the range Go's crypto/rsa accepts for
//     verification. Real keys use 65537 (or, rarely, 3).
const (
	MinPublicKeyBits     = 1024
	MaxPublicKeyBits     = 16384
	minPublicKeyExponent = 3
	maxPublicKeyExponent = 1<<31 - 1
)

// CheckPublicKey reports whether pub is within the bounds above, without
// doing any RSA arithmetic.
func CheckPublicKey(pub *rsa.PublicKey) error {
	if pub == nil || pub.N == nil || pub.N.Sign() <= 0 {
		return errors.New("auth: missing RSA modulus")
	}
	if bits := pub.N.BitLen(); bits < MinPublicKeyBits || bits > MaxPublicKeyBits {
		return fmt.Errorf("auth: RSA modulus of %d bits is outside %d to %d", bits, MinPublicKeyBits, MaxPublicKeyBits)
	}
	if pub.E < minPublicKeyExponent || pub.E > maxPublicKeyExponent || pub.E%2 == 0 {
		return fmt.Errorf("auth: RSA public exponent %d is not an odd number from %d to %d", pub.E, minPublicKeyExponent, maxPublicKeyExponent)
	}
	return nil
}

// ParsePublicKey parses a PEM-encoded RSA public key. It accepts both
// "PUBLIC KEY" (PKIX/SubjectPublicKeyInfo) and "RSA PUBLIC KEY" (PKCS#1)
// blocks, which together cover what Chef stores and what clients send.
func ParsePublicKey(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("auth: no PEM block found in public key")
	}
	switch block.Type {
	case "PUBLIC KEY":
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("auth: parse PKIX public key: %w", err)
		}
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("auth: public key is not RSA")
		}
		return checkedPublicKey(rsaKey)
	case "RSA PUBLIC KEY":
		rsaKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return checkedPublicKey(rsaKey)
	default:
		return nil, fmt.Errorf("auth: unexpected PEM type %q for public key", block.Type)
	}
}

// checkedPublicKey returns pub if CheckPublicKey accepts it: a key outside
// the bounds does not parse, so it is neither stored nor verified with.
func checkedPublicKey(pub *rsa.PublicKey) (*rsa.PublicKey, error) {
	if err := CheckPublicKey(pub); err != nil {
		return nil, err
	}
	return pub, nil
}

// ParsePrivateKey parses a PEM-encoded RSA private key in PKCS#1 ("RSA PRIVATE
// KEY") or PKCS#8 ("PRIVATE KEY") form.
func ParsePrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("auth: no PEM block found in private key")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("auth: parse PKCS8 private key: %w", err)
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("auth: private key is not RSA")
		}
		return rsaKey, nil
	default:
		return nil, fmt.Errorf("auth: unexpected PEM type %q for private key", block.Type)
	}
}

// EncodePrivateKeyPEM returns the PKCS#1 PEM encoding of key, the format Chef
// writes for client keys (e.g. the validator and admin keys).
func EncodePrivateKeyPEM(key *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

// EncodePublicKeyPEM returns the PKIX ("PUBLIC KEY") PEM encoding of pub, the
// format Chef stores and returns for actor public keys.
func EncodePublicKeyPEM(pub *rsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}
