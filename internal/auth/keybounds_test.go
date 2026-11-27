package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/http"
	"strconv"
	"testing"
	"time"
)

// craftedPublicKeyPEM marshals an RSA public key with an arbitrary modulus
// size and exponent, without generating a key pair: the modulus is
// 2^(bits-1)+1, which has exactly bits bits and is odd.
func craftedPublicKeyPEM(t *testing.T, bits int, e int) []byte {
	t.Helper()
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	n.Add(n, big.NewInt(1))
	der, err := x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: n, E: e})
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func TestParsePublicKeyBoundsModulusAndExponent(t *testing.T) {
	for _, c := range []struct {
		name string
		bits int
		e    int
		ok   bool
	}{
		{"1024-bit", 1024, 65537, true},
		{"2048-bit", 2048, 65537, true},
		{"4096-bit", 4096, 65537, true},
		{"16384-bit", MaxPublicKeyBits, 65537, true},
		{"exponent 3", 2048, 3, true},
		{"largest exponent", 2048, 1<<31 - 1, true},
		{"512-bit", 512, 65537, false},
		{"1023-bit", MinPublicKeyBits - 1, 65537, false},
		{"16385-bit", MaxPublicKeyBits + 1, 65537, false},
		{"10-Mbit", 10_000_000, 65537, false},
		{"exponent 1", 2048, 1, false},
		{"even exponent", 2048, 65536, false},
		{"exponent past 2^31-1", 2048, 1<<31 + 1, false},
		{"huge exponent", 2048, 1<<62 + 1, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParsePublicKey(craftedPublicKeyPEM(t, c.bits, c.e))
			if (err == nil) != c.ok {
				t.Errorf("ParsePublicKey(%d bits, e=%d) error = %v, want ok=%v", c.bits, c.e, err, c.ok)
			}
		})
	}
}

// The PKCS#1 ("RSA PUBLIC KEY") form is bounded the same way.
func TestParsePKCS1PublicKeyBounded(t *testing.T) {
	n := new(big.Int).Lsh(big.NewInt(1), MaxPublicKeyBits)
	n.Add(n, big.NewInt(1))
	der := x509.MarshalPKCS1PublicKey(&rsa.PublicKey{N: n, E: 65537})
	if _, err := ParsePublicKey(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: der})); err == nil {
		t.Error("ParsePublicKey accepted an oversized PKCS#1 key")
	}
}

// unsignedHeaders returns X-Ops headers for a request naming "mallory" with
// an arbitrary signature, as an unauthenticated caller would send them.
func unsignedHeaders(version string, sig []byte) http.Header {
	h := http.Header{}
	h.Set("X-Ops-Sign", "version="+version)
	h.Set("X-Ops-Userid", "mallory")
	h.Set("X-Ops-Timestamp", "2026-01-01T00:00:00Z")
	h.Set("X-Ops-Content-Hash", "x")
	h.Set("X-Ops-Authorization-1", base64.StdEncoding.EncodeToString(sig))
	return h
}

// A key outside the bounds never verifies, and is refused before any RSA
// arithmetic: with a 16-Mbit modulus and a 63-bit exponent the
// exponentiation alone would run for a very long time.
func TestVerifyRefusesOversizedKeyWithoutExponentiating(t *testing.T) {
	n := new(big.Int).Lsh(big.NewInt(1), 1<<24)
	n.Add(n, big.NewInt(1))
	huge := &rsa.PublicKey{N: n, E: 1<<62 + 1}
	k := (n.BitLen() + 7) / 8
	for _, version := range []string{"1.0", "1.1", "1.3"} {
		for _, size := range []int{1, k} {
			sig := make([]byte, size)
			sig[size-1] = 2
			start := time.Now()
			if err := VerifyRequest("GET", "/users", nil, unsignedHeaders(version, sig), huge); err == nil {
				t.Errorf("v%s: oversized key verified a %d-byte signature", version, size)
			}
			if d := time.Since(start); d > 2*time.Second {
				t.Errorf("v%s: refusing an oversized key took %v", version, d)
			}
		}
	}
	// So does a key whose exponent is outside the bounds.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []int{1, 2, 1<<31 + 1, 1<<62 + 1} {
		pub := &rsa.PublicKey{N: key.N, E: e}
		sig := make([]byte, key.Size())
		sig[len(sig)-1] = 2
		if err := VerifyRequest("GET", "/users", nil, unsignedHeaders("1.0", sig), pub); err == nil {
			t.Errorf("e=%d verified", e)
		}
	}
}

// A PKCS#1 v1.5 signature is always as long as the modulus (OpenSSL's
// private_encrypt, which Mixlib 1.0/1.1 signs with, pads it to RSA_size), so
// a shorter one is refused even when its value would decrypt correctly.
// Without the check a 1-byte signature forces the full exponentiation.
func TestVerifyV10RefusesShortSignature(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	k := key.Size()
	// Find a signing string whose signature has a leading zero byte, so the
	// same value can be sent one byte shorter.
	for i := range 8192 {
		p := &Parsed{Version: "1.0", Algorithm: "sha1", UserID: "alice", Timestamp: strconv.Itoa(i)}
		msg := []byte(canonicalString("GET", "/users", nil, p, ""))
		sig := privateEncrypt(key, msg)
		if sig[0] != 0 {
			continue
		}
		p.Signature = sig
		if err := Verify("GET", "/users", nil, p, "", &key.PublicKey); err != nil {
			t.Fatalf("full-length signature: %v", err)
		}
		p.Signature = sig[1:]
		if err := Verify("GET", "/users", nil, p, "", &key.PublicKey); err == nil {
			t.Fatalf("a %d-byte signature for a %d-byte modulus verified", k-1, k)
		}
		return
	}
	t.Fatal("no signature with a leading zero byte found")
}

// privateEncrypt is OpenSSL's RSA_private_encrypt with PKCS#1 type 1 padding,
// what Mixlib 1.0/1.1 signs with.
func privateEncrypt(key *rsa.PrivateKey, msg []byte) []byte {
	k := key.Size()
	em := make([]byte, k)
	em[1] = 1
	for i := 2; i < k-len(msg)-1; i++ {
		em[i] = 0xFF
	}
	copy(em[k-len(msg):], msg)
	m := new(big.Int).SetBytes(em)
	c := new(big.Int).Exp(m, key.D, key.N)
	return c.FillBytes(make([]byte, k))
}
