package auth

import (
	"bytes"
	"runtime"
	"testing"
	"time"
	"unsafe"
)

// BenchmarkParseUncached measures the per-request cost the auth path paid
// before caching: a full PEM+x509 parse on every signature verification.
func BenchmarkParseUncached(b *testing.B) {
	key, _ := GenerateKey()
	pemBytes, _ := EncodePublicKeyPEM(&key.PublicKey)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := ParsePublicKey(pemBytes); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkParseCached measures the same lookup served from the cache, i.e. the
// cost on every request after the first from a given actor key.
func BenchmarkParseCached(b *testing.B) {
	key, _ := GenerateKey()
	pemBytes, _ := EncodePublicKeyPEM(&key.PublicKey)
	pemStr := string(pemBytes)
	c := NewPublicKeyCache()
	if _, err := c.Parse(pemStr); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := c.Parse(pemStr); err != nil {
			b.Fatal(err)
		}
	}
}

func TestPublicKeyCacheReusesParsedKey(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err := EncodePublicKeyPEM(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	c := NewPublicKeyCache()
	k1, err := c.Parse(string(pemBytes))
	if err != nil {
		t.Fatalf("first Parse: %v", err)
	}
	k2, err := c.Parse(string(pemBytes))
	if err != nil {
		t.Fatalf("second Parse: %v", err)
	}
	if k1 != k2 {
		t.Fatal("expected the cache to return the same parsed key on a hit")
	}
	if !k1.Equal(&key.PublicKey) {
		t.Fatal("cached key does not match the original public key")
	}
}

func TestPublicKeyCacheReparsesDifferentPEM(t *testing.T) {
	a, _ := GenerateKey()
	b, _ := GenerateKey()
	pa, _ := EncodePublicKeyPEM(&a.PublicKey)
	pb, _ := EncodePublicKeyPEM(&b.PublicKey)
	c := NewPublicKeyCache()
	ka, err := c.Parse(string(pa))
	if err != nil {
		t.Fatal(err)
	}
	kb, err := c.Parse(string(pb))
	if err != nil {
		t.Fatal(err)
	}
	if ka == kb {
		t.Fatal("distinct PEMs should not share a cached key")
	}
	if !ka.Equal(&a.PublicKey) || !kb.Equal(&b.PublicKey) {
		t.Fatal("cache returned the wrong key for a PEM")
	}
}

func TestPublicKeyCacheRejectsInvalidPEMWithoutCaching(t *testing.T) {
	c := NewPublicKeyCache()
	if _, err := c.Parse("not a pem"); err == nil {
		t.Fatal("expected an error for invalid PEM")
	}
	// A subsequent valid Parse must still succeed (the failure was not cached).
	key, _ := GenerateKey()
	p, _ := EncodePublicKeyPEM(&key.PublicKey)
	if _, err := c.Parse(string(p)); err != nil {
		t.Fatalf("valid Parse after invalid: %v", err)
	}
}

// paddedPEM returns pem followed by n bytes of junk: still a key ParsePublicKey
// accepts, since pem.Decode ignores what follows the first block.
func paddedPEM(pem []byte, n int) string {
	b := make([]byte, 0, len(pem)+1+n)
	b = append(b, pem...)
	b = append(b, '\n')
	b = append(b, bytes.Repeat([]byte{'x'}, n)...)
	return string(b)
}

func TestPublicKeyCacheIsBounded(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	p, err := EncodePublicKeyPEM(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	const size = 8
	c := newPublicKeyCache(size)
	// Distinct inputs for the same key: each one is a separate cache entry,
	// as a caller rotating through padded copies of a key would produce.
	for i := range size * 4 {
		if _, err := c.Parse(paddedPEM(p, i)); err != nil {
			t.Fatalf("Parse %d: %v", i, err)
		}
		if n := c.Len(); n > size {
			t.Fatalf("after %d distinct keys the cache holds %d entries, want at most %d", i+1, n, size)
		}
	}
	if n := c.Len(); n != size {
		t.Fatalf("cache holds %d entries, want %d", n, size)
	}
}

func TestPublicKeyCacheEvictsLeastRecentlyUsed(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	p, err := EncodePublicKeyPEM(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	c := newPublicKeyCache(2)
	a, b, d := paddedPEM(p, 1), paddedPEM(p, 2), paddedPEM(p, 3)
	ka, err := c.Parse(a)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := c.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	// Touch a, so b is the least recently used when d arrives.
	if k, _ := c.Parse(a); k != ka {
		t.Fatal("expected a hit for a")
	}
	if _, err := c.Parse(d); err != nil {
		t.Fatal(err)
	}
	if k, _ := c.Parse(a); k != ka {
		t.Fatal("a was used most recently and should still be cached")
	}
	if k, _ := c.Parse(b); k == kb {
		t.Fatal("b was least recently used and should have been evicted")
	}
}

// TestPublicKeyCacheDoesNotRetainInput checks that a cache entry's size does
// not depend on the caller's input: the PEM string must be collectable once
// the caller drops it, while its parsed key stays cached.
func TestPublicKeyCacheDoesNotRetainInput(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	p, err := EncodePublicKeyPEM(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	c := NewPublicKeyCache()
	freed := make(chan struct{})
	func() {
		s := paddedPEM(p, 1<<20)
		runtime.AddCleanup(unsafe.StringData(s), func(ch chan struct{}) { close(ch) }, freed)
		if _, err := c.Parse(s); err != nil {
			t.Fatal(err)
		}
	}()
	defer runtime.KeepAlive(c)
	for range 250 {
		runtime.GC()
		select {
		case <-freed:
			if n := c.Len(); n != 1 {
				t.Fatalf("cache holds %d entries, want 1", n)
			}
			return
		case <-time.After(20 * time.Millisecond):
		}
	}
	t.Fatal("the cache kept the caller's PEM string reachable")
}
