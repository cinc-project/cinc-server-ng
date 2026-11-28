package auth

import (
	"crypto/rsa"
	"math/big"
	"testing"
)

// TestPreparedVerifiesGoldenVectors: a request prepared once verifies, on
// every protocol version, exactly as Verify does.
func TestPreparedVerifiesGoldenVectors(t *testing.T) {
	vf, pub := loadVectors(t)
	for _, v := range vf.Cases {
		t.Run(v.ProtoVersion+"_"+v.HTTPMethod+"_"+v.Path, func(t *testing.T) {
			h := header(v)
			p, err := Parse(h)
			if err != nil {
				t.Fatal(err)
			}
			body := []byte(v.Body)
			prep, err := Prepare(v.HTTPMethod, v.Path, body, p, h.Get("X-Ops-Server-API-Version"))
			if err != nil {
				t.Fatalf("Prepare: %v", err)
			}
			// The body is hashed by Prepare and never again: trying a key
			// does not read it.
			for i := range body {
				body[i] ^= 0xff
			}
			if err := prep.Verify(pub); err != nil {
				t.Fatalf("Verify: %v", err)
			}
			other := mustParsePub(t, generateOtherPubPEM(t))
			if prep.VerifyAny([]*rsa.PublicKey{other}) {
				t.Fatal("verified against a key that did not sign")
			}
			if !prep.VerifyAny([]*rsa.PublicKey{other, other, pub}) {
				t.Fatal("did not verify against the signing key among several")
			}
		})
	}
}

// TestPreparedRefusesTamperedBody: the body hashed at Prepare is the one the
// signature must cover.
func TestPreparedRefusesTamperedBody(t *testing.T) {
	vf, pub := loadVectors(t)
	for _, v := range vf.Cases {
		if v.Body == "" {
			continue
		}
		h := header(v)
		p, err := Parse(h)
		if err != nil {
			t.Fatal(err)
		}
		prep, err := Prepare(v.HTTPMethod, v.Path, []byte(v.Body+"x"), p, h.Get("X-Ops-Server-API-Version"))
		if err != nil {
			t.Fatal(err)
		}
		if prep.VerifyAny([]*rsa.PublicKey{pub}) {
			t.Fatalf("%s: verified a tampered body", v.ProtoVersion)
		}
	}
}

func TestPrepareRefusesUnsupportedVersion(t *testing.T) {
	if _, err := Prepare("GET", "/", nil, &Parsed{Version: "1.2", Algorithm: "sha1"}, ""); err == nil {
		t.Fatal("Prepare accepted version 1.2")
	}
}

// TestPreparedVerifyAnySkipsUnusableKeys: a nil or out-of-bounds key is passed
// over, not fatal to the keys after it.
func TestPreparedVerifyAnySkipsUnusableKeys(t *testing.T) {
	vf, pub := loadVectors(t)
	v := vf.Cases[0]
	h := header(v)
	p, err := Parse(h)
	if err != nil {
		t.Fatal(err)
	}
	prep, err := Prepare(v.HTTPMethod, v.Path, []byte(v.Body), p, h.Get("X-Ops-Server-API-Version"))
	if err != nil {
		t.Fatal(err)
	}
	small := &rsa.PublicKey{N: big.NewInt(3233), E: 17}
	if !prep.VerifyAny([]*rsa.PublicKey{nil, small, pub}) {
		t.Fatal("an unusable key stopped the search")
	}
}

// TestDistinctKeys: the same public key, held under many key names or parsed
// from different PEM encodings, is tried once.
func TestDistinctKeys(t *testing.T) {
	a := mustParsePub(t, generateOtherPubPEM(t))
	b := mustParsePub(t, generateOtherPubPEM(t))
	aCopy := &rsa.PublicKey{N: new(big.Int).Set(a.N), E: a.E}
	aOtherE := &rsa.PublicKey{N: new(big.Int).Set(a.N), E: 3}
	got := distinctKeys([]*rsa.PublicKey{a, a, aCopy, b, aOtherE, b, nil})
	want := []*rsa.PublicKey{a, b, aOtherE}
	if len(got) != len(want) {
		t.Fatalf("got %d keys, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("key %d: order or identity not kept", i)
		}
	}
}

// BenchmarkPreparedManyKeys measures trying one request against many keys:
// the body is hashed once, whatever the key count.
func BenchmarkPreparedManyKeys(b *testing.B) {
	body := make([]byte, 2<<20)
	other, err := GenerateKey()
	if err != nil {
		b.Fatal(err)
	}
	pubs := make([]*rsa.PublicKey, 100)
	for i := range pubs {
		pubs[i] = &other.PublicKey
	}
	p := &Parsed{Version: "1.3", Algorithm: "sha256", UserID: "u", Timestamp: "t", Signature: make([]byte, 256)}
	for b.Loop() {
		prep, err := Prepare("POST", "/x", body, p, "")
		if err != nil {
			b.Fatal(err)
		}
		prep.VerifyAny(pubs)
	}
}
