package server

import (
	"encoding/json"
	"testing"

	"github.com/tas50/cinc-server-ng/internal/auth"
)

// TestServerNewMultiOrgValidatorKeysMatch verifies that each org's returned
// validator private key matches the public key stored on its validator client,
// and that the admin key is valid. This guards the bootstrap against mismatching
// keys to orgs now that they are generated in parallel.
func TestServerNewMultiOrgValidatorKeysMatch(t *testing.T) {
	orgs := []string{"alpha", "beta", "gamma"}
	s, err := New(Options{Orgs: orgs, DisableAuth: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range orgs {
		priv, err := auth.ParsePrivateKey(s.ValidatorKey(name))
		if err != nil {
			t.Fatalf("parse validator key for %q: %v", name, err)
		}
		org, ok, err := s.Store().Org(name)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Fatalf("org %q missing", name)
		}
		raw, ok, err := org.Get("clients", name+"-validator")
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Fatalf("validator client missing for %q", name)
		}
		var client struct {
			PublicKey string `json:"public_key"`
		}
		if err := json.Unmarshal(raw, &client); err != nil {
			t.Fatal(err)
		}
		storedPub, err := auth.ParsePublicKey([]byte(client.PublicKey))
		if err != nil {
			t.Fatalf("parse stored public key for %q: %v", name, err)
		}
		if priv.PublicKey.N.Cmp(storedPub.N) != 0 || priv.PublicKey.E != storedPub.E {
			t.Fatalf("validator key for %q does not match its stored public key", name)
		}
	}
	if _, err := auth.ParsePrivateKey(s.AdminKey()); err != nil {
		t.Fatalf("admin key invalid: %v", err)
	}
}

// BenchmarkServerNew1Org and BenchmarkServerNew3Orgs track bootstrap latency,
// which is dominated by RSA-2048 key generation (one admin key plus one
// validator key per org, generated in parallel).
func BenchmarkServerNew1Org(b *testing.B) {
	for b.Loop() {
		if _, err := New(Options{Orgs: []string{"acme"}, DisableAuth: true}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkServerNew3Orgs(b *testing.B) {
	for b.Loop() {
		if _, err := New(Options{Orgs: []string{"a", "b", "c"}, DisableAuth: true}); err != nil {
			b.Fatal(err)
		}
	}
}
