package auth

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

var presignKey = []byte("0123456789abcdef0123456789abcdef")

// query builds the signed query for a grant and parses it back, the way a
// client would after receiving the URL.
func query(t *testing.T, key []byte, org, checksum, op string, exp time.Time) url.Values {
	t.Helper()
	q, err := url.ParseQuery(FileStoreQuery(key, org, checksum, op, exp))
	if err != nil {
		t.Fatalf("parse signed query: %v", err)
	}
	return q
}

func TestFileStoreQueryVerifies(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	q := query(t, presignKey, "acme", "abc123", FileStoreGet, now.Add(time.Hour))
	if err := VerifyFileStore(presignKey, "acme", "abc123", FileStoreGet, q, now); err != nil {
		t.Fatalf("freshly signed grant rejected: %v", err)
	}
}

func TestFileStoreQueryRejectsTampering(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	signed := query(t, presignKey, "acme", "abc123", FileStoreGet, now.Add(time.Hour))

	cases := []struct {
		name             string
		org, sum, op     string
		mutate           func(url.Values)
		wantVerifyFailed bool
	}{
		{name: "different checksum", org: "acme", sum: "deadbeef", op: FileStoreGet},
		{name: "different org", org: "other", sum: "abc123", op: FileStoreGet},
		{name: "get grant replayed as put", org: "acme", sum: "abc123", op: FileStorePut},
		{name: "expiry extended", org: "acme", sum: "abc123", op: FileStoreGet,
			mutate: func(q url.Values) { q.Set("exp", "99999999999") }},
		{name: "signature forged", org: "acme", sum: "abc123", op: FileStoreGet,
			mutate: func(q url.Values) { q.Set("sig", strings.Repeat("a", 64)) }},
		{name: "signature dropped", org: "acme", sum: "abc123", op: FileStoreGet,
			mutate: func(q url.Values) { q.Del("sig") }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			q := url.Values{}
			for k, v := range signed {
				q[k] = append([]string(nil), v...)
			}
			if c.mutate != nil {
				c.mutate(q)
			}
			if err := VerifyFileStore(presignKey, c.org, c.sum, c.op, q, now); err == nil {
				t.Fatalf("%s: accepted, want rejection", c.name)
			}
		})
	}
}

func TestFileStoreQueryRejectsExpired(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	q := query(t, presignKey, "acme", "abc123", FileStoreGet, now.Add(time.Minute))
	if err := VerifyFileStore(presignKey, "acme", "abc123", FileStoreGet, q, now.Add(2*time.Minute)); err == nil {
		t.Fatal("expired grant accepted, want rejection")
	}
}

// An unset key must authorize nothing. Otherwise a caller that verifies with a
// key it forgot to configure would accept grants anyone could compute.
func TestFileStoreVerifyRejectsEmptyKey(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	q := query(t, nil, "acme", "abc123", FileStoreGet, now.Add(time.Hour))
	if err := VerifyFileStore(nil, "acme", "abc123", FileStoreGet, q, now); err == nil {
		t.Fatal("grant verified against an empty key, want rejection")
	}
}

func TestFileStoreQueryRejectsOtherKey(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	q := query(t, presignKey, "acme", "abc123", FileStoreGet, now.Add(time.Hour))
	other := []byte("ffffffffffffffffffffffffffffffff")
	if err := VerifyFileStore(other, "acme", "abc123", FileStoreGet, q, now); err == nil {
		t.Fatal("grant signed by another key accepted, want rejection")
	}
}
