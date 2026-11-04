package api

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// Passwords are stored as PBKDF2-HMAC-SHA256 hashes in a self-describing form:
//
//	pbkdf2-sha256$<iterations>$<salt>$<key>
//
// with the salt and key in unpadded base64 (RawStdEncoding). Verification
// reads the iteration count from the stored hash, so raising the cost for new
// hashes never invalidates existing ones.
const (
	passwordScheme = "pbkdf2-sha256"

	// DefaultPasswordIterations is the PBKDF2 cost for new hashes: OWASP's
	// recommendation for PBKDF2-HMAC-SHA256.
	DefaultPasswordIterations = 600_000

	// maxPasswordIterations bounds the cost a stored hash may ask for, so a
	// corrupt or hand-edited value can't make one login burn minutes of CPU.
	maxPasswordIterations = 10_000_000

	passwordSaltLen = 16
	passwordKeyLen  = 32
)

var passwordIter atomic.Int64

func init() { passwordIter.Store(DefaultPasswordIterations) }

func passwordIterations() int { return int(passwordIter.Load()) }

// SetPasswordIterations changes the PBKDF2 cost for new hashes and returns a
// function that restores the previous value. It exists for tests, which would
// otherwise spend most of their time hashing (the production cost is slow by
// design, and much slower under -race). Production code never calls it.
func SetPasswordIterations(n int) (restore func()) {
	prev := passwordIter.Swap(int64(n))
	return func() { passwordIter.Store(prev) }
}

// HashPassword returns a salted PBKDF2 hash of password in the stored form.
func HashPassword(password string) ([]byte, error) {
	salt := make([]byte, passwordSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("password salt: %w", err)
	}
	iter := passwordIterations()
	key, err := pbkdf2.Key(sha256.New, password, salt, iter, passwordKeyLen)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}
	enc := base64.RawStdEncoding
	return []byte(passwordScheme + "$" + strconv.Itoa(iter) + "$" +
		enc.EncodeToString(salt) + "$" + enc.EncodeToString(key)), nil
}

type passwordHash struct {
	iter      int
	salt, key []byte
}

func parsePasswordHash(stored []byte) (passwordHash, bool) {
	parts := strings.Split(string(stored), "$")
	if len(parts) != 4 || parts[0] != passwordScheme {
		return passwordHash{}, false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1 || iter > maxPasswordIterations {
		return passwordHash{}, false
	}
	enc := base64.RawStdEncoding
	salt, err := enc.DecodeString(parts[2])
	if err != nil || len(salt) == 0 {
		return passwordHash{}, false
	}
	key, err := enc.DecodeString(parts[3])
	if err != nil || len(key) == 0 {
		return passwordHash{}, false
	}
	return passwordHash{iter: iter, salt: salt, key: key}, true
}

// IsPasswordHash reports whether a stored password value is a hash this
// package wrote, rather than the plain text older versions stored.
func IsPasswordHash(stored []byte) bool {
	_, ok := parsePasswordHash(stored)
	return ok
}

// VerifyPassword reports whether password matches a stored value. A stored
// value that isn't a well-formed hash is plain text left by an older version
// (UpgradePasswords converts those at startup) and is compared directly. Both
// comparisons are constant-time.
func VerifyPassword(stored []byte, password string) bool {
	h, ok := parsePasswordHash(stored)
	if !ok {
		return subtle.ConstantTimeCompare(stored, []byte(password)) == 1
	}
	key, err := pbkdf2.Key(sha256.New, password, h.salt, h.iter, len(h.key))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(key, h.key) == 1
}

// UpgradePasswords replaces every plain-text value in a scope's passwords
// collection with a hash and returns how many it converted. Existing hashes
// are left alone, so running it again is a no-op.
func UpgradePasswords(org *store.Org) (int, error) {
	// Collect first: writing to a collection while ranging over it is not
	// safe on every backend.
	plain := map[string]string{}
	err := org.Range(PasswordsCollection, func(name string, raw []byte) bool {
		if !IsPasswordHash(raw) {
			plain[name] = string(raw)
		}
		return true
	})
	if err != nil {
		return 0, err
	}
	for name, pw := range plain {
		h, err := HashPassword(pw)
		if err != nil {
			return 0, err
		}
		if err := org.Put(PasswordsCollection, name, h); err != nil {
			return 0, err
		}
	}
	return len(plain), nil
}
