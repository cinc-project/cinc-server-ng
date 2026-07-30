package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"strconv"
	"time"
)

// Pre-signed cookbook file-store grants.
//
// The file store cannot use Mixlib signing: chef-client, knife, and cinc fetch
// and upload cookbook file bodies at a URL the server hands them, without
// signing those requests, because a real Chef Infra Server issues pre-signed
// bookshelf URLs there. cinc-zero reproduces that shape rather than leaving the
// endpoint open — the URL itself carries the authorization.
//
// A grant is scoped to one organization, one checksum, and one operation, and
// expires. That keeps a download grant from being replayed as an upload, and
// keeps a grant for one file from reaching another.

// The operations a file-store grant can authorize.
const (
	FileStoreGet = "get"
	FileStorePut = "put"
)

// fileStoreMAC computes the grant's authentication tag. The fields are joined
// with a separator that cannot occur in any of them, so no two distinct grants
// share an input string.
func fileStoreMAC(key []byte, org, checksum, op, exp string) string {
	mac := hmac.New(sha256.New, key)
	for _, field := range []string{org, checksum, op, exp} {
		mac.Write([]byte(field))
		mac.Write([]byte{0})
	}
	return hex.EncodeToString(mac.Sum(nil))
}

// FileStoreQuery returns the URL query string authorizing op on the given
// organization's file-store object until exp. Append it to the file-store URL.
func FileStoreQuery(key []byte, org, checksum, op string, exp time.Time) string {
	expStr := strconv.FormatInt(exp.Unix(), 10)
	q := url.Values{}
	q.Set("op", op)
	q.Set("exp", expStr)
	q.Set("sig", fileStoreMAC(key, org, checksum, op, expStr))
	return q.Encode()
}

// VerifyFileStore checks that q carries a valid, unexpired grant for op on the
// given organization's file-store object. It returns nil only if the request is
// authorized.
func VerifyFileStore(key []byte, org, checksum, op string, q url.Values, now time.Time) error {
	// With no key every grant would be forgeable, since the MAC input is public.
	// Refuse rather than authorize on a key a caller forgot to configure.
	if len(key) == 0 {
		return errors.New("auth: no file store key configured")
	}
	sig := q.Get("sig")
	if sig == "" {
		return errors.New("auth: file store request is not signed")
	}
	expStr := q.Get("exp")
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil {
		return errors.New("auth: file store grant has an invalid expiry")
	}
	// Authenticate before trusting any field, so the expiry cannot be extended
	// by editing the URL: exp is covered by the MAC.
	want := fileStoreMAC(key, org, checksum, q.Get("op"), expStr)
	if !hmac.Equal([]byte(sig), []byte(want)) {
		return errors.New("auth: file store grant is not valid for this request")
	}
	// The grant is authentic; now hold it to the operation it was issued for.
	if q.Get("op") != op {
		return errors.New("auth: file store grant does not authorize this operation")
	}
	if now.After(time.Unix(exp, 0)) {
		return errors.New("auth: file store grant has expired")
	}
	return nil
}
