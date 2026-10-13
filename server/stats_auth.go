package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
)

// /_stats authentication.
//
// Chef Infra Server does not authenticate /_stats in erchef at all: the
// resource has no auth callbacks, and nginx in front of it demands HTTP Basic
// credentials (user "statsuser", password the generated opscode_erchef
// stats_password) from an htpasswd file. A Mixlib signature is neither needed
// nor sufficient. cinc-server-ng has no nginx, so the auth layer plays its part.

// DefaultStatsUser is Chef Infra Server's stats user name.
const DefaultStatsUser = "statsuser"

// statsPath is the stats endpoint.
const statsPath = "/_stats"

// statsRealm is the realm Chef Infra Server's nginx config announces.
const statsRealm = "Chef Server Admin Stats"

// generateStatsPassword returns a random password for a server started without
// one: 48 random bytes, URL-safe base64 (64 characters).
func generateStatsPassword() (string, error) {
	b := make([]byte, 48)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate stats password: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// statsAuthorized reports whether r carries the configured stats credentials.
// Both halves are compared in constant time, over fixed-length digests so the
// comparison does not reveal the configured lengths either, and both are always
// evaluated.
func (s *Server) statsAuthorized(r *http.Request) bool {
	user, password, ok := r.BasicAuth()
	if !ok {
		return false
	}
	userOK := equalDigest(user, s.opts.StatsUser)
	passwordOK := equalDigest(password, s.opts.StatsPassword)
	return userOK&passwordOK == 1
}

func equalDigest(got, want string) int {
	g := sha256.Sum256([]byte(got))
	w := sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(g[:], w[:])
}

// statsUnauthorized is the 401 for missing or wrong stats credentials: a
// Basic challenge, so a browser or scraper knows what to send, and the JSON
// error body every other rejection uses.
func statsUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="`+statsRealm+`"`)
	unauthorized(w, "/_stats requires HTTP Basic authentication with the stats user and password")
}
