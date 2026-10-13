package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

// writeJSON writes v as JSON with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

// writeRaw writes pre-encoded JSON bytes with the given status code.
func writeRaw(w http.ResponseWriter, status int, raw []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}

// writeError writes a Chef-style error body: {"error":["message", ...]}.
func writeError(w http.ResponseWriter, status int, messages ...string) {
	writeJSON(w, status, map[string]any{"error": messages})
}

// externalURLKey carries a configured external URL on the request context.
type externalURLKey struct{}

// withExternalURL makes requestBaseURL answer base for every request.
func withExternalURL(base string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), externalURLKey{}, base)))
	})
}

// requestBaseURL reconstructs the scheme://host prefix for building the
// absolute URLs Chef returns in list and create responses. A configured
// external URL takes precedence over anything the request says.
func requestBaseURL(r *http.Request) string {
	if base, ok := r.Context().Value(externalURLKey{}).(string); ok {
		return base
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if proto := forwardedScheme(r); proto != "" {
		scheme = proto
	}
	return scheme + "://" + r.Host
}

// forwardedScheme reads the scheme a reverse proxy reports for the original
// request, or "" when there is none to honor.
//
// The header is only trustworthy behind a proxy that sets it; on a direct
// connection it arrives from the client, and it decides the scheme of every URL
// the server hands back — including the pre-signed file-store URLs a
// chef-client then fetches. So only the two schemes this server can actually be
// reached on are accepted, and anything else leaves the scheme the connection
// really used. A chained proxy appends to the header, and the first entry is the
// original client's.
func forwardedScheme(r *http.Request) string {
	first, _, _ := strings.Cut(r.Header.Get("X-Forwarded-Proto"), ",")
	switch scheme := strings.ToLower(strings.TrimSpace(first)); scheme {
	case "http", "https":
		return scheme
	}
	return ""
}
