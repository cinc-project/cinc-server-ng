package api

import (
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

// requestBaseURL reconstructs the scheme://host prefix for building the
// absolute URLs Chef returns in list and create responses.
func requestBaseURL(r *http.Request) string {
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
