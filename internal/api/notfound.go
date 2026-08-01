package api

import "net/http"

// withJSONErrors wraps mux so that requests which match no route fall back to a
// Chef-compatible JSON error body instead of net/http's plaintext defaults
// ("404 page not found", "Method Not Allowed"). Matched routes are served
// untouched — the success path is never buffered.
func withJSONErrors(mux *recordingMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A non-empty pattern means a route (or a redirect) matched; serve it
		// normally. Only genuinely unmatched requests are rewritten.
		if _, pattern := mux.Handler(r); pattern != "" {
			mux.ServeHTTP(w, r)
			return
		}
		// Let the mux's own default handler decide 404 vs 405 (and populate the
		// Allow header for a method mismatch), capturing the outcome instead of
		// emitting its plaintext body.
		cap := &statusCapture{header: http.Header{}}
		mux.ServeHTTP(cap, r)
		if cap.status == http.StatusMethodNotAllowed {
			if allow := cap.header.Get("Allow"); allow != "" {
				w.Header().Set("Allow", allow)
			}
			writeError(w, http.StatusMethodNotAllowed, "Method not allowed: "+r.Method+" "+r.URL.Path)
			return
		}
		writeError(w, http.StatusNotFound, "No route for "+r.URL.Path)
	})
}

// statusCapture is a minimal http.ResponseWriter that records the status code
// and headers of the response while discarding its body. It is used only on the
// unmatched-route path to learn whether the mux produced a 404 or a 405.
type statusCapture struct {
	status int
	header http.Header
}

func (c *statusCapture) Header() http.Header         { return c.header }
func (c *statusCapture) WriteHeader(code int)        { c.status = code }
func (c *statusCapture) Write(b []byte) (int, error) { return len(b), nil }
