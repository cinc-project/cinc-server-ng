package api

import "net/http"

// registerSystemRoutes wires server-level, unauthenticated status endpoints.
func (a *API) registerSystemRoutes(mux *recordingMux) {
	mux.HandleFunc("GET /_status", func(w http.ResponseWriter, r *http.Request) {
		if a.draining.Load() {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "draining"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "pong",
			"keygen": map[string]any{"keys": 0},
		})
	})
}

// SystemPaths are request paths served without authentication.
var SystemPaths = map[string]bool{
	"/_status":            true,
	"/server_api_version": true,
}

// Drain marks the server as shutting down: from now on /_status answers 503,
// so a load balancer health check takes this instance out of rotation, while
// every other route keeps serving.
func (a *API) Drain() { a.draining.Store(true) }
