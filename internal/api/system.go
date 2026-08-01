package api

import "net/http"

// registerSystemRoutes wires server-level, unauthenticated status endpoints.
func (a *API) registerSystemRoutes(mux *recordingMux) {
	mux.HandleFunc("GET /_status", func(w http.ResponseWriter, r *http.Request) {
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
