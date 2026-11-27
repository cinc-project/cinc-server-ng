package api

import (
	"context"
	"net/http"
	"time"
)

// healthPingTimeout bounds each upstream check, as erchef's health_ping_timeout
// (400 ms by default) does: a check that has not answered by then is a failure.
const healthPingTimeout = 400 * time.Millisecond

// statusResponse is /_status in erchef's member order
// (chef_wm_status:check_health): status, upstreams, keygen, indexing.
type statusResponse struct {
	Status    string         `json:"status"`
	Upstreams statusUpstream `json:"upstreams"`
	Keygen    statusKeygen   `json:"keygen"`
	Indexing  statusIndexing `json:"indexing"`
}

// statusUpstream keeps erchef's upstream names, so a monitor keyed on them
// works unchanged, each mapped onto what plays that part here: chef_solr is the
// in-process search index, chef_sql the store backend (pinged, so a closed or
// unreadable SQLite database fails), and oc_chef_authz the in-process
// authorization layer. Each value is "pong" or "fail"; erchef reports a timed
// out check as "fail" too.
type statusUpstream struct {
	ChefSolr    string `json:"chef_solr"`
	ChefSQL     string `json:"chef_sql"`
	OcChefAuthz string `json:"oc_chef_authz"`
}

// statusKeygen is chef_keygen_cache:status_for_json's shape. There is no
// pre-generated key cache or worker pool here: a key is generated inline by the
// request that asks for one, so every count is zero.
type statusKeygen struct {
	Keys          int `json:"keys"`
	Max           int `json:"max"`
	MaxWorkers    int `json:"max_workers"`
	CurMaxWorkers int `json:"cur_max_workers"`
	Inflight      int `json:"inflight"`
	AvailWorkers  int `json:"avail_workers"`
	StartSize     int `json:"start_size"`
}

// statusIndexing is chef_index:status. Writes update the search index
// synchronously, before the request returns, which is erchef's "inline" mode
// rather than its queued "batch" mode.
type statusIndexing struct {
	Mode string `json:"mode"`
}

// registerSystemRoutes wires server-level, unauthenticated status endpoints.
func (a *API) registerSystemRoutes(mux *recordingMux) {
	mux.HandleFunc("GET /_status", func(w http.ResponseWriter, r *http.Request) {
		if a.draining.Load() {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "draining"})
			return
		}
		resp := statusResponse{
			Status: "pong",
			Upstreams: statusUpstream{
				ChefSolr:    "pong",
				ChefSQL:     a.pingStore(r.Context()),
				OcChefAuthz: "pong",
			},
			Indexing: statusIndexing{Mode: "inline"},
		}
		code := http.StatusOK
		if resp.Upstreams.ChefSQL != "pong" {
			resp.Status = "fail"
			code = http.StatusInternalServerError
		}
		writeJSON(w, code, resp)
	})
}

// pingStore checks the store backend within healthPingTimeout. The ping runs on
// its own goroutine so a backend that ignores its context still cannot hold
// the health check past the timeout.
func (a *API) pingStore(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, healthPingTimeout)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- a.store.Ping(ctx) }()
	select {
	case err := <-done:
		if err != nil {
			return "fail"
		}
		return "pong"
	case <-ctx.Done():
		return "fail"
	}
}

// SystemPaths are request paths served without authentication.
// /server_api_version is not one: erchef signs it like any API route.
var SystemPaths = map[string]bool{
	"/_status": true,
}

// Drain marks the server as shutting down: from now on /_status answers 503,
// so a load balancer health check takes this instance out of rotation, while
// every other route keeps serving.
func (a *API) Drain() { a.draining.Store(true) }
