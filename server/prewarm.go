package server

import (
	"io"
	"net/http"
	"strings"
)

// prewarm sends a handful of synthetic requests to the freshly started listener
// so the first real client request does not pay the one-time cost of warming the
// whole serving path: accepting a connection, the per-connection read/write
// buffers, route matching, the middleware chain, the JSON encode/decode paths,
// the list-response buffer pool, and growing the GC heap. The cost is paid once
// at startup (where it overlaps nothing the client waits on) instead of on a
// client's first request.
//
// The warm-up requests are intentionally unsigned: the cold cost lives in the
// connection-setup path (accepting the connection, the per-connection buffers,
// reading the request, the middleware chain, and JSON error encoding), all of
// which run before authentication rejects an unsigned request. Skipping the
// signatures keeps startup cheap (no RSA work) while still warming the path that
// matters. None of the requests mutate the store. It returns how many requests
// completed, so a caller can tell the warm-up actually reached the handlers.
func (s *Server) prewarm() int {
	base := s.url + "/organizations/" + s.opts.Orgs[0]
	reqs := []struct{ method, path, body string }{
		{"GET", base + "/nodes", ""},                        // list path + response buffer pool
		{"GET", base + "/nodes/_prewarm_", ""},              // object lookup miss + error JSON
		{"GET", base + "/search/node?q=name:_prewarm_", ""}, // search parse + scan
		{"POST", base + "/nodes", "{}"},                     // body decode, then 400 (no name): no persist
	}

	client := &http.Client{}
	if s.certs != nil {
		client.Transport = &http.Transport{TLSClientConfig: s.certs.selfClientConfig()}
	}
	defer client.CloseIdleConnections()
	done := 0
	for range 2 { // a second pass benefits from the heap the first pass grew
		for _, rq := range reqs {
			req, err := http.NewRequest(rq.method, rq.path, strings.NewReader(rq.body))
			if err != nil {
				continue
			}
			req.Header.Set("X-Ops-Server-API-Version", "1")
			if rq.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			done++
		}
	}
	return done
}
