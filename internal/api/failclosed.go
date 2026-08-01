package api

import (
	"net/http"
	"strings"
)

// Failing closed on mutating routes.
//
// classifyRequest is an allowlist, and for most of this server's life an
// unrecognized route was *permitted*. That is not a bug in any one handler; it
// is a default that converts "nobody added a case" into "anyone may do this",
// silently. Five privilege-escalation paths reached production that way.
//
// Two things close it, and the build-time one matters more. Every registered
// mutating route must be classified or declared an exception, checked by a test
// — so the failure happens when the route is written, with a message saying
// what to do, rather than in a review months later. The run-time refusal below
// is the backstop for anything that slips through.
//
// It applies only to requests that matched a real route. Refusing everything
// unclassified would turn "no such path" into 403 and lose the 404 and 405 that
// clients rely on, so the check asks the router first.

// mutatingMethod reports whether a method can change server state. Reads are
// left alone: the consequence of getting a read wrong is disclosure, which the
// per-object ACL checks already govern, and failing closed on reads would break
// the endpoints that are open by design.
func mutatingMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
		return true
	}
	return false
}

// openWrite declares a mutating route that carries no ACL check on purpose.
type openWrite struct {
	// Method and Prefix identify the route. Prefix matches the path after the
	// organization segment, or the whole path for server-level routes.
	Method, Prefix string
	// Reason must say why the route is safe to leave open.
	Reason string
}

// openWrites are the mutating routes that are deliberately not ACL-checked.
// Each is open because something else governs it; none is open merely because
// nobody got to it.
var openWrites = []openWrite{
	{http.MethodPost, "/authenticate_user",
		"verifies a password and is restricted to the superuser (or the web UI) by the handler itself"},
	{http.MethodPost, "/organizations/{org}/sandboxes",
		"announces cookbook checksums; the cookbook write that follows is what carries the ACL check"},
	{http.MethodPut, "/organizations/{org}/sandboxes/",
		"commits a sandbox announced above; the cookbook write is what carries the ACL check"},
	{http.MethodPut, "/organizations/{org}/file_store/",
		"cookbook file transfer, authorized by the pre-signed URL rather than a signed request"},
	{http.MethodPost, "/organizations/{org}/search/",
		"partial search: a read that uses POST to carry the projection in a body"},
	{http.MethodPut, "/users/{user}/association_requests/",
		"an invitation response, which the handler restricts to the invited user"},
	{http.MethodPost, "/organizations/{org}/environments/",
		"cookbook-version solving: a read that uses POST to carry a run list in a body, " +
			"returning only cookbook metadata the caller could read directly"},
}

// openWriteReason returns why a mutating route is deliberately unchecked, or ""
// if it is not one of them.
func openWriteReason(method, path string) string {
	for _, o := range openWrites {
		if o.Method != method {
			continue
		}
		if matchesRoutePrefix(o.Prefix, path) {
			return o.Reason
		}
	}
	return ""
}

// matchesRoutePrefix compares a declared prefix against a concrete path,
// treating "{org}" and "{user}" as single-segment wildcards.
func matchesRoutePrefix(prefix, path string) bool {
	pParts := strings.Split(strings.Trim(prefix, "/"), "/")
	aParts := strings.Split(strings.Trim(path, "/"), "/")
	if len(aParts) < len(pParts) {
		return false
	}
	for i, want := range pParts {
		if strings.HasPrefix(want, "{") && strings.HasSuffix(want, "}") {
			continue
		}
		if aParts[i] != want {
			return false
		}
	}
	// A prefix ending in "/" covers everything below it; otherwise the path must
	// be exactly as deep as the prefix.
	if strings.HasSuffix(prefix, "/") {
		return true
	}
	return len(aParts) == len(pParts)
}

// refuseUnclassifiedWrite reports whether a request that no classification
// covers should nonetheless be refused: it changes state, it matched a real
// route, and nobody declared it open.
func (a *API) refuseUnclassifiedWrite(r *http.Request) bool {
	if !mutatingMethod(r.Method) {
		return false
	}
	if openWriteReason(r.Method, r.URL.Path) != "" {
		return false
	}
	return a.routeMatched(r)
}

// routeMatched asks the router whether this request reaches a registered
// handler. A request that matches nothing, or that matches a path but not its
// method, must keep its 404 or 405 rather than being converted into a 403.
func (a *API) routeMatched(r *http.Request) bool {
	if a.mux == nil {
		return false
	}
	_, pattern := a.mux.Handler(r)
	return pattern != ""
}

// recordingMux is an http.ServeMux that remembers what was registered on it, so
// a test can hold every mutating route to account.
type recordingMux struct {
	mux      *http.ServeMux
	patterns []string
}

func newRecordingMux() *recordingMux {
	return &recordingMux{mux: http.NewServeMux()}
}

func (m *recordingMux) HandleFunc(pattern string, h http.HandlerFunc) {
	m.patterns = append(m.patterns, pattern)
	m.mux.HandleFunc(pattern, h)
}

func (m *recordingMux) Handler(r *http.Request) (http.Handler, string) {
	return m.mux.Handler(r)
}

func (m *recordingMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mux.ServeHTTP(w, r)
}
