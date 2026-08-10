package store_test

import (
	"testing"

	"github.com/tas50/cinc-server-ng/internal/store"
	"github.com/tas50/cinc-server-ng/internal/store/backendtest"
)

// TestMemoryBackendConformance runs the shared Backend conformance suite against
// the default in-memory backend. It lives in an external test package so it can
// import backendtest (which imports store) without an import cycle.
func TestMemoryBackendConformance(t *testing.T) {
	backendtest.Run(t, func(t *testing.T) store.Backend { return store.NewMemoryBackend() })
}
