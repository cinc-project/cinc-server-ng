package server

import (
	"os"
	"testing"

	"github.com/cinc-project/cinc-server-ng/internal/api"
)

// Password hashing at the production cost (600k PBKDF2 iterations) is slow by
// design, and far slower under -race. Tests verify behavior, not the cost.
func TestMain(m *testing.M) {
	api.SetPasswordIterations(1000)
	os.Exit(m.Run())
}
