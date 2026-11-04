package api

import (
	"os"
	"testing"
)

// Password hashing at the production cost (600k PBKDF2 iterations) is slow by
// design, and far slower under -race. Tests verify behavior, not the cost.
func TestMain(m *testing.M) {
	SetPasswordIterations(1000)
	os.Exit(m.Run())
}
