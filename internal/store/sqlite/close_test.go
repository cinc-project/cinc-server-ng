package sqlite_test

import (
	"path/filepath"
	"testing"

	"github.com/tas50/cinc-server-ng/internal/store/sqlite"
)

// Close has to tolerate being called twice. Shutdown paths overlap in practice
// — a deferred stop plus an explicit one, a cleanup that runs after an error
// path already tore down — and a second close crashing the process is a far
// worse outcome than it being a no-op.
func TestCloseIsIdempotent(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts []sqlite.Option
	}{
		{"default", nil},
		{"group commit", []sqlite.Option{sqlite.WithGroupCommit()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			be, err := sqlite.Open(filepath.Join(t.TempDir(), "x.db"), tc.opts...)
			if err != nil {
				t.Fatal(err)
			}
			if err := be.Close(); err != nil {
				t.Fatalf("first Close: %v", err)
			}
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("second Close panicked: %v", r)
				}
			}()
			if err := be.Close(); err != nil {
				t.Logf("second Close reported: %v", err) // an error is fine; a panic is not
			}
		})
	}
}
