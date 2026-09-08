package api

import "testing"

// "~> 1" means ">= 1, < 2" — the last specified component is the one allowed to
// move. A one-component constraint was treated as unbounded above, so an
// environment pinned to "~> 1" would hand a node a 2.x cookbook: exactly the
// major-version jump the pessimistic operator exists to prevent.
func TestPessimisticConstraintUpperBound(t *testing.T) {
	cases := []struct {
		version, constraint string
		want                bool
	}{
		{"1.0.0", "~> 1", true},
		{"1.9.9", "~> 1", true},
		{"2.0.0", "~> 1", false},
		{"10.0.0", "~> 1", false},
		{"0.9.0", "~> 1", false},

		// Unchanged: the multi-component cases.
		{"1.2.0", "~> 1.2", true},
		{"1.9.9", "~> 1.2", true},
		{"2.0.0", "~> 1.2", false},
		{"1.1.0", "~> 1.2", false},
		{"1.2.3", "~> 1.2.3", true},
		{"1.2.9", "~> 1.2.3", true},
		{"1.3.0", "~> 1.2.3", false},
		{"1.2.2", "~> 1.2.3", false},

		{"0.1.0", "~> 0", true},
		{"1.0.0", "~> 0", false},
	}
	for _, c := range cases {
		if got := satisfiesConstraint(c.version, c.constraint); got != c.want {
			t.Errorf("satisfiesConstraint(%q, %q) = %v, want %v",
				c.version, c.constraint, got, c.want)
		}
	}
}
