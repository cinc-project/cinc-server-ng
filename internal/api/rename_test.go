package api

import "testing"

// A rename skips decoding a stored document that cannot name the renamed
// object, but must never skip one that can, however the name is spelled.
func TestMayName(t *testing.T) {
	for _, tc := range []struct {
		raw, name string
		want      bool
	}{
		{`{"read":{"users":["bob"]}}`, "bob", true},
		{`{"read":{"users":["bobby","alice"]}}`, "bob", false},
		{`{"read":{"users":["alice"]}}`, "bob", false},
		// An escaped spelling of the name still names it.
		{`{"read":{"users":["bob"]}}`, "bob", true},
		{`{"read":{"users":["bob"]}}`, "bob", true},
		// A name JSON may escape is never ruled out by bytes.
		{`{"read":{"users":["a\/b"]}}`, "a/b", true},
		{`{"read":{"users":[]}}`, "a<b", true},
		{`{"read":{"users":[]}}`, `a"b`, true},
		{`{"read":{"users":[]}}`, "zoë", true},
		{`{"read":{"users":["web-01.example"]}}`, "web-01.example", true},
		{`{"read":{"users":["web-01.example2"]}}`, "web-01.example", false},
	} {
		if got := mayName([]byte(tc.raw), tc.name); got != tc.want {
			t.Errorf("mayName(%s, %q) = %v, want %v", tc.raw, tc.name, got, tc.want)
		}
	}
}
