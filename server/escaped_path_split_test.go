package server

import "testing"

// TestAuthPathsSplitLikeTheRouter: the org whose clients may authenticate a
// request, and the file-store exemption from signing, are read from the
// escaped path split as the router splits it.
func TestAuthPathsSplitLikeTheRouter(t *testing.T) {
	if got := orgFromPath("/organizations/ac%2Fme/nodes"); got != "ac/me" {
		t.Errorf("orgFromPath = %q, want ac/me", got)
	}
	if got := orgFromPath("/users/bob"); got != "" {
		t.Errorf("orgFromPath(/users/bob) = %q, want none", got)
	}
	if _, _, ok := fileStorePath("/organizations/acme/file_store%2Fabc"); ok {
		t.Error("an escaped slash made a file-store path, exempting it from signing")
	}
	if org, sum, ok := fileStorePath("/organizations/acme/file_store/abc"); !ok || org != "acme" || sum != "abc" {
		t.Errorf("fileStorePath = %q %q %v", org, sum, ok)
	}
}
