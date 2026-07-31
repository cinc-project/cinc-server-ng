//go:build differential

// The run against a real Chef Infra Server. It is behind a build tag because it
// needs two live servers, which only the differential CI workflow stands up.
//
// Both targets must present the *same* identity — same user name, same key —
// because a response can legitimately name the actor that created an object
// (per-object ACLs do), and comparing responses produced by two different users
// would report that as a difference every time.
package differential_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tas50/cinc-zero/differential"
	"github.com/tas50/cinc-zero/internal/auth"
)

// Environment the workflow supplies.
const (
	envReferenceURL = "DIFF_REFERENCE_URL" // e.g. https://chef.example/organizations/diffs
	envCandidateURL = "DIFF_CANDIDATE_URL" // e.g. http://127.0.0.1:8889/organizations/diffs
	envUser         = "DIFF_USER"          // the shared identity
	envKeyFile      = "DIFF_KEY"           // its private key, valid on both
	envCAFile       = "DIFF_REFERENCE_CA"  // reference server's CA certificate (optional)
)

func requireEnv(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		t.Fatalf("%s is not set; the differential run needs both servers configured", name)
	}
	return v
}

func TestAgainstRealChefServer(t *testing.T) {
	referenceURL := requireEnv(t, envReferenceURL)
	candidateURL := requireEnv(t, envCandidateURL)
	user := requireEnv(t, envUser)

	keyPEM, err := os.ReadFile(requireEnv(t, envKeyFile))
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	key, err := auth.ParsePrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}

	var ca []byte
	if path := os.Getenv(envCAFile); path != "" {
		if ca, err = os.ReadFile(path); err != nil {
			t.Fatalf("read CA: %v", err)
		}
	}

	reference := &differential.Target{
		Name: "chef-infra-server", BaseURL: referenceURL, User: user, Key: key, CACert: ca,
	}
	candidate := &differential.Target{
		Name: "cinc-zero", BaseURL: candidateURL, User: user, Key: key,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	diffs, err := differential.Run(ctx, differential.Script(), reference, candidate,
		differential.AcceptedDifferences())
	if err != nil {
		t.Fatalf("differential run: %v", err)
	}
	known, unknown := differential.Split(diffs)

	// Report the accepted ones too. They are the compatibility statement, and
	// they should be read rather than silently tolerated.
	if len(known) > 0 {
		var sb strings.Builder
		for _, d := range known {
			sb.WriteString("\n" + d.String())
		}
		t.Logf("%d accepted difference(s):%s", len(known), sb.String())
	}
	if len(unknown) > 0 {
		var sb strings.Builder
		for _, d := range unknown {
			sb.WriteString("\n" + d.String())
		}
		t.Fatalf("%d unexplained difference(s) from the reference server. "+
			"Each is either a fidelity bug to fix, or a deviation to accept in "+
			"differential/known.go with a stated reason:%s", len(unknown), sb.String())
	}
}
