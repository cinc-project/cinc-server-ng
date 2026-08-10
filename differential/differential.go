// Package differential compares cinc-zero's API responses against a real Chef
// Infra Server by issuing the same requests to both and diffing what comes
// back.
//
// Every other test in this repository asserts cinc-zero against its own idea of
// correct. A conformance suite gets closer — a real client either works or does
// not — but clients are lenient: knife will happily accept a response with a
// missing field, an extra field, or the wrong type, so "the client did not
// error" is a weak signal about fidelity.
//
// This compares responses directly. It cannot prove compatibility, because the
// reference implementation keeps evolving and no finite script covers an API.
// What it produces instead is something checkable: a list of the ways the two
// differ. A difference is either a bug to fix or an accepted deviation with a
// stated reason (see known.go), and that list is a far more honest compatibility
// claim than a percentage.
package differential

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/tas50/cinc-server-ng/internal/auth"
)

// chefClientVersion is announced on every request, as a real client does.
const chefClientVersion = "18.10.17"

// Target is one server under comparison.
type Target struct {
	// Name identifies the target in reported differences.
	Name string
	// BaseURL is the organization endpoint, e.g. https://host/organizations/acme.
	BaseURL string
	// User and Key are the Mixlib signing identity.
	User string
	Key  *rsa.PrivateKey
	// CACert is a PEM certificate to trust in addition to the system roots. A
	// real Chef Infra Server serves its own self-signed certificate, so its CA
	// is pinned here rather than turning verification off: the comparison is
	// meaningless if the responses being compared could have come from anywhere.
	CACert []byte

	client *http.Client
	err    error
}

func (t *Target) httpClient() (*http.Client, error) {
	if t.client != nil || t.err != nil {
		return t.client, t.err
	}
	tr := &http.Transport{}
	if len(t.CACert) > 0 {
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(t.CACert) {
			t.err = fmt.Errorf("%s: CACert is not a valid PEM certificate", t.Name)
			return nil, t.err
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	}
	t.client = &http.Client{Transport: tr, Timeout: 30 * time.Second}
	return t.client, nil
}

// urlFor resolves a step's path against the target.
func (t *Target) urlFor(step Step) string {
	base := strings.TrimRight(t.BaseURL, "/")
	if step.ServerRoot {
		base = originOf(base)
	}
	return base + step.Path
}

// Step is one request issued to both targets.
type Step struct {
	// Name identifies the step in reported differences.
	Name string
	// Method and Path are the request; Path is relative to the target's
	// BaseURL, so "/nodes" addresses the organization's nodes.
	Method string
	Path   string
	// ServerRoot addresses the path relative to the server root rather than the
	// organization, for the endpoints that live outside an org.
	ServerRoot bool
	// Body is the request payload, if any.
	Body string
	// SkipBody compares only the status code. Use it for responses that are
	// inherently unequal — one that returns a freshly generated private key,
	// say — where normalizing would amount to deleting the whole payload.
	SkipBody bool
}

// Observation is one target's response to a step, after normalization.
type Observation struct {
	Status int
	Body   any
	// Transport is set when the request could not be made at all, which is
	// distinct from the server returning an error status.
	Transport error
}

// Difference is one mismatch between the two targets.
type Difference struct {
	Step string
	// Field is "status", or a dotted path into the response body.
	Field     string
	Reference any
	Candidate any
	// Reason is set when the difference matched a known, accepted deviation.
	Reason string
}

func (d Difference) String() string {
	s := fmt.Sprintf("%s: %s\n    reference: %v\n    candidate: %v", d.Step, d.Field, d.Reference, d.Candidate)
	if d.Reason != "" {
		s += "\n    accepted: " + d.Reason
	}
	return s
}

// Known returns the accepted differences, and Unknown the ones that are not.
func Split(diffs []Difference) (known, unknown []Difference) {
	for _, d := range diffs {
		if d.Reason != "" {
			known = append(known, d)
		} else {
			unknown = append(unknown, d)
		}
	}
	return known, unknown
}

// do issues one step against one target.
func (t *Target) do(ctx context.Context, step Step) Observation {
	var body io.Reader
	payload := []byte(step.Body)
	if step.Body != "" {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, step.Method, t.urlFor(step), body)
	if err != nil {
		return Observation{Transport: err}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Ops-Server-API-Version", "1")
	// Real Chef clients announce their version, and a Chef Infra Server's front
	// end uses that to tell an API request from someone pointing a browser at
	// it — without it, the request is answered with a friendly landing page
	// instead of being routed to the API.
	req.Header.Set("X-Chef-Version", chefClientVersion)
	ts := time.Now().UTC().Format(time.RFC3339)
	if err := auth.SignRequest(req, t.User, ts, payload, t.Key); err != nil {
		return Observation{Transport: fmt.Errorf("sign: %w", err)}
	}

	client, err := t.httpClient()
	if err != nil {
		return Observation{Transport: err}
	}
	resp, err := client.Do(req)
	if err != nil {
		return Observation{Transport: err}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return Observation{Transport: err}
	}

	obs := Observation{Status: resp.StatusCode}
	if len(bytes.TrimSpace(raw)) == 0 {
		return obs
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		// A non-JSON body is itself a comparable fact; keep it as a string so a
		// difference in content type shows up rather than being swallowed.
		obs.Body = string(raw)
		return obs
	}
	obs.Body = decoded
	return obs
}

// Run issues every step against both targets and returns the differences,
// annotated with a reason where one is accepted.
//
// Steps run in order against each target, because the script is stateful: it
// creates objects that later steps read back. Both targets see the same
// sequence.
func Run(ctx context.Context, steps []Step, reference, candidate *Target, accepted []Accepted) ([]Difference, error) {
	var diffs []Difference
	for _, step := range steps {
		ref := reference.do(ctx, step)
		can := candidate.do(ctx, step)

		if ref.Transport != nil {
			return diffs, fmt.Errorf("%s: %s: %w", step.Name, reference.Name, ref.Transport)
		}
		if can.Transport != nil {
			return diffs, fmt.Errorf("%s: %s: %w", step.Name, candidate.Name, can.Transport)
		}

		if ref.Status != can.Status {
			diffs = append(diffs, annotate(Difference{
				Step: step.Name, Field: "status",
				Reference: ref.Status, Candidate: can.Status,
			}, accepted))
		}
		if step.SkipBody {
			continue
		}
		refBody := Normalize(ref.Body, reference.BaseURL)
		canBody := Normalize(can.Body, candidate.BaseURL)
		for _, d := range compare(step.Name, "", refBody, canBody) {
			diffs = append(diffs, annotate(d, accepted))
		}
	}
	return diffs, nil
}
