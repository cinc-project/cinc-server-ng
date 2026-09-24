package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestStatsEndpoint(t *testing.T) {
	srv, _ := newTestAPI(t)
	resp, body := do(t, "GET", srv.URL+"/_stats", "")
	if resp.StatusCode != 200 {
		t.Fatalf("_stats = %d", resp.StatusCode)
	}
	// Body must be valid JSON.
	var v any
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		t.Fatalf("_stats body not JSON: %v (%s)", err, body)
	}
}

func TestLicenseEndpoint(t *testing.T) {
	srv, _ := newTestAPI(t)
	resp, body := do(t, "GET", srv.URL+"/license", "")
	if resp.StatusCode != 200 {
		t.Fatalf("/license = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("/license Content-Type = %q, want application/json", ct)
	}
	var lic struct {
		LimitExceeded *bool `json:"limit_exceeded"`
		NodeLicense   *int  `json:"node_license"`
		NodeCount     *int  `json:"node_count"`
	}
	if err := json.Unmarshal([]byte(body), &lic); err != nil {
		t.Fatalf("/license body not JSON: %v (%s)", err, body)
	}
	if lic.LimitExceeded == nil || lic.NodeLicense == nil || lic.NodeCount == nil {
		t.Fatalf("/license missing required fields: %s", body)
	}
	if *lic.LimitExceeded {
		t.Errorf("/license limit_exceeded = true, want false")
	}
}

func TestRequiredRecipeDisabled(t *testing.T) {
	srv, _ := newTestAPI(t)
	// Disabled by default, like a stock Chef server.
	resp, _ := do(t, "GET", srv.URL+"/organizations/acme/required_recipe", "")
	if resp.StatusCode != 404 {
		t.Fatalf("required_recipe = %d, want 404", resp.StatusCode)
	}
}

func TestPrincipals(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"

	// A global user.
	do(t, "POST", srv.URL+"/users", userBody(`{"name":"alice"}`))
	_, body := do(t, "GET", base+"/principals/alice", "")
	var u struct {
		Name      string `json:"name"`
		Type      string `json:"type"`
		PublicKey string `json:"public_key"`
	}
	json.Unmarshal([]byte(body), &u)
	if u.Name != "alice" || u.Type != "user" || !strings.Contains(u.PublicKey, "PUBLIC KEY") {
		t.Fatalf("user principal = %s", body)
	}

	// An org client.
	do(t, "POST", base+"/clients", `{"name":"web01"}`)
	_, body = do(t, "GET", base+"/principals/web01", "")
	json.Unmarshal([]byte(body), &u)
	if u.Type != "client" {
		t.Fatalf("client principal type = %s", body)
	}

	// Unknown principal.
	resp, _ := do(t, "GET", base+"/principals/ghost", "")
	if resp.StatusCode != 404 {
		t.Fatalf("unknown principal = %d, want 404", resp.StatusCode)
	}
}

func TestAPIVersionHeader(t *testing.T) {
	srv, _ := newTestAPI(t)

	// Every response advertises the supported server API version range.
	resp, _ := do(t, "GET", srv.URL+"/organizations/acme/nodes", "")
	hdr := resp.Header.Get("X-Ops-Server-API-Version")
	if hdr == "" {
		t.Fatalf("missing X-Ops-Server-API-Version header")
	}
	var neg struct {
		MinVersion string `json:"min_version"`
		MaxVersion string `json:"max_version"`
	}
	if err := json.Unmarshal([]byte(hdr), &neg); err != nil {
		t.Fatalf("version header not JSON: %v (%s)", err, hdr)
	}
	if neg.MinVersion == "" || neg.MaxVersion == "" {
		t.Fatalf("version header missing bounds: %s", hdr)
	}

	// Requesting an unsupported version is rejected with 406.
	req, _ := http.NewRequest("GET", srv.URL+"/organizations/acme/nodes", nil)
	req.Header.Set("X-Ops-Server-API-Version", "99")
	got, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Body.Close()
	if got.StatusCode != http.StatusNotAcceptable {
		t.Fatalf("unsupported version = %d, want 406", got.StatusCode)
	}
	if got.Header.Get("X-Ops-Server-API-Version") == "" {
		t.Fatalf("406 response missing version header")
	}
}

func TestServerAPIVersionEndpoint(t *testing.T) {
	srv, _ := newTestAPI(t)

	// With no header, request/response default to the minimum.
	_, body := do(t, "GET", srv.URL+"/server_api_version", "")
	var v struct {
		MinVersion      int `json:"min_api_version"`
		MaxVersion      int `json:"max_api_version"`
		RequestVersion  int `json:"request_version"`
		ResponseVersion int `json:"response_version"`
	}
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		t.Fatalf("server_api_version body not JSON: %v (%s)", err, body)
	}
	if v.MinVersion != 0 || v.MaxVersion != 2 {
		t.Fatalf("bounds = %d..%d, want 0..2 (%s)", v.MinVersion, v.MaxVersion, body)
	}
	if v.RequestVersion != 0 || v.ResponseVersion != 0 {
		t.Fatalf("default request/response = %d/%d, want 0/0 (%s)", v.RequestVersion, v.ResponseVersion, body)
	}

	// A requested in-range version is reflected.
	req, _ := http.NewRequest("GET", srv.URL+"/server_api_version", nil)
	req.Header.Set("X-Ops-Server-API-Version", "2")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		t.Fatal(err)
	}
	if v.RequestVersion != 2 || v.ResponseVersion != 2 {
		t.Fatalf("request/response with header 2 = %d/%d, want 2/2", v.RequestVersion, v.ResponseVersion)
	}
}

func TestAPIVersionNonNumericRejected(t *testing.T) {
	srv, _ := newTestAPI(t)
	req, _ := http.NewRequest("GET", srv.URL+"/organizations/acme/nodes", nil)
	req.Header.Set("X-Ops-Server-API-Version", "banana")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	// A non-numeric version is a malformed request (400), distinct from a
	// well-formed but unsupported version (406, see TestAPIVersionTooLowRejected).
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("non-numeric version = %d, want 400; body %s", resp.StatusCode, body)
	}
	var e struct {
		Error []string `json:"error"`
	}
	if json.Unmarshal(body, &e) != nil || len(e.Error) == 0 {
		t.Fatalf("expected JSON error array, got %s", body)
	}
}

func TestAPIVersionTooLowRejected(t *testing.T) {
	srv, _ := newTestAPI(t)
	req, _ := http.NewRequest("GET", srv.URL+"/organizations/acme/nodes", nil)
	req.Header.Set("X-Ops-Server-API-Version", "-1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotAcceptable {
		t.Fatalf("too-low version = %d, want 406", resp.StatusCode)
	}
}

func TestAPIVersionNegotiatedEcho(t *testing.T) {
	srv, _ := newTestAPI(t)
	req, _ := http.NewRequest("GET", srv.URL+"/organizations/acme/nodes", nil)
	req.Header.Set("X-Ops-Server-API-Version", "1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var neg struct {
		RequestVersion  string `json:"request_version"`
		ResponseVersion string `json:"response_version"`
	}
	if err := json.Unmarshal([]byte(resp.Header.Get("X-Ops-Server-API-Version")), &neg); err != nil {
		t.Fatal(err)
	}
	if neg.RequestVersion != "1" || neg.ResponseVersion != "1" {
		t.Fatalf("negotiated echo = req %q resp %q, want 1/1", neg.RequestVersion, neg.ResponseVersion)
	}
}
