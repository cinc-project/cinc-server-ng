package api

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
)

// trickyNames are identifiers that have historically broken naive string
// handling: JSON-special characters (quote, backslash), spaces, and non-ASCII
// Unicode. Slashes are intentionally excluded — they are path separators and
// genuinely cannot appear in a single URL path segment or a "name/version"
// store key.
var trickyNames = []string{
	`quote"inside`,
	`back\slash`,
	`with space`,
	`mixed "q" and \b`,
	`ünïcödé`,
	`emoji😀tail`,
}

// TestObjectNameRoundTrip pins that an object name with JSON-special or Unicode
// characters survives create → get → list as canonical JSON. This guards the
// class of bug where a name is concatenated into JSON or a URL without
// escaping (cf. the data-bag and global-user-URI fixes).
func TestObjectNameRoundTrip(t *testing.T) {
	srv, _ := newTestAPI(t)
	const base = "/organizations/acme/nodes"

	for _, name := range trickyNames {
		t.Run(name, func(t *testing.T) {
			body, _ := json.Marshal(map[string]any{"name": name, "marker": "v"})
			if resp, b := do(t, "POST", srv.URL+base, string(body)); resp.StatusCode != http.StatusCreated {
				t.Fatalf("create = %d: %s", resp.StatusCode, b)
			}

			// GET it back via a properly-escaped path segment.
			esc := url.PathEscape(name)
			resp, got := do(t, "GET", srv.URL+base+"/"+esc, "")
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("get %q = %d: %s", name, resp.StatusCode, got)
			}
			var doc map[string]any
			if err := json.Unmarshal([]byte(got), &doc); err != nil {
				t.Fatalf("stored object is not valid JSON: %v (%s)", err, got)
			}
			if doc["name"] != name {
				t.Errorf("round-tripped name = %v, want %q", doc["name"], name)
			}

			// The name must appear verbatim as a key in the list response.
			_, listBody := do(t, "GET", srv.URL+base, "")
			var list map[string]string
			if err := json.Unmarshal([]byte(listBody), &list); err != nil {
				t.Fatalf("list is not valid JSON: %v (%s)", err, listBody)
			}
			if _, ok := list[name]; !ok {
				t.Errorf("list missing key %q: %s", name, listBody)
			}
		})
	}
}

// TestDataBagItemNameRoundTrip pins the two-level data-bag namespace against
// the same tricky characters. erchef refuses every one of them as a bag name
// and as an item id (its data_bag_name / data_bag_item_id rule), so each must
// be answered with a 400 and leave nothing behind that a later read finds.
func TestDataBagItemNameRoundTrip(t *testing.T) {
	srv, _ := newTestAPI(t)
	const data = "/organizations/acme/data"
	if resp, b := do(t, "POST", srv.URL+data, `{"name":"bag"}`); resp.StatusCode != http.StatusCreated {
		t.Fatalf("create bag = %d: %s", resp.StatusCode, b)
	}

	for _, name := range trickyNames {
		t.Run(name, func(t *testing.T) {
			esc := url.PathEscape(name)

			bagBody, _ := json.Marshal(map[string]any{"name": name})
			if resp, b := do(t, "POST", srv.URL+data, string(bagBody)); resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("create bag = %d: %s, want 400", resp.StatusCode, b)
			}
			if resp, b := do(t, "GET", srv.URL+data+"/"+esc, ""); resp.StatusCode != http.StatusNotFound {
				t.Errorf("get refused bag = %d: %s, want 404", resp.StatusCode, b)
			}

			itemBody, _ := json.Marshal(map[string]any{"id": name, "secret": "s"})
			if resp, b := do(t, "POST", srv.URL+data+"/bag", string(itemBody)); resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("create item = %d: %s, want 400", resp.StatusCode, b)
			}
			if resp, b := do(t, "GET", srv.URL+data+"/bag/"+esc, ""); resp.StatusCode != http.StatusNotFound {
				t.Errorf("get refused item = %d: %s, want 404", resp.StatusCode, b)
			}
		})
	}
}
