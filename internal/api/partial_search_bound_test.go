package api

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

// The streamed partial-search response is byte-for-byte what encoding the whole
// result as one map produced: keys sorted, HTML left unescaped, U+2028 escaped,
// stored numbers kept, a trailing newline.
func TestPartialSearchResponseBytes(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	for _, n := range []string{"web02", "web01", "db01"} {
		resp, b := do(t, "POST", base+"/nodes", `{"name":"`+n+`","chef_environment":"prod","normal":{"tags":["a<b>&c"," x"],"n":{"big":12345678901234567890,"f":1.0,"s":"é"}},"automatic":{"ipaddress":"10.0.0.1"}}`)
		if resp.StatusCode != 201 {
			t.Fatal(b)
		}
	}
	_, body := do(t, "POST", base+"/search/node?q=chef_environment:prod&start=0&rows=10",
		`{"z":["n"],"a":["ipaddress"],"m":["tags"],"empty":[],"missing":["no","pe"],"<k>":["name"]}`)

	row := func(name string) string {
		return `{"data":{"<k>":"` + name + `","a":"10.0.0.1","empty":null,"m":["a<b>&c","` + `\` + `u2028x"],"missing":null,` +
			`"z":{"big":12345678901234567890,"f":1.0,"s":"é"}},"url":"` + base + `/nodes/` + name + `"}`
	}
	want := `{"rows":[` + row("db01") + `,` + row("web01") + `,` + row("web02") + `],"start":0,"total":3}` + "\n"
	if body != want {
		t.Fatalf("partial search body\n got %q\nwant %q", body, want)
	}

	// An empty window still has the same shape.
	_, body = do(t, "POST", base+"/search/node?q=chef_environment:prod&start=5", `{"a":["ipaddress"]}`)
	if want := `{"rows":[],"start":5,"total":3}` + "\n"; body != want {
		t.Fatalf("empty window body = %q, want %q", body, want)
	}
}

func partialBody(keys int, path []string) string {
	p, _ := json.Marshal(path)
	var b strings.Builder
	b.WriteByte('{')
	for i := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`"k` + strconv.Itoa(i) + `":` + string(p))
	}
	b.WriteByte('}')
	return b.String()
}

func TestPartialSearchRefusesTooManyKeys(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	seedNode(t, base, "web01", "production", "alpha")

	// Baseline: the most keys allowed is answered.
	resp, body := do(t, "POST", base+"/search/node?q=name:web01", partialBody(maxPartialSearchKeys, []string{"name"}))
	if resp.StatusCode != 200 {
		t.Fatalf("%d keys = %d: %.200s", maxPartialSearchKeys, resp.StatusCode, body)
	}

	resp, body = do(t, "POST", base+"/search/node?q=name:web01", partialBody(maxPartialSearchKeys+1, []string{"name"}))
	if resp.StatusCode != 413 {
		t.Fatalf("%d keys = %d, want 413: %.200s", maxPartialSearchKeys+1, resp.StatusCode, body)
	}
	assertJSONError(t, body)
}

func TestPartialSearchRefusesTooLongAPath(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	seedNode(t, base, "web01", "production", "alpha")

	path := make([]string, maxPartialSearchPathLen)
	for i := range path {
		path[i] = "x"
	}
	resp, body := do(t, "POST", base+"/search/node?q=name:web01", partialBody(1, path))
	if resp.StatusCode != 200 {
		t.Fatalf("path of %d = %d: %s", len(path), resp.StatusCode, body)
	}

	resp, body = do(t, "POST", base+"/search/node?q=name:web01", partialBody(1, append(path, "x")))
	if resp.StatusCode != 413 {
		t.Fatalf("path of %d = %d, want 413: %s", len(path)+1, resp.StatusCode, body)
	}
	assertJSONError(t, body)
}

// A node's own large subtree projected under many keys must not be expanded
// into an unbounded response: the result is refused before anything is
// written once it would outgrow the whole objects plus a fixed allowance.
func TestPartialSearchOutputIsBounded(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	blob := strings.Repeat("a", 100<<10) // a 100 KiB normal subtree
	resp, b := do(t, "POST", base+"/nodes", `{"name":"big","normal":{"blob":"`+blob+`"}}`)
	if resp.StatusCode != 201 {
		t.Fatal(b)
	}

	// Baseline: projecting the subtree a few times is answered in full.
	resp, body := do(t, "POST", base+"/search/node?q=name:big", partialBody(3, []string{"normal"}))
	if resp.StatusCode != 200 || len(body) < 3*len(blob) {
		t.Fatalf("3 keys = %d, %d bytes", resp.StatusCode, len(body))
	}

	// 1000 copies would be a 100 MB response from a 100 KB node.
	resp, body = do(t, "POST", base+"/search/node?q=name:big", partialBody(1000, []string{"normal"}))
	if resp.StatusCode != 413 {
		t.Fatalf("1000 keys = %d (%d bytes), want 413", resp.StatusCode, len(body))
	}
	assertJSONError(t, body)
}

func assertJSONError(t *testing.T, body string) {
	t.Helper()
	var e struct {
		Error []string `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &e); err != nil || len(e.Error) == 0 {
		t.Fatalf("not a JSON error body: %.200s", body)
	}
}
