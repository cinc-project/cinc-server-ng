package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cinc-project/cinc-server-ng/internal/chefjson"
)

// A search page is written straight from the stored rows. It must be byte for
// byte what encoding the page as a map did, since clients and the differential
// gate see those bytes: key order, the trailing newline, and every row exactly
// as stored, including the characters an HTML-escaping encoder would rewrite.
func TestWriteSearchRowsMatchesEncoder(t *testing.T) {
	var stored []json.RawMessage
	for _, in := range []string{
		`{"name":"web","run_list":["recipe[base]"]}`,
		`{"html":"<b>&amp;</b>","sep":"\u2028\u2029","ctl":"\u0001\u001f","q":"\"\\\/"}`,
		`{"big":12345678901234567890,"f":1.5,"e":1e21,"neg":-0,"u":"é🚀"}`,
		`{"k":1,"k":2,"nested":{"a":[[],{},null,true,false]}}`,
		"{\"mixed\":\"a\u2026\u2028\u2014\u2029\u2029z\u2028\"}",
	} {
		raw, err := chefjson.Normalize(strings.NewReader(in))
		if err != nil {
			t.Fatal(err)
		}
		stored = append(stored, raw)
	}
	for name, rows := range map[string][]json.RawMessage{
		"none": {},
		"one":  stored[:1],
		"all":  stored,
	} {
		t.Run(name, func(t *testing.T) {
			out := make([]any, len(rows))
			for i, r := range rows {
				out[i] = r
			}
			want := httptest.NewRecorder()
			writeJSON(want, http.StatusOK, map[string]any{"total": 1234, "start": 7, "rows": out})

			got := httptest.NewRecorder()
			writeSearchRows(got, 1234, 7, rows)

			if got.Body.String() != want.Body.String() {
				t.Errorf("body\n got %s\nwant %s", got.Body, want.Body)
			}
			if got.Code != want.Code || got.Header().Get("Content-Type") != want.Header().Get("Content-Type") {
				t.Errorf("status/type = %d %q, want %d %q", got.Code, got.Header().Get("Content-Type"),
					want.Code, want.Header().Get("Content-Type"))
			}
		})
	}
}

// discardWriter is a ResponseWriter that keeps nothing, so a test measures
// what writing the response allocates rather than what recording it does.
type discardWriter struct{ h http.Header }

func (d discardWriter) Header() http.Header       { return d.h }
func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
func (discardWriter) WriteHeader(int)             {}

// A page of whole documents (a dashboard listing a thousand nodes) is written
// without re-validating every row and buffering the page a second time.
func TestWriteSearchRowsDoesNotCopyRows(t *testing.T) {
	row := json.RawMessage(`{"name":"n","automatic":{"blob":"` + strings.Repeat("x", 8<<10) + `"}}`)
	rows := make([]json.RawMessage, 100)
	for i := range rows {
		rows[i] = row
	}
	page := int64(len(row) * len(rows))
	w := discardWriter{h: http.Header{}}
	got := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			writeSearchRows(w, len(rows), 0, rows)
		}
	}).AllocedBytesPerOp()
	if limit := page / 16; got > limit {
		t.Fatalf("writing a %d-byte page allocated %d bytes, want at most %d", page, got, limit)
	}
}
