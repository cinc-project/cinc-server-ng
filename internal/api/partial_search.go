package api

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strconv"

	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// Limits on a partial search. A partial search projects every key of its body
// out of every row in the window, so the response grows as rows x keys x the
// size of each projected subtree: a body naming one large subtree under many
// keys turns a small stored document into an arbitrarily large response.
//
//   - maxPartialSearchKeys: real partial searches (knife search -a, the
//     filter_result of a recipe's search) name a handful of keys; a thousand
//     is far past any of them.
//   - maxPartialSearchPathLen: a path is as deep as the attribute it names, and
//     no real attribute tree comes near 128 levels.
//   - partialSearchSlack: a projection is a subset of each document, so the
//     whole objects of the window (what the same search without a body
//     returns) are a natural ceiling on the result; the slack on top covers
//     the result keys, URLs and a projection that repeats a subtree.
const (
	maxPartialSearchKeys    = 1000
	maxPartialSearchPathLen = 128
	partialSearchSlack      = 16 << 20
)

// checkPartialSearchBody returns why a decoded partial search body is over the
// limits above, or "" when it is within them.
func checkPartialSearchBody(partial map[string][]string) string {
	if len(partial) > maxPartialSearchKeys {
		return "partial search body must name no more than " + strconv.Itoa(maxPartialSearchKeys) + " keys"
	}
	for _, path := range partial {
		if len(path) > maxPartialSearchPathLen {
			return "partial search paths must have no more than " + strconv.Itoa(maxPartialSearchPathLen) + " elements"
		}
	}
	return ""
}

// errPartialTooLarge stops a partial search whose result outgrows its budget.
var errPartialTooLarge = errors.New("partial search result too large")

// writePartialSearch writes the partial-search result for window: what
// writeJSON made of {"total","start","rows"} with each row a map of url and
// data (keys sorted, HTML unescaped, trailing newline), but one value at a time
// rather than built and encoded as a whole.
//
// The status can't change once the body has started, so the result is sized
// first, by encoding it into a counter that gives up as soon as the budget is
// spent, and only a result within budget is written, encoded a second time
// straight to the response. Both passes read the same stored bytes, so they
// produce the same output. Memory is one projected value at a time in either
// pass, and the work is bounded by the budget.
func (a *API) writePartialSearch(w http.ResponseWriter, r *http.Request, org *store.Org, idx searchIndex, partial map[string][]string, total, start int, window []match) {
	names := make([]string, 0, len(partial))
	for name := range partial {
		names = append(names, name)
	}
	sort.Strings(names) // encoding/json's order for map keys

	budget := int64(partialSearchSlack)
	for _, m := range window {
		budget += int64(len(m.raw))
	}
	counter := &budgetWriter{budget: budget}
	if err := a.encodePartialRows(counter, r, org, idx, names, partial, window); err != nil {
		if errors.Is(err, errPartialTooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge,
				"partial search result would exceed "+strconv.FormatInt(budget, 10)+" bytes; request fewer keys or rows")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	bw := bufio.NewWriterSize(w, 32<<10)
	_, _ = io.WriteString(bw, `{"rows":[`)
	if err := a.encodePartialRows(bw, r, org, idx, names, partial, window); err != nil {
		return // the client went away
	}
	tail := strconv.AppendInt([]byte(`],"start":`), int64(start), 10)
	tail = append(tail, `,"total":`...)
	tail = strconv.AppendInt(tail, int64(total), 10)
	_, _ = bw.Write(append(tail, "}\n"...))
	_ = bw.Flush()
}

// encodePartialRows writes the rows of a partial search, comma separated,
// stopping at the first failed write.
func (a *API) encodePartialRows(w io.Writer, r *http.Request, org *store.Org, idx searchIndex, names []string, partial map[string][]string, window []match) error {
	e := newJSONStream(w)
	for i, m := range window {
		if i > 0 {
			e.raw(",")
		}
		// Re-fetch the merged view for this row only (a flatten-cache hit, since
		// collectMatches flattened every match); the full result set is not merged.
		merged, _, _ := a.searchDoc(idx.collection, m.id, m.raw, idx.mergeAttrs)
		e.raw(`{"data":{`)
		for j, name := range names {
			if j > 0 {
				e.raw(",")
			}
			e.value(name)
			e.raw(":")
			if path := partial[name]; len(path) == 0 {
				e.raw("null") // empty projection: no value for this key
			} else {
				e.value(traversePath(merged, path))
			}
			if e.err != nil {
				return e.err
			}
		}
		e.raw(`},"url":`)
		e.value(idx.urlFor(r, org.Name(), m.id))
		e.raw("}")
		if e.err != nil {
			return e.err
		}
	}
	return e.err
}

// jsonStream writes JSON a value at a time, each encoded as writeJSON would
// encode it in place, and keeps the first error.
type jsonStream struct {
	w   io.Writer
	buf bytes.Buffer
	enc *json.Encoder
	err error
}

func newJSONStream(w io.Writer) *jsonStream {
	s := &jsonStream{w: w}
	s.enc = json.NewEncoder(&s.buf)
	s.enc.SetEscapeHTML(false)
	return s
}

func (s *jsonStream) raw(text string) {
	if s.err == nil {
		_, s.err = io.WriteString(s.w, text)
	}
}

func (s *jsonStream) value(v any) {
	if s.err != nil {
		return
	}
	s.buf.Reset()
	if s.err = s.enc.Encode(v); s.err != nil {
		return
	}
	_, s.err = s.w.Write(bytes.TrimSuffix(s.buf.Bytes(), []byte("\n")))
}

// budgetWriter discards what it is given, failing with errPartialTooLarge once
// more than budget bytes have been written.
type budgetWriter struct {
	n, budget int64
}

func (b *budgetWriter) Write(p []byte) (int, error) {
	b.n += int64(len(p))
	if b.n > b.budget {
		return 0, errPartialTooLarge
	}
	return len(p), nil
}
