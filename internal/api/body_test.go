package api

import (
	"bytes"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/iotest"
)

// bodyNode is a node-sized request body.
func bodyNode() []byte {
	return []byte(`{"name":"n","run_list":[],"automatic":{` +
		strings.Repeat(`"fs_k":{"kb_size":"1024","mount":"/","options":["rw","noatime"],"percent_used":12.5},`, 200) +
		`"x":1}}`)
}

// A body whose length the client declared is read in one allocation of that
// size, not grown by doubling from 512 bytes.
func TestReadBodyUsesContentLength(t *testing.T) {
	doc := bodyNode()
	rd := bytes.NewReader(doc)
	allocs := testing.AllocsPerRun(20, func() {
		rd.Reset(doc)
		got, err := ReadBody(rd, int64(len(doc)))
		if err != nil || !bytes.Equal(got, doc) {
			t.Fatalf("ReadBody = %d bytes, %v", len(got), err)
		}
	})
	if allocs != 1 {
		t.Fatalf("ReadBody of a %d-byte body: %v allocations, want 1", len(doc), allocs)
	}
}

// The declared length is only a hint: the body is read whole whatever it says,
// and a read error is reported.
func TestReadBodyReadsWhatArrives(t *testing.T) {
	doc := bodyNode()
	for name, hint := range map[string]int64{
		"unknown":       -1,
		"none":          0,
		"too short":     10,
		"too long":      int64(len(doc)) * 2,
		"past the hint": maxPresizedBody + 1,
	} {
		got, err := ReadBody(iotest.HalfReader(bytes.NewReader(doc)), hint)
		if err != nil || !bytes.Equal(got, doc) {
			t.Errorf("%s: ReadBody = %d bytes, %v; want the %d-byte body", name, len(got), err, len(doc))
		}
	}
	if _, err := ReadBody(iotest.ErrReader(io.ErrUnexpectedEOF), 100); err != io.ErrUnexpectedEOF {
		t.Errorf("ReadBody of a failing reader: err = %v", err)
	}
}

// The body is read before the request is authenticated, so a declared length
// alone must not reserve memory: a client declaring a megabyte and sending a
// few bytes, on many connections, would otherwise hold a megabyte each.
func TestReadBodyDoesNotTrustADeclaredLength(t *testing.T) {
	rd := strings.NewReader(`{}`)
	got := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			rd.Reset(`{}`)
			if _, err := ReadBody(rd, maxPresizedBody); err != nil {
				b.Fatal(err)
			}
		}
	}).AllocedBytesPerOp()
	if limit := int64(presizeStep + 1); got > limit {
		t.Fatalf("a 2-byte body declared as %d bytes allocated %d bytes, want at most %d", maxPresizedBody, got, limit)
	}
}

// A body past the first step grows toward its declared length as it arrives,
// in a few steps rather than doubling from 512 bytes.
func TestReadBodyGrowsTowardTheDeclaredLength(t *testing.T) {
	doc := bytes.Repeat([]byte("x"), 300<<10)
	rd := bytes.NewReader(doc)
	got := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			rd.Reset(doc)
			body, err := ReadBody(rd, int64(len(doc)))
			if err != nil || len(body) != len(doc) {
				b.Fatalf("ReadBody = %d bytes, %v", len(body), err)
			}
		}
	})
	allocs := got.AllocsPerOp()
	if bytesPer, limit := got.AllocedBytesPerOp(), int64(len(doc))*3; bytesPer > limit || allocs > 4 {
		t.Fatalf("a %d-byte body allocated %d bytes in %d allocations, want at most %d in 4", len(doc), bytesPer, allocs, limit)
	}
}

// A body the signature check has already read is decoded where it lies: the
// object handlers allocate about the stored document, not a second copy of the
// body inside the decoder plus an output grown by doubling.
func TestBufferedBodyIsDecodedInPlace(t *testing.T) {
	doc := bodyNode()
	got := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			r := httptest.NewRequest("PUT", "/organizations/acme/nodes/n", nil)
			r.Body = BufferBody(doc)
			if _, err := decodeObjectBody(r); err != nil {
				b.Fatal(err)
			}
		}
	}).AllocedBytesPerOp()
	// httptest.NewRequest itself allocates a few kilobytes.
	if limit := int64(len(doc))*5/4 + 8<<10; got > limit {
		t.Fatalf("decoding a buffered %d-byte body allocated %d bytes, want at most %d", len(doc), got, limit)
	}
}

// A buffered body still reads as an ordinary body for handlers that stream it.
func TestBufferedBodyReadsAsABody(t *testing.T) {
	body := BufferBody([]byte(`{"a":1}`))
	got, err := io.ReadAll(body)
	if err != nil || string(got) != `{"a":1}` {
		t.Fatalf("ReadAll = %q, %v", got, err)
	}
	if err := body.Close(); err != nil {
		t.Fatal(err)
	}
}
