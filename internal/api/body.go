package api

import (
	"bytes"
	"io"
	"net/http"
)

// A signed request's body is read whole before routing, since its hash is part
// of the signature. Reading it once at the right size, and handing the bytes on
// so the object handlers parse them where they lie, matters because a node is
// tens of kilobytes (Ohai's automatic attributes) and every chef-client run
// saves the whole of it.

// maxPresizedBody is the longest declared body ReadBody sizes its reads for;
// past it, a body is read as io.ReadAll reads it.
const maxPresizedBody = 1 << 20

// presizeStep is the most ReadBody allocates before any of the body has
// arrived. The body is read before the request is authenticated, so a
// declared length alone must not reserve memory: a client declaring a
// megabyte and sending nothing, on many connections, would hold a megabyte
// each. A node body usually fits in the first step.
const presizeStep = 64 << 10

// ReadBody reads r to the end. contentLength, when the client declared one, is
// a hint: the first read buffer is the declared length or presizeStep, whichever
// is smaller, and each time it fills it grows toward the declared length, at
// most doubling, so memory stays within twice what has actually arrived. That
// reads a node in one allocation where io.ReadAll, starting at 512 bytes and
// doubling, discards several times the body.
func ReadBody(r io.Reader, contentLength int64) ([]byte, error) {
	if contentLength <= 0 || contentLength > maxPresizedBody {
		return io.ReadAll(r)
	}
	// One byte past the declared length, so reaching EOF on a body of exactly
	// that length does not grow the buffer.
	want := int(contentLength) + 1
	b := make([]byte, 0, min(want, presizeStep))
	for {
		n, err := r.Read(b[len(b):cap(b)])
		b = b[:len(b)+n]
		if err == io.EOF {
			return b, nil
		}
		if err != nil {
			return b, err
		}
		if len(b) == cap(b) {
			next := 2 * cap(b)
			if want > cap(b) {
				next = min(next, want)
			}
			grown := make([]byte, len(b), next)
			copy(grown, b)
			b = grown
		}
	}
}

// BufferBody returns body as a request body. It reads like any other, and
// decodeObjectBody parses it in place rather than copying it into the decoder.
func BufferBody(body []byte) io.ReadCloser {
	return bufferedBody{bytes.NewBuffer(body)}
}

type bufferedBody struct{ *bytes.Buffer }

func (bufferedBody) Close() error { return nil }

// bodyReader returns the request body for decoding: a buffered body as its
// *bytes.Buffer, which chefjson.Normalize parses in place.
func bodyReader(r *http.Request) io.Reader {
	if bb, ok := r.Body.(bufferedBody); ok {
		return bb.Buffer
	}
	return r.Body
}
