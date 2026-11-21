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

// maxPresizedBody bounds how much ReadBody allocates up front on the strength
// of a Content-Length the client declared. The body is read before the request
// is authenticated, so the declaration alone must not reserve much; a longer
// body is still read whole, just grown as it arrives.
const maxPresizedBody = 1 << 20

// ReadBody reads r to the end. contentLength, when the client declared one, is
// a hint: a body up to maxPresizedBody is read into a single allocation of that
// size rather than grown by doubling from 512 bytes, which for a node is
// several times the body in discarded buffers.
func ReadBody(r io.Reader, contentLength int64) ([]byte, error) {
	if contentLength <= 0 || contentLength > maxPresizedBody {
		return io.ReadAll(r)
	}
	// One byte past the declared length, so reaching EOF on a body of exactly
	// that length does not grow the buffer.
	b := make([]byte, 0, contentLength+1)
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
			b = append(b, 0)[:len(b)] // a longer body than declared
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
