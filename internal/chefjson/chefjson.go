// Package chefjson reads and writes JSON documents the way Chef Infra Server
// does, so a document round-trips through cinc-server-ng byte for byte as it
// does through the real server.
//
// erchef decodes a request body with jiffy and stores what jiffy encodes back.
// That is neither the client's bytes nor what encoding/json produces:
//
//   - Members keep the client's order at every depth, and a repeated name is
//     kept verbatim. A field is read from the first member with its name.
//   - Integers are exact at any size. Floats are IEEE doubles written in
//     shortest form, and stay floats: 1.0 is "1.0" and 1e3 is "1000.0". Plain
//     decimal notation is used for magnitudes in [1e-6, 1e21), exponent
//     notation ("1e+21", "1.5e-7") outside it; zero, negative zero and
//     subnormals are "0.0".
//   - Strings are decoded and re-escaped minimally: '"', '\\', the short
//     escapes \b \f \n \r \t, and other control characters as \u00XX with
//     upper-case hex. Everything else, '/' and U+2028 included, is raw UTF-8.
//   - Invalid UTF-8, an unpaired surrogate escape, a float beyond the range of
//     a double, and anything after the first value are rejected.
//
// Each rule is pinned by a test whose expected output was captured from a real
// server; the differential harness cannot see them, because it compares
// decoded values.
package chefjson

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
)

// Normalize reads exactly one JSON value from r and returns it encoded as
// erchef stores it. An error means erchef would answer 400 "invalid JSON".
func Normalize(r io.Reader) ([]byte, error) {
	dec := jsontext.NewDecoder(r, jsontext.AllowDuplicateNames(true))
	// One frame per open container: whether it is an object, and how many
	// tokens it has held so far (an object's keys are its even-numbered ones).
	type frame struct {
		object bool
		n      int
	}
	stack := make([]frame, 0, 16)
	var out, scratch []byte
	for {
		kind := dec.PeekKind()
		if kind == '}' || kind == ']' {
			if _, err := dec.ReadToken(); err != nil {
				return nil, err
			}
			stack = stack[:len(stack)-1]
			out = append(out, byte(kind))
		} else {
			if len(stack) > 0 {
				top := &stack[len(stack)-1]
				if top.object && top.n%2 == 1 {
					out = append(out, ':')
				} else if top.n > 0 {
					out = append(out, ',')
				}
				top.n++
			}
			switch kind {
			case '"':
				// A string literal without escapes is already in the form erchef
				// writes (the decoder has rejected raw control characters and
				// invalid UTF-8), so copy it through; only an escaped one needs
				// decoding and re-escaping.
				lit, err := dec.ReadValue()
				if err != nil {
					return nil, err
				}
				if bytes.IndexByte(lit, '\\') < 0 {
					out = append(out, lit...)
					break
				}
				if scratch, err = jsontext.AppendUnquote(scratch[:0], lit); err != nil {
					return nil, err
				}
				out = appendString(out, scratch)
			case '0':
				lit, err := dec.ReadValue()
				if err != nil {
					return nil, err
				}
				if out, err = appendNumber(out, lit); err != nil {
					return nil, err
				}
			default:
				tok, err := dec.ReadToken()
				if err != nil {
					if err == io.EOF {
						err = io.ErrUnexpectedEOF
					}
					return nil, err
				}
				switch tok.Kind() {
				case '{', '[':
					out = append(out, byte(tok.Kind()))
					stack = append(stack, frame{object: tok.Kind() == '{'})
				case 'n':
					out = append(out, "null"...)
				case 't':
					out = append(out, "true"...)
				case 'f':
					out = append(out, "false"...)
				}
			}
		}
		if len(stack) == 0 {
			break
		}
	}
	if _, err := dec.ReadToken(); err != io.EOF {
		return nil, errors.New("chefjson: unexpected data after the top-level value")
	}
	return out, nil
}

// String returns the top-level member name of the JSON object doc when it is
// a string. Like erchef, it reads the first member with that name, so a later
// duplicate never changes the answer.
func String(doc []byte, name string) (string, bool) {
	dec := jsontext.NewDecoder(bytes.NewReader(doc), jsontext.AllowDuplicateNames(true))
	if tok, err := dec.ReadToken(); err != nil || tok.Kind() != '{' {
		return "", false
	}
	for dec.PeekKind() == '"' {
		key, err := dec.ReadToken()
		if err != nil {
			return "", false
		}
		if key.String() != name {
			if dec.SkipValue() != nil {
				return "", false
			}
			continue
		}
		val, err := dec.ReadToken()
		if err != nil || val.Kind() != '"' {
			return "", false
		}
		return val.String(), true
	}
	return "", false
}

// DecodeObject decodes the JSON object doc for reading: the first member of a
// repeated name wins, as it does in erchef, and numbers are kept as their
// literals so no precision is lost. Use Parse to edit a document instead,
// which keeps member order and repeats.
func DecodeObject(doc []byte) (map[string]any, error) {
	dec := jsontext.NewDecoder(bytes.NewReader(doc), jsontext.AllowDuplicateNames(true))
	v, err := decode(dec, false)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("chefjson: not a JSON object")
	}
	return m, nil
}

// Member is one name/value pair of an Object.
type Member struct {
	Name  string
	Value any
}

// Object is a JSON object that keeps its members' order and repeats, so an
// edit leaves the rest of the document as the client sent it.
type Object struct {
	Members []Member
}

// Get returns the value of the first member called name.
func (o *Object) Get(name string) (any, bool) {
	for _, m := range o.Members {
		if m.Name == name {
			return m.Value, true
		}
	}
	return nil, false
}

// Set replaces the value of the first member called name in place, or appends
// a member when there is none, matching erchef's ej:set.
func (o *Object) Set(name string, v any) {
	for i := range o.Members {
		if o.Members[i].Name == name {
			o.Members[i].Value = v
			return
		}
	}
	o.Members = append(o.Members, Member{Name: name, Value: v})
}

// Parse decodes doc into a tree for editing: objects are *Object, arrays
// []any, numbers json.Number, and strings, booleans and null their Go values.
// Marshal writes the tree back out.
func Parse(doc []byte) (any, error) {
	dec := jsontext.NewDecoder(bytes.NewReader(doc), jsontext.AllowDuplicateNames(true))
	return decode(dec, true)
}

// decode reads one value. ordered selects *Object (for Parse) over a
// first-member-wins map (for DecodeObject).
func decode(dec *jsontext.Decoder, ordered bool) (any, error) {
	tok, err := dec.ReadToken()
	if err != nil {
		return nil, err
	}
	switch tok.Kind() {
	case '{':
		var obj *Object
		var m map[string]any
		if ordered {
			obj = &Object{}
		} else {
			m = map[string]any{}
		}
		for dec.PeekKind() != '}' {
			key, err := dec.ReadToken()
			if err != nil {
				return nil, err
			}
			name := key.String()
			if !ordered {
				if _, seen := m[name]; seen {
					if err := dec.SkipValue(); err != nil {
						return nil, err
					}
					continue
				}
			}
			v, err := decode(dec, ordered)
			if err != nil {
				return nil, err
			}
			if ordered {
				obj.Members = append(obj.Members, Member{Name: name, Value: v})
			} else {
				m[name] = v
			}
		}
		if _, err := dec.ReadToken(); err != nil {
			return nil, err
		}
		if ordered {
			return obj, nil
		}
		return m, nil
	case '[':
		arr := []any{}
		for dec.PeekKind() != ']' {
			v, err := decode(dec, ordered)
			if err != nil {
				return nil, err
			}
			arr = append(arr, v)
		}
		if _, err := dec.ReadToken(); err != nil {
			return nil, err
		}
		return arr, nil
	case '"':
		return tok.String(), nil
	case '0':
		return json.Number(tok.String()), nil
	case 't':
		return true, nil
	case 'f':
		return false, nil
	case 'n':
		return nil, nil
	}
	return nil, fmt.Errorf("chefjson: unexpected token %v", tok)
}

// Marshal encodes a tree as erchef would. It accepts what Parse produces, plus
// plain strings; any other value is encoded with encoding/json.
func Marshal(v any) []byte {
	return appendValue(nil, v)
}

func appendValue(dst []byte, v any) []byte {
	switch t := v.(type) {
	case *Object:
		dst = append(dst, '{')
		for i, m := range t.Members {
			if i > 0 {
				dst = append(dst, ',')
			}
			dst = appendString(dst, m.Name)
			dst = append(dst, ':')
			dst = appendValue(dst, m.Value)
		}
		return append(dst, '}')
	case []any:
		dst = append(dst, '[')
		for i, e := range t {
			if i > 0 {
				dst = append(dst, ',')
			}
			dst = appendValue(dst, e)
		}
		return append(dst, ']')
	case string:
		return appendString(dst, t)
	case json.Number:
		if out, err := appendNumber(dst, string(t)); err == nil {
			return out
		}
		return append(dst, t...)
	case bool:
		if t {
			return append(dst, "true"...)
		}
		return append(dst, "false"...)
	case nil:
		return append(dst, "null"...)
	}
	b, err := json.Marshal(v)
	if err != nil {
		return append(dst, "null"...)
	}
	return append(dst, b...)
}

const hexUpper = "0123456789ABCDEF"

// appendString writes s as a JSON string escaped as jiffy escapes it. s is
// assumed to be valid UTF-8, which the decoder has already enforced.
func appendString[S ~[]byte | ~string](dst []byte, s S) []byte {
	dst = append(dst, '"')
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x20 && c != '"' && c != '\\' {
			continue
		}
		dst = append(dst, s[start:i]...)
		switch c {
		case '"', '\\':
			dst = append(dst, '\\', c)
		case '\b':
			dst = append(dst, '\\', 'b')
		case '\f':
			dst = append(dst, '\\', 'f')
		case '\n':
			dst = append(dst, '\\', 'n')
		case '\r':
			dst = append(dst, '\\', 'r')
		case '\t':
			dst = append(dst, '\\', 't')
		default:
			dst = append(dst, '\\', 'u', '0', '0', hexUpper[c>>4], hexUpper[c&0xF])
		}
		start = i + 1
	}
	dst = append(dst, s[start:]...)
	return append(dst, '"')
}

// appendNumber writes a JSON number literal as erchef stores it: an integer
// exactly, anything with a fraction or exponent as a double.
func appendNumber[S ~[]byte | ~string](dst []byte, lit S) ([]byte, error) {
	if !containsAny(lit, ".eE") {
		if string(lit) == "-0" {
			return append(dst, '0'), nil
		}
		return append(dst, lit...), nil
	}
	f, err := strconv.ParseFloat(string(lit), 64)
	if err != nil {
		return nil, fmt.Errorf("chefjson: number %s is out of range", lit)
	}
	return appendFloat(dst, f), nil
}

func containsAny[S ~[]byte | ~string](s S, chars string) bool {
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(chars, s[i]) >= 0 {
			return true
		}
	}
	return false
}

// smallestNormal is the least positive normal double. erchef stores anything
// smaller in magnitude as 0.0.
const smallestNormal = 0x1p-1022

// appendFloat writes f as ECMAScript's Number.prototype.toString would, with
// ".0" added to an integral value written in plain decimal notation.
func appendFloat(dst []byte, f float64) []byte {
	if math.Abs(f) < smallestNormal {
		return append(dst, "0.0"...)
	}
	if f < 0 {
		dst = append(dst, '-')
		f = -f
	}
	// The shortest digits that round-trip, as "d.ddde±XX".
	var buf [32]byte
	sci := strconv.AppendFloat(buf[:0], f, 'e', -1, 64)
	ePos := bytes.IndexByte(sci, 'e')
	exp, _ := strconv.Atoi(string(sci[ePos+1:]))
	digits := make([]byte, 0, ePos)
	for _, c := range sci[:ePos] {
		if c != '.' {
			digits = append(digits, c)
		}
	}
	k, n := len(digits), exp+1 // value is 0.<digits> × 10^n
	switch {
	case k <= n && n <= 21:
		dst = append(dst, digits...)
		for range n - k {
			dst = append(dst, '0')
		}
		return append(dst, '.', '0')
	case 0 < n && n <= 21:
		dst = append(dst, digits[:n]...)
		dst = append(dst, '.')
		return append(dst, digits[n:]...)
	case -6 < n && n <= 0:
		dst = append(dst, '0', '.')
		for range -n {
			dst = append(dst, '0')
		}
		return append(dst, digits...)
	}
	dst = append(dst, digits[0])
	if k > 1 {
		dst = append(dst, '.')
		dst = append(dst, digits[1:]...)
	}
	dst = append(dst, 'e')
	if n-1 > 0 {
		dst = append(dst, '+')
	}
	return strconv.AppendInt(dst, int64(n-1), 10)
}
