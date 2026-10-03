package api

import "unicode/utf8"

const hexDigits = "0123456789abcdef"

// appendJSONStringContent appends s to dst as the *contents* of a JSON string
// (without the surrounding quotes), escaped identically to encoding/json with
// SetEscapeHTML(false) — the same encoding writeJSON produces. Callers add the
// quotes themselves. It allocates nothing beyond growing dst, so list responses
// can be streamed straight into a reusable buffer instead of building an
// intermediate map and paying reflection-based encoding.
func appendJSONStringContent(dst []byte, s string) []byte {
	start := 0
	for i := 0; i < len(s); {
		if b := s[i]; b < utf8.RuneSelf {
			if b >= 0x20 && b != '"' && b != '\\' {
				i++
				continue
			}
			dst = append(dst, s[start:i]...)
			switch b {
			case '\\':
				dst = append(dst, '\\', '\\')
			case '"':
				dst = append(dst, '\\', '"')
			case '\n':
				dst = append(dst, '\\', 'n')
			case '\r':
				dst = append(dst, '\\', 'r')
			case '\t':
				dst = append(dst, '\\', 't')
			default:
				// Other control characters use the \u00xx form, matching encoding/json.
				dst = append(dst, '\\', 'u', '0', '0', hexDigits[b>>4], hexDigits[b&0xF])
			}
			i++
			start = i
			continue
		}
		c, size := utf8.DecodeRuneInString(s[i:])
		if c == utf8.RuneError && size == 1 {
			// Invalid UTF-8 byte → a literal U+FFFD, matching encoding/json
			// (which since Go 1.27 writes the character rather than �).
			dst = append(dst, s[start:i]...)
			dst = append(dst, "�"...)
			i += size
			start = i
			continue
		}
		// U+2028 and U+2029 are valid JSON but encoding/json escapes them so the
		// output is safe to embed in JavaScript.
		if c == '\u2028' || c == '\u2029' {
			dst = append(dst, s[start:i]...)
			dst = append(dst, '\\', 'u', '2', '0', '2', hexDigits[c&0xF])
			i += size
			start = i
			continue
		}
		i += size
	}
	return append(dst, s[start:]...)
}
