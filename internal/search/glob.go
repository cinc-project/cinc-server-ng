package search

import (
	"strings"
	"unicode/utf8"
)

// A globMatcher is a compiled wildcard pattern: '*' matches any run of runes and '?'
// exactly one, and a backslash makes the next rune literal. Neither wildcard
// matches a newline, and invalid UTF-8 (in pattern or value) compares as
// U+FFFD; both are what the regexp translation this replaced did, so results
// are unchanged.
//
// The point of not using a regexp is cost. Translating each '*' to '.*' made a
// match cost the value's length times the number of stars, and a wildcard
// term runs against every distinct value in the index. Here a pattern is split
// at its stars into fixed-length segments, and each is placed at its leftmost
// occurrence after the previous one: a segment of fixed length placed earlier
// leaves strictly more of the value for the rest, so the first placement found
// is the one to keep, and nothing is ever retried. A match costs the value's
// length times the longest segment, however many stars there are.
type globMatcher struct {
	// lines is the pattern split at literal newlines. Since a wildcard cannot
	// match a newline, every newline in the value must line up with one of
	// these, so a value matches when it has the same number of lines and each
	// matches its own.
	lines []globLine
}

// globLine is one newline-free stretch of pattern. segs are the pieces between
// stars (consecutive stars leave no piece between them); with no star at all,
// segs holds the single piece the whole line must equal.
type globLine struct {
	segs  []globSeg
	stars bool
}

// anyRune marks a '?' in a segment.
const anyRune rune = -1

// globSeg is a fixed-length piece of pattern: runes, with anyRune for '?'.
// lit is its UTF-8 form when it holds no '?', for a substring search.
type globSeg struct {
	runes []rune
	lit   string
	isLit bool
}

func compileGlob(pattern string) *globMatcher {
	g := &globMatcher{}
	line := globLine{}
	var seg []rune
	flushSeg := func() {
		if len(seg) > 0 || !line.stars {
			line.segs = append(line.segs, newGlobSeg(seg))
		}
		seg = nil
	}
	flushLine := func() {
		// The last piece is kept even when empty, since with a star before
		// it, an empty last piece is what lets the line end anywhere.
		line.segs = append(line.segs, newGlobSeg(seg))
		seg = nil
		g.lines = append(g.lines, line)
		line = globLine{}
	}
	escaped := false
	for _, r := range pattern {
		switch {
		case escaped:
			escaped = false
			if r == '\n' {
				flushLine()
				continue
			}
			seg = append(seg, r)
		case r == '\\':
			escaped = true
		case r == '*':
			flushSeg()
			line.stars = true
		case r == '?':
			seg = append(seg, anyRune)
		case r == '\n':
			flushLine()
		default:
			seg = append(seg, r)
		}
	}
	flushLine()
	return g
}

func newGlobSeg(runes []rune) globSeg {
	s := globSeg{runes: runes, isLit: true}
	for _, r := range runes {
		if r == anyRune {
			s.isLit = false
			break
		}
	}
	if s.isLit {
		s.lit = string(runes)
	}
	return s
}

func (g *globMatcher) match(v string) bool {
	// Normalizing invalid UTF-8 to U+FFFD up front (as a regexp decodes it)
	// lets the rest compare bytes of valid strings. Values are almost always
	// valid, so this costs one scan.
	if !utf8.ValidString(v) {
		v = string([]rune(v)) // one U+FFFD per invalid byte
	}
	if len(g.lines) == 1 {
		if strings.IndexByte(v, '\n') >= 0 {
			return false
		}
		return g.lines[0].match(v)
	}
	if strings.Count(v, "\n")+1 != len(g.lines) {
		return false
	}
	for _, l := range g.lines {
		end := strings.IndexByte(v, '\n')
		if end < 0 {
			end = len(v)
		}
		if !l.match(v[:end]) {
			return false
		}
		if end < len(v) {
			v = v[end+1:]
		} else {
			v = ""
		}
	}
	return true
}

// match reports whether one newline-free line of value matches.
func (l globLine) match(v string) bool {
	if !l.stars {
		end, ok := l.segs[0].at(v, 0)
		return ok && end == len(v)
	}
	first, last := l.segs[0], l.segs[len(l.segs)-1]
	lo, ok := first.at(v, 0)
	if !ok {
		return false
	}
	hi, ok := last.suffixStart(v)
	if !ok || hi < lo {
		return false
	}
	// Each middle piece goes at its leftmost place within what the first and
	// last pieces leave over.
	for _, s := range l.segs[1 : len(l.segs)-1] {
		end, ok := s.find(v[:hi], lo)
		if !ok {
			return false
		}
		lo = end
	}
	return true
}

// at matches the segment at byte offset i of v, returning where it ends.
func (s globSeg) at(v string, i int) (int, bool) {
	if s.isLit {
		if strings.HasPrefix(v[i:], s.lit) {
			return i + len(s.lit), true
		}
		return 0, false
	}
	for _, want := range s.runes {
		if i >= len(v) {
			return 0, false
		}
		r, n := utf8.DecodeRuneInString(v[i:])
		if want != anyRune && want != r {
			return 0, false
		}
		i += n
	}
	return i, true
}

// suffixStart reports where the segment would have to start for it to end v.
func (s globSeg) suffixStart(v string) (int, bool) {
	i := len(v)
	for range s.runes {
		if i == 0 {
			return 0, false
		}
		_, n := utf8.DecodeLastRuneInString(v[:i])
		i -= n
	}
	end, ok := s.at(v, i)
	return i, ok && end == len(v)
}

// find places the segment at its leftmost occurrence in v at or after byte
// offset from, returning where that occurrence ends.
func (s globSeg) find(v string, from int) (int, bool) {
	if s.isLit {
		j := strings.Index(v[from:], s.lit)
		if j < 0 {
			return 0, false
		}
		return from + j + len(s.lit), true
	}
	for i := from; i < len(v); {
		if end, ok := s.at(v, i); ok {
			return end, true
		}
		_, n := utf8.DecodeRuneInString(v[i:])
		i += n
	}
	return 0, false
}
