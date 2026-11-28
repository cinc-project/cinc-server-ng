package search

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Query is a parsed Solr query that can be evaluated against a flattened doc.
type Query interface {
	Matches(fields map[string][]string) bool
}

// Parse compiles a Chef/Solr search query. Supported syntax: field:value,
// nested keys, wildcards (* and ?), inclusive [a TO b] and exclusive {a TO b}
// ranges with open bounds (*), quoted "phrases", field existence (field:*),
// the match-all *:*, bare terms (matched against any field), boolean AND / OR /
// NOT with parentheses, implicit AND between adjacent clauses, and leading-dash
// negation (-field:value), and Lucene backslash escapes, which make the next
// character literal (run_list:recipe\[base\], a\*b). Fuzzy (~), boosting (^),
// and per-field grouping (field:(a OR b)) are not supported.
func Parse(s string) (Query, error) {
	if len(s) > maxQueryLength {
		return nil, fmt.Errorf("search: query is longer than %d bytes", maxQueryLength)
	}
	toks, err := lex(s)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	q, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.peek().kind != tEOF {
		return nil, fmt.Errorf("search: unexpected token %q", p.peek().text)
	}
	return q, nil
}

// Limits on what one query may ask for. A search runs on behalf of any client
// that can read an index, so each bounds a cost the caller would otherwise
// choose; each is set well past anything knife or a chef-client recipe sends.
const (
	// maxQueryLength caps q before it is lexed, since lexing allocates a token
	// per delimiter. A real Chef Infra Server sits behind nginx, whose default
	// 8 KiB request-line buffer is the most any client has ever been able to
	// send it as q; this is sixteen times that.
	maxQueryLength = 128 << 10

	// maxQueryDepth caps nesting of parentheses and NOT, each of which is a
	// level of parser recursion (four frames per paren). Unbounded, about a
	// megabyte of '(' overflows the goroutine stack, which is fatal to the
	// whole process rather than a recoverable panic. Hand-written queries nest a
	// few levels; generated ones (a host list, a role list) are flat.
	maxQueryDepth = 256

	// maxQueryClauses caps the leaf terms and negations in a query, each of
	// which the planner resolves against the index separately. Solr refuses a
	// boolean query of more than 1024 clauses (its default maxBooleanClauses),
	// but counts per boolean query rather than across the whole tree, so this
	// counts more generously than Solr: 4096 is as many one-letter terms as
	// fit in the 8 KiB request line a real Chef Infra Server accepts.
	maxQueryClauses = 4096
)

// --- AST ------------------------------------------------------------------

type matchAll struct{}

func (matchAll) Matches(map[string][]string) bool { return true }

// IsMatchAll reports whether q matches every document (the *:* query). Callers
// can use this to return stored documents directly without flattening them,
// since the field map is irrelevant when nothing is filtered.
func IsMatchAll(q Query) bool {
	_, ok := q.(matchAll)
	return ok
}

type andQ struct{ l, r Query }

func (q andQ) Matches(f map[string][]string) bool { return q.l.Matches(f) && q.r.Matches(f) }

type orQ struct{ l, r Query }

func (q orQ) Matches(f map[string][]string) bool { return q.l.Matches(f) || q.r.Matches(f) }

type notQ struct{ q Query }

func (q notQ) Matches(f map[string][]string) bool { return !q.q.Matches(f) }

// termQ matches a field (or any field when field is "") against a value that
// may contain * / ? wildcards, unless phrase is set (exact match).
type termQ struct {
	field, value string
	phrase       bool
	// glob is the compiled form of a wildcarded value, built once when the term
	// is parsed and nil when the value has nothing to expand. matchVal runs once
	// per value of every document a scan touches, so compiling there made the
	// cost of a wildcard proportional to the size of the collection rather than
	// to the pattern.
	glob *globMatcher
}

func (q termQ) Matches(f map[string][]string) bool {
	if q.field == "" {
		for _, vals := range f {
			for _, v := range vals {
				if q.matchVal(v) {
					return true
				}
			}
		}
		return false
	}
	for _, v := range f[q.field] {
		if q.matchVal(v) {
			return true
		}
	}
	return false
}

func (q termQ) matchVal(v string) bool {
	if q.glob == nil {
		return v == q.value
	}
	return q.glob.match(v)
}

// existsQ matches when a field is present with at least one value (field:*).
type existsQ struct{ field string }

func (q existsQ) Matches(f map[string][]string) bool {
	if q.field == "" {
		return len(f) > 0
	}
	return len(f[q.field]) > 0
}

// rangeQ matches values within [lo, hi]; lo/hi may be "*" for open bounds.
type rangeQ struct {
	field        string
	lo, hi       string
	incLo, incHi bool
}

func (q rangeQ) Matches(f map[string][]string) bool {
	for _, v := range f[q.field] {
		if q.inRange(v) {
			return true
		}
	}
	return false
}

func (q rangeQ) inRange(v string) bool {
	vn, vok := parseFloat(v)
	lon, lok := parseFloat(q.lo)
	hin, hok := parseFloat(q.hi)
	numeric := vok && (q.lo == "*" || lok) && (q.hi == "*" || hok)
	if numeric {
		if q.lo != "*" && (vn < lon || (!q.incLo && vn == lon)) {
			return false
		}
		if q.hi != "*" && (vn > hin || (!q.incHi && vn == hin)) {
			return false
		}
		return true
	}
	// Lexical comparison.
	if q.lo != "*" && (v < q.lo || (!q.incLo && v == q.lo)) {
		return false
	}
	if q.hi != "*" && (v > q.hi || (!q.incHi && v == q.hi)) {
		return false
	}
	return true
}

func parseFloat(s string) (float64, bool) {
	f, err := strconv.ParseFloat(s, 64)
	return f, err == nil
}

// buildTerm constructs the right leaf query for a field:value pair, recognizing
// *:* (match all), field:* (existence), and wildcards. value is the literal
// term; glob is the same term with only its literal wildcard characters (and
// backslashes) still escaped, so a backslash-escaped * or ? matches itself.
// A phrase is always literal and passes glob == value.
func buildTerm(field, value, glob string, phrase bool) Query {
	field = strings.ToLower(field)
	value = strings.ToLower(value)
	glob = strings.ToLower(glob)
	if glob == "*" {
		if field == "" || field == "*" {
			return matchAll{}
		}
		return existsQ{field: field}
	}
	t := termQ{field: field, value: value, phrase: phrase}
	if !phrase && hasWildcard(glob) {
		t.glob = compileGlob(glob)
	}
	return t
}

// hasWildcard reports whether glob has an unescaped * or ?.
func hasWildcard(glob string) bool {
	for i := 0; i < len(glob); i++ {
		switch glob[i] {
		case '\\':
			i++
		case '*', '?':
			return true
		}
	}
	return false
}

// --- lexer ----------------------------------------------------------------

type tokKind int

const (
	tEOF tokKind = iota
	tLParen
	tRParen
	tAnd
	tOr
	tNot
	tColon
	tWord
	tPhrase
	tRange
)

type token struct {
	kind         tokKind
	text         string
	lo, hi       string // for tRange
	incLo, incHi bool   // for tRange
	// For tWord: text has backslash escapes resolved, glob keeps \*, \? and
	// \\ escaped for wildcard matching, and negate records an unescaped
	// leading '-'.
	glob   string
	negate bool
}

func lex(s string) ([]token, error) {
	var toks []token
	i := 0
	for i < len(s) {
		c := s[i]
		switch c {
		case ' ', '\t', '\n', '\r':
			i++
		case '(':
			toks = append(toks, token{kind: tLParen, text: "("})
			i++
		case ')':
			toks = append(toks, token{kind: tRParen, text: ")"})
			i++
		case ':':
			toks = append(toks, token{kind: tColon, text: ":"})
			i++
		case '"':
			end := strings.IndexByte(s[i+1:], '"')
			if end < 0 {
				return nil, fmt.Errorf("search: unterminated phrase")
			}
			toks = append(toks, token{kind: tPhrase, text: s[i+1 : i+1+end]})
			i += end + 2
		case '[', '{':
			close := byte(']')
			incLo, incHi := true, true
			if c == '{' {
				close, incLo, incHi = '}', false, false
			}
			end := strings.IndexByte(s[i+1:], close)
			if end < 0 {
				return nil, fmt.Errorf("search: unterminated range")
			}
			inner := s[i+1 : i+1+end]
			lo, hi, ok := strings.Cut(inner, " TO ")
			if !ok {
				return nil, fmt.Errorf("search: malformed range %q", inner)
			}
			toks = append(toks, token{
				kind:  tRange,
				lo:    strings.ToLower(strings.TrimSpace(lo)),
				hi:    strings.ToLower(strings.TrimSpace(hi)),
				incLo: incLo, incHi: incHi,
			})
			i += end + 2
		default:
			start := i
			// A backslash makes the next character literal, as in Lucene:
			// it neither ends the word nor acts as a wildcard, keyword or
			// negation. text is the word with its escapes resolved; glob
			// keeps only the escapes a wildcard pattern still needs.
			var text, glob strings.Builder
			for i < len(s) && !strings.ContainsRune(" \t\n\r()[]{}\":", rune(s[i])) {
				if s[i] != '\\' {
					text.WriteByte(s[i])
					glob.WriteByte(s[i])
					i++
					continue
				}
				if i+1 >= len(s) {
					return nil, fmt.Errorf("search: query cannot end with an escape character")
				}
				_, n := utf8.DecodeRuneInString(s[i+1:])
				esc := s[i+1 : i+1+n]
				text.WriteString(esc)
				if esc == "*" || esc == "?" || esc == "\\" {
					glob.WriteByte('\\')
				}
				glob.WriteString(esc)
				i += 1 + n
			}
			if i == start {
				// A delimiter with no lexer case of its own — a stray range
				// closer ']' or '}' with no matching opener. It is neither
				// consumed nor scanned over, so bail out instead of looping
				// forever on it.
				return nil, fmt.Errorf("search: unexpected character %q", s[i:i+1])
			}
			word := s[start:i]
			switch word {
			case "AND":
				toks = append(toks, token{kind: tAnd, text: word})
			case "OR":
				toks = append(toks, token{kind: tOr, text: word})
			case "NOT":
				toks = append(toks, token{kind: tNot, text: word})
			default:
				toks = append(toks, token{
					kind: tWord, text: text.String(), glob: glob.String(),
					negate: len(word) > 1 && word[0] == '-',
				})
			}
		}
	}
	toks = append(toks, token{kind: tEOF})
	return toks, nil
}

// --- parser (precedence: NOT > AND > OR; juxtaposition is AND) -------------

type parser struct {
	toks    []token
	pos     int
	depth   int // current nesting of parens and NOT
	clauses int // leaf terms and negations parsed so far
}

// enter records one more level of nesting, refusing to go past maxQueryDepth.
// The caller pairs it with p.depth-- on the way out.
func (p *parser) enter() error {
	p.depth++
	if p.depth > maxQueryDepth {
		return fmt.Errorf("search: query nests more than %d levels deep", maxQueryDepth)
	}
	return nil
}

// clause counts one leaf term or negation against maxQueryClauses.
func (p *parser) clause() error {
	p.clauses++
	if p.clauses > maxQueryClauses {
		return fmt.Errorf("search: query has more than %d clauses", maxQueryClauses)
	}
	return nil
}

func (p *parser) peek() token { return p.toks[p.pos] }

func (p *parser) next() token {
	t := p.toks[p.pos]
	if p.pos < len(p.toks)-1 {
		p.pos++
	}
	return t
}

func (p *parser) parseOr() (Query, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.peek().kind == tOr {
		p.next()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = orQ{left, right}
	}
	return left, nil
}

func (p *parser) parseAnd() (Query, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for {
		switch p.peek().kind {
		case tAnd:
			p.next()
			right, err := p.parseUnary()
			if err != nil {
				return nil, err
			}
			left = andQ{left, right}
		case tWord, tPhrase, tLParen, tNot: // implicit AND
			right, err := p.parseUnary()
			if err != nil {
				return nil, err
			}
			left = andQ{left, right}
		default:
			return left, nil
		}
	}
}

func (p *parser) parseUnary() (Query, error) {
	if p.peek().kind == tNot {
		p.next()
		if err := p.enter(); err != nil {
			return nil, err
		}
		if err := p.clause(); err != nil {
			return nil, err
		}
		q, err := p.parseUnary()
		p.depth--
		if err != nil {
			return nil, err
		}
		return notQ{q}, nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (Query, error) {
	switch t := p.peek(); t.kind {
	case tLParen:
		p.next()
		if err := p.enter(); err != nil {
			return nil, err
		}
		q, err := p.parseOr()
		p.depth--
		if err != nil {
			return nil, err
		}
		if p.peek().kind != tRParen {
			return nil, fmt.Errorf("search: missing closing paren")
		}
		p.next()
		return q, nil
	case tPhrase:
		p.next()
		if err := p.clause(); err != nil {
			return nil, err
		}
		return buildTerm("", t.text, t.text, true), nil
	case tWord:
		return p.parseClause()
	default:
		return nil, fmt.Errorf("search: unexpected token %q", t.text)
	}
}

func (p *parser) parseClause() (Query, error) {
	if err := p.clause(); err != nil {
		return nil, err
	}
	f := p.next()
	field, glob, negate := f.text, f.glob, f.negate
	if negate {
		field, glob = field[1:], glob[1:]
	}

	var q Query
	if p.peek().kind == tColon {
		p.next()
		v := p.next()
		switch v.kind {
		case tWord:
			q = buildTerm(field, v.text, v.glob, false)
		case tPhrase:
			q = buildTerm(field, v.text, v.text, true)
		case tRange:
			q = rangeQ{field: strings.ToLower(field), lo: v.lo, hi: v.hi, incLo: v.incLo, incHi: v.incHi}
		default:
			return nil, fmt.Errorf("search: expected value after ':'")
		}
	} else {
		// Bare term: match against any field.
		q = buildTerm("", field, glob, false)
	}

	if negate {
		if err := p.clause(); err != nil {
			return nil, err
		}
		q = notQ{q}
	}
	return q, nil
}
