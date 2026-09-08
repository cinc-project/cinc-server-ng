package search

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
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
// negation (-field:value). Fuzzy (~), boosting (^), and per-field grouping
// (field:(a OR b)) are not supported.
func Parse(s string) (Query, error) {
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
	if q.phrase || !strings.ContainsAny(q.value, "*?") {
		return v == q.value
	}
	return wildcardToRegexp(q.value).MatchString(v)
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

func wildcardToRegexp(pattern string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	for _, r := range pattern {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	// Pattern is already lowercased by the parser; values are lowercased too.
	return regexp.MustCompile(b.String())
}

// buildTerm constructs the right leaf query for a field:value pair, recognizing
// *:* (match all), field:* (existence), and wildcards.
func buildTerm(field, value string, phrase bool) Query {
	field = strings.ToLower(field)
	value = strings.ToLower(value)
	if value == "*" {
		if field == "" || field == "*" {
			return matchAll{}
		}
		return existsQ{field: field}
	}
	return termQ{field: field, value: value, phrase: phrase}
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
			for i < len(s) && !strings.ContainsRune(" \t\n\r()[]{}\":", rune(s[i])) {
				i++
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
				toks = append(toks, token{kind: tWord, text: word})
			}
		}
	}
	toks = append(toks, token{kind: tEOF})
	return toks, nil
}

// --- parser (precedence: NOT > AND > OR; juxtaposition is AND) -------------

type parser struct {
	toks []token
	pos  int
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
		q, err := p.parseUnary()
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
		q, err := p.parseOr()
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
		return buildTerm("", t.text, true), nil
	case tWord:
		return p.parseClause()
	default:
		return nil, fmt.Errorf("search: unexpected token %q", t.text)
	}
}

func (p *parser) parseClause() (Query, error) {
	field := p.next().text
	negate := false
	if strings.HasPrefix(field, "-") && len(field) > 1 {
		negate, field = true, field[1:]
	}

	var q Query
	if p.peek().kind == tColon {
		p.next()
		v := p.next()
		switch v.kind {
		case tWord:
			q = buildTerm(field, v.text, false)
		case tPhrase:
			q = buildTerm(field, v.text, true)
		case tRange:
			q = rangeQ{field: strings.ToLower(field), lo: v.lo, hi: v.hi, incLo: v.incLo, incHi: v.incHi}
		default:
			return nil, fmt.Errorf("search: expected value after ':'")
		}
	} else {
		// Bare term: match against any field.
		q = buildTerm("", field, false)
	}

	if negate {
		q = notQ{q}
	}
	return q, nil
}
