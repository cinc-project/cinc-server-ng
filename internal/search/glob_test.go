package search

import (
	"math/rand"
	"regexp"
	"strings"
	"testing"
)

// referenceGlobRegexp is the regexp translation the glob matcher replaced,
// kept as the oracle its semantics are held to: '*' is any run and '?' any one
// rune, neither crossing a newline (regexp '.' without the s flag); a
// backslash makes the next rune literal; a trailing backslash is dropped; and
// invalid UTF-8 compares as U+FFFD.
func referenceGlobRegexp(pattern string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	escaped := false
	for _, r := range pattern {
		if escaped {
			b.WriteString(regexp.QuoteMeta(string(r)))
			escaped = false
			continue
		}
		switch r {
		case '\\':
			escaped = true
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}

func TestGlobMatchesReferenceRegexp(t *testing.T) {
	patterns := []string{
		"web*", "*01", "w*b*1", "web?1", "*", "**", "?", "??", "*?", "?*",
		"a*b*c", "*a*", "a**b", `a\*b`, `a\?b`, `a\\b`, `a\\*`, `\*`, `a\`,
		"a.c", "a+c", "a(b)", "é*", "*é", "?é?", "a\nb", "a*\n*b", "*\n*",
		"\xff*", "*\xff", "?\xffa", "a\xe2\x82*", "�*",
		"*a*a*a*a*b", "*ab*ab*", "ab*ba", "aa*aa", "a*a", "*aa?", "?*?*?",
	}
	values := []string{
		"", "a", "b", "ab", "abc", "a.c", "abc", "web01", "web001", "db01",
		"a*b", "a?b", `a\b`, "axb", "aab", "aaaa", "aaab", "abab", "abba",
		"é", "éé", "aé", "\n", "a\nb", "a\n\nb", "ax\nyb", "\xff", "\xffa",
		"a\xe2\x82", "a\xe2\x82x", "�", "�a", "a(b)", "a+c", "aaaaab",
	}
	check := func(p, v string) {
		t.Helper()
		want := referenceGlobRegexp(p).MatchString(v)
		if got := compileGlob(p).match(v); got != want {
			t.Errorf("glob %q against %q = %v, regexp says %v", p, v, got, want)
		}
	}
	for _, p := range patterns {
		for _, v := range values {
			check(p, v)
		}
	}

	// Random patterns and values over a small alphabet, so overlaps, repeats
	// and the newline and escape edges come up often.
	rng := rand.New(rand.NewSource(1))
	patAlpha := []string{"a", "b", "*", "*", "?", `\*`, `\?`, `\\`, "\n", "é", "\xff", ".", `\`}
	valAlpha := []string{"a", "b", "a", "*", "?", `\`, "\n", "é", "\xff", "\xe2\x82", "."}
	gen := func(alpha []string, n int) string {
		var b strings.Builder
		for range rng.Intn(n) {
			b.WriteString(alpha[rng.Intn(len(alpha))])
		}
		return b.String()
	}
	for range 20000 {
		check(gen(patAlpha, 8), gen(valAlpha, 10))
	}
}
