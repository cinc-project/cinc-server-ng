package search

import "testing"

func TestQueryMatch(t *testing.T) {
	doc := mustDoc(t, `{
		"name": "web01",
		"chef_environment": "production",
		"tags": ["frontend", "ssl"],
		"cpu": {"total": 8},
		"role": "WebServer"
	}`)
	fields := Flatten(doc)

	cases := []struct {
		query string
		want  bool
	}{
		{`*:*`, true},
		{`name:web01`, true},
		{`name:web02`, false},
		{`name:WEB01`, true},     // case-insensitive
		{`role:webserver`, true}, // value lowercased
		{`name:web*`, true},      // wildcard
		{`name:w?b01`, true},     // single-char wildcard
		{`name:nope*`, false},
		{`tags:ssl`, true},    // array membership
		{`total:8`, true},     // nested suffix key
		{`cpu_total:8`, true}, // full nested path
		{`chef_environment:production AND tags:ssl`, true},
		{`chef_environment:staging AND tags:ssl`, false},
		{`chef_environment:staging OR tags:ssl`, true},
		{`tags:ssl AND NOT name:web02`, true},
		{`tags:ssl AND NOT name:web01`, false},
		{`NOT name:web02`, true},
		{`-name:web02`, true},               // leading-dash negation
		{`name:web01 tags:frontend`, true},  // implicit AND
		{`name:web02 tags:frontend`, false}, // implicit AND, one fails
		{`(name:web01 OR name:web99) AND tags:ssl`, true},
		{`cpu_total:[1 TO 10]`, true}, // inclusive numeric range
		{`cpu_total:[10 TO 20]`, false},
		{`cpu_total:{8 TO 20}`, false}, // exclusive lower bound
		{`cpu_total:[* TO 10]`, true},  // open-ended range
		{`name:*`, true},               // field existence
		{`missing:*`, false},
		{`web01`, true}, // bare term, any field
		{`nonexistent`, false},
	}
	for _, c := range cases {
		q, err := Parse(c.query)
		if err != nil {
			t.Errorf("Parse(%q) error: %v", c.query, err)
			continue
		}
		if got := q.Matches(fields); got != c.want {
			t.Errorf("Matches(%q) = %v, want %v", c.query, got, c.want)
		}
	}
}

// TestIsMatchAll lets callers recognize the *:* query so they can return stored
// documents without flattening them. Only *:* (and the equivalent *) is match-all;
// any field constraint, existence check, or bare term is not.
func TestIsMatchAll(t *testing.T) {
	cases := []struct {
		query string
		want  bool
	}{
		{`*:*`, true},
		{`*`, true},
		{`name:web01`, false},
		{`name:*`, false}, // field existence, not match-all
		{`web01`, false},  // bare term
		{`NOT name:x`, false},
		{`*:* AND name:web01`, false},
	}
	for _, c := range cases {
		q, err := Parse(c.query)
		if err != nil {
			t.Errorf("Parse(%q) error: %v", c.query, err)
			continue
		}
		if got := IsMatchAll(q); got != c.want {
			t.Errorf("IsMatchAll(%q) = %v, want %v", c.query, got, c.want)
		}
	}
}

// TestQueryBackslashEscapes: queries are Lucene, where a backslash makes the
// next character literal. `run_list:recipe\[base\]` is the term
// `recipe[base]`, the form knife's documentation uses, and an escaped
// wildcard, colon, dash or keyword loses its special meaning.
func TestQueryBackslashEscapes(t *testing.T) {
	doc := mustDoc(t, `{
		"name": "web01",
		"run_list": ["recipe[base]", "role[web]"],
		"fqdn": "host:8080",
		"note": "a*b",
		"flag": "-x",
		"word": "AND",
		"path": "c:\\temp",
		"spaced": "two words"
	}`)
	fields := Flatten(doc)

	cases := []struct {
		query string
		want  bool
	}{
		{`run_list:recipe\[base\]`, true},
		{`run_list:role\[web\]`, true},
		{`run_list:recipe\[other\]`, false},
		{`name:web01 AND run_list:recipe\[base\]`, true},
		{`run_list:recipe\[base\] AND name:web01`, true},
		{`run_list:recipe\[ba*`, true}, // an escape and a live wildcard
		{`fqdn:host\:8080`, true},
		{`note:a\*b`, true}, // escaped wildcard is literal
		{`note:a\*c`, false},
		{`name:web\*`, false}, // literal '*', not a wildcard
		{`name:w\?b01`, false},
		{`flag:\-x`, true},
		{`\-x`, true}, // a bare term, not a negation
		{`word:\AND`, true},
		{`path:c\:\\temp`, true},
		{`spaced:two\ words`, true},
		{`recipe\[base\]`, true}, // bare escaped term, any field
		{`(run_list:recipe\[base\])`, true},
	}
	for _, c := range cases {
		q, err := Parse(c.query)
		if err != nil {
			t.Errorf("Parse(%q) error: %v", c.query, err)
			continue
		}
		if got := q.Matches(fields); got != c.want {
			t.Errorf("Matches(%q) = %v, want %v", c.query, got, c.want)
		}
	}
}

func TestParseErrors(t *testing.T) {
	for _, q := range []string{"", "(unclosed", "name:", `name:web\`} {
		if _, err := Parse(q); err == nil {
			t.Errorf("Parse(%q) expected error, got nil", q)
		}
	}
}
