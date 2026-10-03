package search

import (
	"encoding/json"
	"slices"
	"testing"
)

func mustDoc(t testing.TB, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestFlatten(t *testing.T) {
	doc := mustDoc(t, `{
		"name": "web01",
		"tags": ["prod", "frontend"],
		"foo": {"bar": {"baz": "qux"}},
		"count": 3,
		"enabled": true
	}`)
	fields := Flatten(doc)

	cases := []struct {
		key  string
		want []string
	}{
		{"name", []string{"web01"}},
		{"tags", []string{"prod", "frontend"}},
		{"foo_bar_baz", []string{"qux"}}, // full path
		{"bar_baz", []string{"qux"}},     // suffix
		{"baz", []string{"qux"}},         // deepest suffix
		{"count", []string{"3"}},
		{"enabled", []string{"true"}},
	}
	for _, c := range cases {
		got := fields[c.key]
		for _, w := range c.want {
			if !slices.Contains(got, w) {
				t.Errorf("fields[%q] = %v, want to contain %q", c.key, got, w)
			}
		}
	}
}

func TestFlattenLowercases(t *testing.T) {
	fields := Flatten(mustDoc(t, `{"Role": "WebServer"}`))
	if !slices.Contains(fields["role"], "webserver") {
		t.Fatalf("expected lowercased key and value, got %v", fields)
	}
}

// TestFlattenArrayOfMaps pins the indexing of maps nested inside arrays and of
// deep paths with mixed-case keys: array elements share the parent path, and
// every suffix of a leaf's path is indexed. This is the behavior the cheaper
// suffix builder must preserve.
func TestFlattenArrayOfMaps(t *testing.T) {
	fields := Flatten(mustDoc(t, `{
		"Network": {"Interfaces": [{"Name": "eth0"}, {"Name": "eth1"}]},
		"deep": {"a": {"b": {"c": "V"}}}
	}`))
	cases := []struct {
		key  string
		want []string
	}{
		{"network_interfaces_name", []string{"eth0", "eth1"}}, // both array elements, full path, lowercased
		{"interfaces_name", []string{"eth0", "eth1"}},         // suffix
		{"name", []string{"eth0", "eth1"}},                    // deepest suffix
		{"deep_a_b_c", []string{"v"}},
		{"a_b_c", []string{"v"}},
		{"b_c", []string{"v"}},
		{"c", []string{"v"}},
	}
	for _, c := range cases {
		for _, w := range c.want {
			if !slices.Contains(fields[c.key], w) {
				t.Errorf("fields[%q] = %v, want to contain %q", c.key, fields[c.key], w)
			}
		}
	}
}

func BenchmarkFlatten(b *testing.B) {
	doc := mustDoc(b, `{
		"name": "node0", "chef_environment": "production",
		"normal": {"foo": {"bar": "baz"}, "tags": ["a", "b", "c"]},
		"automatic": {"os": "linux", "memory": {"total": "16gb"},
			"network": {"interfaces": {"eth0": {"addr": "10.0.0.1"}}}},
		"run_list": ["recipe[nginx]", "recipe[base]"]
	}`)
	b.ReportAllocs()
	for b.Loop() {
		Flatten(doc)
	}
}

// A number decoded as its literal (json.Number) is indexed as written, which is
// how Chef's search matches it: a stored 1.0 is found by "1.0" and not by "1",
// and an integer past 2^53 keeps every digit.
func TestFlattenIndexesNumberLiterals(t *testing.T) {
	fields := Flatten(map[string]any{
		"one":  json.Number("1.0"),
		"big":  json.Number("12345678901234567890"),
		"tiny": json.Number("0.000001"),
	})
	for key, want := range map[string]string{"one": "1.0", "big": "12345678901234567890", "tiny": "0.000001"} {
		if got := fields[key]; !slices.Equal(got, []string{want}) {
			t.Errorf("fields[%q] = %v, want [%s]", key, got, want)
		}
	}
}
