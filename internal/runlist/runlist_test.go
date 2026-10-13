package runlist

import (
	"slices"
	"testing"
)

func TestNormalize(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"empty", []string{}, []string{}},
		{"bare item qualified", []string{"nginx"}, []string{"recipe[nginx]"}},
		{"qualified kept", []string{"recipe[a]", "role[b]"}, []string{"recipe[a]", "role[b]"}},
		{"bare cookbook::recipe@version", []string{"a::b@1.0"}, []string{"recipe[a::b@1.0]"}},
		{"duplicates after qualification", []string{"nginx", "recipe[nginx]", "base", "base"},
			[]string{"recipe[nginx]", "recipe[base]"}},
		{"first occurrence keeps its place", []string{"x", "y", "x", "recipe[y]", "z"},
			[]string{"recipe[x]", "recipe[y]", "recipe[z]"}},
		// erchef drops exact duplicates only: an implicit default recipe and
		// an explicit one are different items.
		{"default recipe not folded", []string{"foo", "foo::default"},
			[]string{"recipe[foo]", "recipe[foo::default]"}},
		{"role and recipe of one name differ", []string{"role[web]", "web"},
			[]string{"role[web]", "recipe[web]"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Normalize(c.in); !slices.Equal(got, c.want) {
				t.Fatalf("Normalize(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestNormalizeNode(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"qualifies and dedups, keeps the rest as sent",
			`{"name":"n","run_list":["nginx","recipe[nginx]","base","base"],"normal":{"big":12345678901234567890,"f":1.5}}`,
			`{"name":"n","run_list":["recipe[nginx]","recipe[base]"],"normal":{"big":12345678901234567890,"f":1.5}}`},
		{"already normal is untouched", `{"name":"n","run_list":["recipe[a]"]}`, `{"name":"n","run_list":["recipe[a]"]}`},
		{"no run list", `{"name":"n"}`, `{"name":"n"}`},
		{"first of a repeated run_list is the one normalized",
			`{"run_list":["a","a"],"run_list":["b","b"]}`,
			`{"run_list":["recipe[a]"],"run_list":["b","b"]}`},
		{"not a list of strings is left alone", `{"run_list":["a",1]}`, `{"run_list":["a",1]}`},
		{"not a list is left alone", `{"run_list":"a"}`, `{"run_list":"a"}`},
		{"env_run_lists is not a node field", `{"env_run_lists":{"prod":["a"]}}`, `{"env_run_lists":{"prod":["a"]}}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := NormalizeNode([]byte(c.in))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != c.want {
				t.Fatalf("NormalizeNode(%s)\n got %s\nwant %s", c.in, got, c.want)
			}
		})
	}
}

func TestNormalizeRole(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"run_list and every env_run_lists entry",
			`{"name":"r","run_list":["nginx","nginx"],"env_run_lists":{"prod":["a","recipe[a]"],"dev":["role[x]"]}}`,
			`{"name":"r","run_list":["recipe[nginx]"],"env_run_lists":{"prod":["recipe[a]"],"dev":["role[x]"]}}`},
		{"env_run_lists alone", `{"env_run_lists":{"prod":["b"]}}`, `{"env_run_lists":{"prod":["recipe[b]"]}}`},
		{"already normal is untouched", `{"run_list":[],"env_run_lists":{}}`, `{"run_list":[],"env_run_lists":{}}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := NormalizeRole([]byte(c.in))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != c.want {
				t.Fatalf("NormalizeRole(%s)\n got %s\nwant %s", c.in, got, c.want)
			}
		})
	}
}

// A document that needs no change comes back as the same slice, so the
// common chef-client save pays no re-encode.
func TestNormalizeNodeUnchangedReturnsInput(t *testing.T) {
	in := []byte(`{"name":"n","run_list":["recipe[a]","role[b]"]}`)
	got, err := NormalizeNode(in)
	if err != nil {
		t.Fatal(err)
	}
	if &got[0] != &in[0] {
		t.Fatal("unchanged document was copied")
	}
}
