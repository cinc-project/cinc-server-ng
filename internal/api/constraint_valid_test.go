package api

import "testing"

// TestValidCookbookConstraint pins validCookbookConstraint to erchef's
// valid_cookbook_constraint.
func TestValidCookbookConstraint(t *testing.T) {
	for c, want := range map[string]bool{
		"1.2.3":               true,
		"1.2":                 true,
		"1":                   true,
		"0.0.0":               true,
		"= 1.2.3":             true,
		"< 2.0":               true,
		"> 1":                 true,
		"<= 1.0.0":            true,
		">= 1.2.0":            true,
		"~> 1.2.0":            true,
		"not a constraint":    false,
		"":                    false,
		"1.2.3.4":             false,
		"1..2":                false,
		"1.2.":                false,
		"-1.0":                false,
		"1.x":                 false,
		">=1.0":               false, // the operator needs its space
		"~>  1.0":             false, // and only one
		"== 1.0":              false,
		"!= 1.0":              false,
		"1.0 ":                false,
		"9223372036854775808": false, // past a bigint
		"9223372036854775807": true,
	} {
		if got := validCookbookConstraint(c); got != want {
			t.Errorf("validCookbookConstraint(%q) = %v, want %v", c, got, want)
		}
	}
}
