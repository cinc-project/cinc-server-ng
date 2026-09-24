package api

import (
	"strconv"
	"strings"
)

// validCookbookConstraint is erchef's chef_cookbook_version:
// valid_cookbook_constraint, which checks environment cookbook_versions values
// and a policy lock's version. The operator must be one of <, >, <=, >=, ~> or
// =, followed by exactly one space; with no operator the whole string is the
// version. The version is one to three dot-separated non-negative integers no
// larger than a Postgres bigint (chef_object_base:parse_constraint and
// chef_cookbook_version:parse_version).
func validCookbookConstraint(c string) bool {
	version := c
	for _, op := range []string{"< ", "> ", "<= ", ">= ", "~> ", "= "} {
		if rest, ok := strings.CutPrefix(c, op); ok {
			version = rest
			break
		}
	}
	parts := strings.Split(version, ".")
	if len(parts) > 3 {
		return false
	}
	for _, p := range parts {
		// Erlang's list_to_integer accepts an optional sign; strconv.ParseInt
		// agrees, and rejects anything past int64 as erchef's MAX_VERSION does.
		n, err := strconv.ParseInt(p, 10, 64)
		if err != nil || n < 0 {
			return false
		}
	}
	return true
}
