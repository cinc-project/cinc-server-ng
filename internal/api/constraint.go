package api

import (
	"strconv"
	"strings"
)

// satisfiesConstraint reports whether a cookbook version satisfies a Chef
// version constraint such as "= 1.0.0", ">= 2.1", "~> 1.4". An empty constraint
// matches anything. A bare version (no operator) is treated as "= version".
func satisfiesConstraint(version, constraint string) bool {
	constraint = strings.TrimSpace(constraint)
	if constraint == "" {
		return true
	}
	op, ver := splitConstraint(constraint)
	cmp := compareVersions(version, ver)
	switch op {
	case "=", "==":
		return cmp == 0
	case "!=":
		return cmp != 0
	case ">":
		return cmp > 0
	case "<":
		return cmp < 0
	case ">=":
		return cmp >= 0
	case "<=":
		return cmp <= 0
	case "~>":
		return cmp >= 0 && compareVersions(version, pessimisticUpper(ver)) < 0
	default:
		return cmp == 0
	}
}

// splitConstraint separates an operator prefix from the version, tolerating an
// optional space between them ("~> 1.2" or "~>1.2").
func splitConstraint(c string) (op, ver string) {
	for _, candidate := range []string{"~>", ">=", "<=", "==", "!=", "=", ">", "<"} {
		if strings.HasPrefix(c, candidate) {
			return candidate, strings.TrimSpace(c[len(candidate):])
		}
	}
	return "", c
}

// pessimisticUpper returns the exclusive upper bound for a "~>" constraint: the
// last specified component is the one allowed to move, so the ceiling is the
// constraint with that component dropped and the new last incremented. "~> 1.2"
// yields "2", "~> 1.2.3" yields "1.3", and "~> 1" yields "2".
//
// A one-component constraint used to return a sentinel ceiling of 1<<30, which
// made "~> 1" unbounded above and let an environment pinned to it hand a node a
// 2.x cookbook — the major-version jump the operator exists to prevent. There is
// nothing special about that case: dropping no component and incrementing the
// only one gives the right answer, which is what Rubygems does.
func pessimisticUpper(ver string) string {
	parts := strings.Split(ver, ".")
	if len(parts) > 1 {
		parts = parts[:len(parts)-1]
	}
	last := len(parts) - 1
	n, _ := strconv.Atoi(parts[last])
	parts[last] = strconv.Itoa(n + 1)
	return strings.Join(parts, ".")
}
