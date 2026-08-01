package differential

import "strings"

// Accepted records a difference we know about and have decided to live with,
// together with why.
//
// This list is the compatibility statement. "100% compatible" is not a claim
// anyone can check; "these are the seventeen ways we differ, and here is the
// reason for each" is. A difference that is not on this list fails the run, so
// the list only grows by someone deciding a deviation is acceptable and saying
// so — never by accident.
type Accepted struct {
	// Step is the step name, or "*" for any step.
	Step string
	// Field is the field path. A trailing "*" matches by prefix, so
	// "metrics*" covers everything under it.
	Field string
	// Reason must explain why the deviation is acceptable, not merely restate
	// the difference.
	Reason string
}

// accepted is the seed list. It deliberately contains only deviations that are
// evident from cinc-zero's own source; the rest are expected to be discovered
// by the first run against a real server and triaged individually, which is the
// point of the exercise.
var accepted = []Accepted{
	{
		Step:  "license",
		Field: "*",
		Reason: "cinc-zero has no entitlement system and always reports an unlimited, " +
			"non-exceeded license, where a real server reports actual node licensing.",
	},
	{
		Step:  "sandbox create",
		Field: "checksums*",
		Reason: "cinc-zero serves cookbook file bodies itself, handing out a pre-signed URL " +
			"on its own address; a real server hands out a bookshelf URL. The flow is the " +
			"same and clients use whatever URL they are given, but the URL cannot match.",
	},
	{
		Step:   "sandbox create",
		Field:  "uri",
		Reason: "the sandbox URI embeds the server's own address and identifier scheme.",
	},
	{
		Step:  "server api version",
		Field: "*",
		Reason: "the supported API version range is a property of each implementation " +
			"rather than a compatibility requirement; clients negotiate against it.",
	},
}

// Accepted returns the seed list of accepted differences.
func AcceptedDifferences() []Accepted { return accepted }

// annotate marks a difference with the reason it is accepted, if it matches an
// entry. An unmatched difference keeps an empty Reason and so counts as a
// failure.
func annotate(d Difference, list []Accepted) Difference {
	for _, a := range list {
		if a.Step != "*" && a.Step != d.Step {
			continue
		}
		if !fieldMatches(a.Field, d.Field) {
			continue
		}
		d.Reason = a.Reason
		return d
	}
	return d
}

func fieldMatches(pattern, field string) bool {
	if pattern == "*" {
		return true
	}
	if prefix, ok := strings.CutSuffix(pattern, "*"); ok {
		return strings.HasPrefix(field, prefix)
	}
	return pattern == field
}
