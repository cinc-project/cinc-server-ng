package api

import (
	"maps"
	"regexp"
	"slices"
)

// erchef validates a policy revision document in oc_chef_policy_revision
// (VALIDATION_CONSTRAINTS) with chef_regex's patterns before storing it, on
// both PUT /policy_groups/G/policies/P and POST /policies/P/revisions.
var (
	// policyNameRE is chef_regex's policy_file_name, policy_file_revision_id
	// and policy_identifier (NAME_REGEX_MAX_255).
	policyNameRE = regexp.MustCompile(`^[.A-Za-z0-9_:-]{1,255}$`)
	// policyLockCookbookRE is chef_regex's cookbook_name (NAME_REGEX), which
	// erchef applies to each cookbook_locks key.
	policyLockCookbookRE = regexp.MustCompile(`^[.A-Za-z0-9_-]+$`)
	// policyRunListItemRE is chef_regex's policy_fully_qualified_recipe:
	// a policy's run list holds only recipe[cookbook::recipe] items.
	policyRunListItemRE = regexp.MustCompile(`^recipe\[[.A-Za-z0-9_-]+::[.A-Za-z0-9_-]+\]$`)
)

// validatePolicyRevision checks a policy revision document the way erchef
// does, in erchef's order, and returns the error message erchef answers 400
// with, or "" when the document is valid. urlName is the policy name from the
// request path, which the document's name must match.
func validatePolicyRevision(urlName string, doc map[string]any) string {
	for _, field := range []string{"revision_id", "name"} {
		v, ok := doc[field]
		if !ok {
			return "Field '" + field + "' missing"
		}
		if s, isStr := v.(string); !isStr || !policyNameRE.MatchString(s) {
			return "Field '" + field + "' invalid"
		}
	}

	runList, ok := doc["run_list"]
	if !ok {
		return "Field 'run_list' missing"
	}
	items, isList := runList.([]any)
	if !isList {
		return "Field 'run_list' is not a valid run list"
	}
	for _, item := range items {
		if s, isStr := item.(string); !isStr || !policyRunListItemRE.MatchString(s) {
			return "Field 'run_list' is not a valid run list"
		}
	}

	locksV, ok := doc["cookbook_locks"]
	if !ok {
		return "Field 'cookbook_locks' missing"
	}
	locks, isObj := locksV.(map[string]any)
	if !isObj {
		return "Field 'cookbook_locks' invalid"
	}
	for _, cookbook := range slices.Sorted(maps.Keys(locks)) {
		if !policyLockCookbookRE.MatchString(cookbook) {
			// chef_wm_malformed's message for an ej object_key failure.
			return "Invalid key '" + cookbook + "' for cookbook_locks"
		}
		lock, isObj := locks[cookbook].(map[string]any)
		if !isObj {
			return "Field 'cookbook_locks' invalid"
		}
		if msg := validateCookbookLock(lock); msg != "" {
			return msg
		}
	}

	if name := doc["name"].(string); name != urlName {
		return "Field 'name' invalid : " + urlName + " does not match " + name
	}
	return ""
}

// validateCookbookLock is erchef's COOKBOOK_LOCK_VAIDATION_CONSTRAINTS.
func validateCookbookLock(lock map[string]any) string {
	id, ok := lock["identifier"]
	if !ok {
		return "Field 'identifier' missing"
	}
	if s, isStr := id.(string); !isStr || !policyNameRE.MatchString(s) {
		return "Field 'identifier' invalid"
	}
	if v, ok := lock["dotted_decimal_identifier"]; ok {
		if s, isStr := v.(string); !isStr || !validCookbookConstraint(s) {
			return "Field 'dotted_decimal_identifier' is not a valid version"
		}
	}
	v, ok := lock["version"]
	if !ok {
		return "Field 'version' missing"
	}
	if s, isStr := v.(string); !isStr || !validCookbookConstraint(s) {
		return "Field 'version' is not a valid version"
	}
	return ""
}
