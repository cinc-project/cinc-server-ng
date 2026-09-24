package api

import (
	"encoding/json"
	"maps"
	"regexp"
	"slices"
	"strings"
)

// erchef validates role and environment bodies (chef_role and
// chef_environment) against chef_regex's patterns and chef_json_validator's
// run list specs, and answers 400 without storing anything. The messages are
// the ones chef_wm_malformed renders for each failure.
var (
	// roleNameRE is chef_regex's role_name (ALTERNATIVE_NAME_REGEX).
	roleNameRE = regexp.MustCompile(`^[.A-Za-z0-9_:-]+$`)
	// environmentNameRE is chef_regex's environment_name (NAME_REGEX), which
	// is also its cookbook_name: no ':' allowed.
	environmentNameRE = regexp.MustCompile(`^[.A-Za-z0-9_-]+$`)

	// chef_regex's qualified_role, qualified_recipe and unqualified_recipe,
	// chosen by the item's prefix as chef_json_validator:item_type does. A
	// recipe may name its cookbook and pin a one-to-three part version.
	runListRoleRE   = regexp.MustCompile(`^role\[[.A-Za-z0-9_-]+\]$`)
	runListRecipeRE = regexp.MustCompile(`^recipe\[(?:[.A-Za-z0-9_-]+::)?[.A-Za-z0-9_-]+(?:@[0-9]+(?:\.[0-9]+){1,2})?\]$`)
	runListBareRE   = regexp.MustCompile(`^(?:[.A-Za-z0-9_-]+::)?[.A-Za-z0-9_-]+(?:@[0-9]+(?:\.[0-9]+){1,2})?$`)
)

// validateObjectBody validates a role or environment body the way erchef
// does, returning the 400 message or "" when it is valid (or segment is not
// one erchef validates here). urlName is the name in the request path on an
// update, "" on a create.
func validateObjectBody(segment, urlName string, raw []byte) string {
	if segment != "roles" && segment != "environments" {
		return ""
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return "invalid JSON body"
	}
	if segment == "roles" {
		return validateRole(urlName, doc)
	}
	return validateEnvironment(doc)
}

// validateRole is chef_role:validate_role. On an update the body may omit its
// name (the URL supplies it), but may not name a different role.
func validateRole(urlName string, doc map[string]any) string {
	name, hasName := doc["name"]
	if urlName != "" {
		if hasName && name != urlName {
			return "Role name mismatch."
		}
		name, hasName = urlName, true
	}
	if !hasName {
		return "Field 'name' missing"
	}
	if s, ok := name.(string); !ok || !roleNameRE.MatchString(s) {
		return "Field 'name' invalid"
	}
	if runList, ok := doc["run_list"]; ok && !validRunList(runList) {
		return "Field 'run_list' is not a valid run list"
	}
	if v, ok := doc["env_run_lists"]; ok {
		envRunLists, isObj := v.(map[string]any)
		if !isObj {
			return "Field 'env_run_lists' contains invalid run lists"
		}
		for _, env := range slices.Sorted(maps.Keys(envRunLists)) {
			if !environmentNameRE.MatchString(env) {
				return "Invalid key '" + env + "' for env_run_lists"
			}
			if !validRunList(envRunLists[env]) {
				return "Field 'env_run_lists' contains invalid run lists"
			}
		}
	}
	return ""
}

// validRunList is chef_json_validator:run_list_spec.
func validRunList(v any) bool {
	items, ok := v.([]any)
	if !ok {
		return false
	}
	for _, item := range items {
		s, ok := item.(string)
		if !ok {
			return false
		}
		re := runListBareRE
		switch {
		case strings.HasPrefix(s, "recipe["):
			re = runListRecipeRE
		case strings.HasPrefix(s, "role["):
			re = runListRoleRE
		}
		if !re.MatchString(s) {
			return false
		}
	}
	return true
}

// validateEnvironment is chef_environment's environment_spec. The name is
// required on an update too; a different name there renames the environment.
func validateEnvironment(doc map[string]any) string {
	name, ok := doc["name"]
	if !ok {
		return "Field 'name' missing"
	}
	if s, isStr := name.(string); !isStr || !environmentNameRE.MatchString(s) {
		return "Field 'name' invalid"
	}
	v, ok := doc["cookbook_versions"]
	if !ok {
		return ""
	}
	versions, isObj := v.(map[string]any)
	if !isObj {
		return "Field 'cookbook_versions' is not a hash"
	}
	for _, cookbook := range slices.Sorted(maps.Keys(versions)) {
		if !environmentNameRE.MatchString(cookbook) {
			return "Invalid key '" + cookbook + "' for cookbook_versions"
		}
		c, isStr := versions[cookbook].(string)
		if !isStr || !validCookbookConstraint(c) {
			return "Invalid value '" + constraintText(versions[cookbook]) + "' for cookbook_versions"
		}
	}
	return ""
}

// constraintText renders a rejected cookbook_versions value for the error
// message: a string as itself, anything else as JSON.
func constraintText(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	b, _ := json.Marshal(v)
	return string(b)
}
