package api

import (
	"encoding/json"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/cinc-project/cinc-server-ng/internal/chefjson"
)

// erchef validates node, role and environment bodies (chef_node, chef_role
// and chef_environment) against chef_regex's patterns and chef_json_validator's
// run list specs, and answers 400 without storing anything. The messages are
// the ones chef_wm_malformed renders for each failure.
var (
	// roleNameRE is chef_regex's role_name (ALTERNATIVE_NAME_REGEX), which
	// is also its node_name.
	roleNameRE = regexp.MustCompile(`^[.A-Za-z0-9_:-]+$`)
	nodeNameRE = roleNameRE
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

// validateObjectBody validates a node, role or environment body the way
// erchef does, returning the 400 message or "" when it is valid (or segment is not
// one erchef validates here). urlName is the name in the request path on an
// update, "" on a create.
func validateObjectBody(segment, urlName string, raw []byte) string {
	if segment != "nodes" && segment != "roles" && segment != "environments" {
		return ""
	}
	doc, err := chefjson.DecodeObject(raw)
	if err != nil {
		return "invalid JSON body"
	}
	switch segment {
	case "nodes":
		return validateNode(urlName, doc)
	case "roles":
		return validateRole(urlName, doc)
	}
	return validateEnvironment(doc)
}

// validateNode is the name, chef_environment and run_list part of
// chef_node:validate_json_node: the name must match node_name, and on an update
// the body may omit it (the URL supplies it) but may not name a different node;
// chef_environment, when present, must be a string matching environment_name;
// run_list, when present, must satisfy run_list_spec. A present
// chef_environment or run_list of null is refused: insert_autofill_fields fills
// in "_default" and [] only for a missing key. The rest of
// chef_node's constraints are not checked here.
func validateNode(urlName string, doc map[string]any) string {
	if msg := validateNodeName(urlName, doc); msg != "" {
		return msg
	}
	if env, ok := doc["chef_environment"]; ok {
		if s, isStr := env.(string); !isStr || !environmentNameRE.MatchString(s) {
			return "Field 'chef_environment' invalid"
		}
	}
	if runList, ok := doc["run_list"]; ok && !validRunList(runList) {
		return "Field 'run_list' is not a valid run list"
	}
	return ""
}

// validateNodeName checks a node body's name against node_name and the URL.
func validateNodeName(urlName string, doc map[string]any) string {
	name, hasName := doc["name"]
	if urlName != "" {
		if hasName && name != urlName {
			return "Node name mismatch."
		}
		name, hasName = urlName, true
	}
	if !hasName {
		return "Field 'name' missing"
	}
	if s, ok := name.(string); !ok || !nodeNameRE.MatchString(s) {
		return "Field 'name' invalid"
	}
	return ""
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
