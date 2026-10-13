package api

import (
	"encoding/json"
	"regexp"
	"slices"

	"github.com/cinc-project/cinc-server-ng/internal/chefjson"
)

// A cookbook version PUT is checked as erchef checks it
// (chef_wm_cookbook_version:validate_request and
// chef_cookbook_version:parse_binary_json): the URL version, then the URL
// name, then the body. The body gets the default json_class, chef_type and
// frozen?, may hold only the top-level keys its API version's spec lists, and
// must then satisfy that spec, checked in the spec's order. The first failure
// is the answer, worded as chef_wm_malformed and chef_wm_cookbook_version word
// it.

// cookbookNameRE is erchef's cookbook_name rule (chef_regex NAME_REGEX):
// letters, digits, '.', '_' and '-'.
var cookbookNameRE = regexp.MustCompile(`^[.A-Za-z0-9_-]+$`)

// cookbookKeys and cookbookKeysV2 are erchef's VALID_KEYS and VALID_KEYS_V2:
// per-segment file lists up to API v1, all_files from v2.
var (
	cookbookKeys = []string{
		"attributes", "chef_type", "cookbook_name", "definitions", "files", "frozen?",
		"json_class", "libraries", "metadata", "name", "providers", "recipes", "resources",
		"root_files", "templates", "version",
	}
	cookbookKeysV2 = []string{
		"all_files", "chef_type", "cookbook_name", "frozen?", "json_class", "metadata", "name", "version",
	}
)

// validateCookbookURL checks a cookbook version PUT's URL name and version,
// which erchef does before it reads the body. It returns erchef's message, or
// "" when both are valid.
func validateCookbookURL(name, version string) string {
	if !validCookbookVersion(version) {
		return "Invalid cookbook version '" + version + "'."
	}
	if !cookbookNameRE.MatchString(name) {
		return "Invalid cookbook name '" + name +
			"' using regex: 'Malformed cookbook name. Must only contain A-Z, a-z, 0-9, _, . or -'."
	}
	return ""
}

// validateCookbookManifest fills a cookbook version body's defaults in place
// and checks it against the spec for urlName and urlVersion: cookbook_spec up
// to API v1, cookbook_spec_v2 when allFiles. It returns erchef's message, or ""
// when the body is valid.
func validateCookbookManifest(obj *chefjson.Object, urlName, urlVersion string, allFiles bool) string {
	for _, d := range []chefjson.Member{
		{Name: "json_class", Value: "Chef::CookbookVersion"},
		{Name: "chef_type", Value: "cookbook_version"},
		{Name: "frozen?", Value: false},
	} {
		if _, ok := obj.Get(d.Name); !ok {
			obj.Set(d.Name, d.Value)
		}
	}

	keys, segments := cookbookKeys, cookbookSegments
	if allFiles {
		keys, segments = cookbookKeysV2, []string{"all_files"}
	}
	for _, m := range obj.Members {
		if !slices.Contains(keys, m.Name) {
			return "Invalid key " + m.Name + " in request body"
		}
	}

	for _, exact := range []struct{ key, want string }{
		{"name", urlName + "-" + urlVersion},
		{"cookbook_name", urlName},
		{"json_class", "Chef::CookbookVersion"},
		{"chef_type", "cookbook_version"},
	} {
		v, ok := obj.Get(exact.key)
		if !ok {
			return "Field '" + exact.key + "' missing"
		}
		if s, isStr := v.(string); !isStr || s != exact.want {
			return "Field '" + exact.key + "' invalid"
		}
	}

	v, ok := obj.Get("metadata")
	if !ok {
		return "Field 'metadata' missing"
	}
	meta, ok := v.(*chefjson.Object)
	if !ok {
		return "Field 'metadata' invalid"
	}
	if msg := validateCookbookMetadata(meta, urlVersion, allFiles); msg != "" {
		return msg
	}

	for _, s := range segments {
		v, ok := obj.Get(s)
		if !ok {
			continue
		}
		list, ok := v.([]any)
		if !ok {
			return "Field '" + s + "' invalid"
		}
		for _, f := range list {
			if !validFileEntry(f) {
				return "Invalid element in array value of '" + s + "'."
			}
		}
	}

	if v, ok := obj.Get("version"); ok {
		if s, isStr := v.(string); !isStr || s != urlVersion {
			return "Field 'version' invalid"
		}
	}
	return ""
}

// validateCookbookMetadata checks the metadata object against the spec's
// nested rules: a version equal to the URL's, an optional well-formed name,
// optional string fields, and constraint maps keyed by cookbook names. The v0
// spec also checks the constraint maps chef-client no longer writes, and
// groupings.
func validateCookbookMetadata(meta *chefjson.Object, urlVersion string, allFiles bool) string {
	v, ok := meta.Get("version")
	if !ok {
		return "Field 'metadata.version' missing"
	}
	if s, isStr := v.(string); !isStr || s != urlVersion {
		return "Field 'metadata.version' invalid"
	}
	if v, ok := meta.Get("name"); ok {
		if s, isStr := v.(string); !isStr || !cookbookNameRE.MatchString(s) {
			return "Field 'metadata.name' invalid"
		}
	}
	for _, field := range []string{"description", "long_description", "maintainer", "maintainer_email", "license"} {
		if v, ok := meta.Get(field); ok {
			if _, isStr := v.(string); !isStr {
				return "Field 'metadata." + field + "' invalid"
			}
		}
	}
	maps := []string{"platforms", "dependencies"}
	if !allFiles {
		maps = append(maps, "recommendations", "suggestions", "conflicting", "replacing")
	}
	for _, field := range maps {
		if msg := validateConstraintMap(meta, field); msg != "" {
			return msg
		}
	}
	if !allFiles {
		if v, ok := meta.Get("groupings"); ok {
			if _, isObj := v.(*chefjson.Object); !isObj {
				return "Field 'metadata.groupings' invalid"
			}
		}
	}
	return ""
}

// validateConstraintMap is erchef's constraint_map_spec(cookbook_name) for
// metadata.<field>, when present: an object whose keys are cookbook names and
// whose values are version constraints, checked in document order.
func validateConstraintMap(meta *chefjson.Object, field string) string {
	v, ok := meta.Get(field)
	if !ok {
		return ""
	}
	constraints, ok := v.(*chefjson.Object)
	if !ok {
		return "Field 'metadata." + field + "' invalid"
	}
	for _, m := range constraints.Members {
		if !cookbookNameRE.MatchString(m.Name) {
			return "Invalid key '" + m.Name + "' for metadata." + field
		}
		if s, isStr := m.Value.(string); !isStr || !validCookbookConstraint(s) {
			return "Invalid value '" + erlangText(m.Value) + "' for metadata." + field
		}
	}
	return ""
}

// validFileEntry is erchef's file_list_spec element: an object with string
// name, path, checksum and specificity.
func validFileEntry(f any) bool {
	entry, ok := f.(*chefjson.Object)
	if !ok {
		return false
	}
	for _, k := range []string{"name", "path", "checksum", "specificity"} {
		v, ok := entry.Get(k)
		if !ok {
			return false
		}
		if _, isStr := v.(string); !isStr {
			return false
		}
	}
	return true
}

// erlangText is how chef_wm_malformed prints a rejected value: a string as
// itself, a number by its digits, true, false and null by name. Erlang prints
// arrays and objects as terms; JSON stands in for that here.
func erlangText(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	case bool:
		if t {
			return "true"
		}
		return "false"
	case nil:
		return "null"
	}
	return string(chefjson.Marshal(v))
}
