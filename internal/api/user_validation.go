package api

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// User validation, after erchef's chef_user (common_user_validation and the
// user specs it applies on create and update).

// userNameRE is chef_regex's user_name pattern.
var userNameRE = regexp.MustCompile(`^[a-z0-9\-_]+$`)

const malformedUserName = "Malformed user name. Must only contain a-z, 0-9, _, or -"

// userEmailRE is chef_user:valid_email/1's pattern, compiled caseless as there.
// It admits most addresses, including a quoted local part and an IP literal.
var userEmailRE = regexp.MustCompile(`(?i)^(?:[a-z0-9!#$%&'*+/=?^_` + "`" + `{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_` + "`" + `{|}~-]+)*` +
	`|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")` +
	`@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?` +
	`|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}` +
	`(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:` +
	`(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])$`)

// validateUser checks a user create or update body the way erchef does, and
// returns the 400 message for the first problem, or "" when the body is valid.
// stored is the existing record on update (nil on create); erchef consults its
// external_authentication_uid when the body does not carry one.
//
// A name is checked when present (under "name" or "username"). Create reports
// a missing one itself; an update may omit it, since the path names the user.
// display_name is required on both. A locally authenticated user (no
// external_authentication_uid) must carry a valid email on both, and a
// password on create. Any password sent must be a string of at least 6
// characters.
func validateUser(obj, stored map[string]any, create bool) string {
	if name, present := userNameField(obj); present {
		if s, ok := name.(string); !ok || !userNameRE.MatchString(s) {
			return malformedUserName
		}
	}
	switch v, ok := obj["display_name"]; {
	case !ok || v == nil:
		return "Field 'display_name' missing"
	case !isString(v):
		return "Field 'display_name' invalid"
	}
	if pw, ok := obj["password"]; ok && pw != nil {
		if s, ok := pw.(string); !ok || len(s) < 6 {
			return "Password must have at least 6 characters"
		}
	}
	if externalAuthUID(obj, stored) != nil {
		return ""
	}
	email, ok := obj["email"]
	if !ok || email == nil {
		return "Field 'email' missing"
	}
	if s, ok := email.(string); !ok || !userEmailRE.MatchString(s) {
		return "email must be valid"
	}
	if create {
		if pw, ok := obj["password"]; !ok || pw == nil {
			return "Field 'password' missing"
		}
	}
	return ""
}

// userNameField returns the body's user name, preferring "name" over
// "username" as erchef does, and whether either was present.
func userNameField(obj map[string]any) (any, bool) {
	if v, ok := obj["name"]; ok {
		return v, true
	}
	v, ok := obj["username"]
	return v, ok
}

// externalAuthUID is the user's external_authentication_uid: the body's when it
// carries one, otherwise the stored record's. nil means locally authenticated.
func externalAuthUID(obj, stored map[string]any) any {
	if v, ok := obj["external_authentication_uid"]; ok && v != nil {
		return v
	}
	if v := stored["external_authentication_uid"]; v != nil {
		return v
	}
	return nil
}

func isString(v any) bool {
	_, ok := v.(string)
	return ok
}

// lowerEmail stores a user's email lower-cased, as erchef does on create and
// update, so addresses that differ only in case are the same address.
func lowerEmail(obj map[string]any) {
	if s, ok := obj["email"].(string); ok {
		obj["email"] = strings.ToLower(s)
	}
}

// storedRecord returns an actor's stored document, or nil when it does not
// exist or does not decode.
func storedRecord(org *store.Org, segment, name string) (map[string]any, error) {
	raw, ok, err := org.Get(segment, name)
	if err != nil || !ok {
		return nil, err
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return nil, nil
	}
	return m, nil
}

// mergeUser applies an update body to the stored user, as erchef's
// merge_user_data does: a field the body sets replaces the stored value, an
// explicit null removes it, and a field the body omits keeps its value.
func mergeUser(stored, body map[string]any) map[string]any {
	out := make(map[string]any, len(stored)+len(body))
	for k, v := range stored {
		out[k] = v
	}
	for k, v := range body {
		if v == nil {
			delete(out, k)
			continue
		}
		out[k] = v
	}
	return out
}
