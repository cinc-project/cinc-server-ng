package api

import (
	"regexp"
	"strings"
	"time"

	"github.com/cinc-project/cinc-server-ng/internal/auth"
)

// Field validation for clients and keys, following erchef's chef_client,
// chef_key and chef_key_base modules.

var (
	// clientNameRE is chef_regex client_name: letters, digits, '.', '_', '-'.
	clientNameRE = regexp.MustCompile(`^[.A-Za-z0-9_-]+$`)
	// keyNameRE is chef_regex key_name, which also allows ':'.
	keyNameRE = regexp.MustCompile(`^[.A-Za-z0-9_:-]+$`)
	// keyDateRE is chef_regex date: "infinity" or an ISO 8601 UTC timestamp.
	keyDateRE = regexp.MustCompile(`^([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z|infinity)$`)
)

// invalidPublicKeyMessage is erchef's answer for a public_key that is not a
// PEM public key (chef_key_base:public_key_spec).
const invalidPublicKeyMessage = "Public Key must be a valid key."

// badExpirationDateMessage is erchef's BAD_DATE_MESSAGE for expiration_date.
const badExpirationDateMessage = `Field expiration_date is invalid. All dates must be a valid date in ISO8601 form of exactly YYYY-MM-DDThh:mm:ss, eg 2099-02-28T01:00:00, or the string "infinity". All times are assumed UTC, so do not include a Z on the end of your date.`

// invalidClientNameMessage is erchef's answer for a client name outside
// client_name ({bad_client_name, Name, Msg} in chef_wm_malformed).
func invalidClientNameMessage(name string) string {
	return "Invalid client name '" + name +
		"' using regex: 'Malformed client name.  Must be A-Z, a-z, 0-9, _, -, or .'."
}

// validPublicKey reports whether s is a PEM public key erchef accepts
// (chef_key_base:valid_public_key): a "PUBLIC KEY" or "RSA PUBLIC KEY" block
// that parses.
func validPublicKey(s string) bool {
	if !strings.HasPrefix(s, "-----BEGIN PUBLIC KEY") && !strings.HasPrefix(s, "-----BEGIN RSA PUBLIC KEY") {
		return false
	}
	_, err := auth.ParsePublicKey([]byte(s))
	return err == nil
}

// validExpirationDate reports whether s is "infinity" or a real date in
// erchef's YYYY-MM-DDThh:mm:ssZ form (chef_object_base:validate_date_field).
func validExpirationDate(s string) bool {
	if !keyDateRE.MatchString(s) {
		return false
	}
	if s == "infinity" {
		return true
	}
	_, err := time.Parse("2006-01-02T15:04:05Z", s)
	return err == nil
}

// validateKeyFields checks whichever of a key body's name, public_key and
// expiration_date are present (chef_key:parse_binary_json), returning erchef's
// error message or "". An empty or null public_key or expiration_date is left
// to the caller, which treats it as absent.
func validateKeyFields(body map[string]any) string {
	if v, ok := body["name"]; ok {
		if s, _ := v.(string); !keyNameRE.MatchString(s) {
			return "Field 'name' invalid"
		}
	}
	if v, ok := body["public_key"]; ok && v != nil && v != "" {
		if s, _ := v.(string); !validPublicKey(s) {
			return invalidPublicKeyMessage
		}
	}
	if v, ok := body["expiration_date"]; ok && v != nil && v != "" {
		if s, _ := v.(string); !validExpirationDate(s) {
			return badExpirationDateMessage
		}
	}
	return ""
}
