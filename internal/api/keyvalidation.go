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

// validKeyName reports whether s is a key name erchef accepts (chef_regex
// key_name) that also addresses the key: "." and ".." match key_name but are
// path segments, so a key under either name could never be fetched, and a
// rename's Location built from one would point at a parent path.
func validKeyName(s string) bool {
	return keyNameRE.MatchString(s) && s != "." && s != ".."
}

// validPublicKey reports whether s is a PEM public key erchef accepts
// (chef_key_base:valid_public_key): a "PUBLIC KEY" or "RSA PUBLIC KEY" block
// that parses. Parsing also refuses an RSA key outside auth.CheckPublicKey's
// modulus and exponent bounds, which could never be used to verify a request
// and would make every request naming its owner expensive to refuse.
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

// Key body errors erchef answers from chef_wm_malformed.
const (
	createOrPubkeyMissingMessage    = "You must either provide a valid value for 'public_key', or specify 'create_key': true"
	createAndPubkeySpecifiedMessage = "You must specify either create_key or public_key, but not both"
	privateKeyFieldMessage          = "Please use create_key: true instead of private_key: true"
	// keyUpdateFieldMissingMessage is oc_chef_wm_named_key's answer for a PUT
	// carrying none of the key fields. Unlike the others, erchef sends it as
	// a bare string, not a list.
	keyUpdateFieldMissingMessage = "At least one of 'name', 'expiration_date', or 'public_key' must be specified"
)

// hasKeyUpdateField reports whether a key PUT body carries any of the fields
// chef_key:parse_binary_json(_, update) looks for. A null is present, as it is
// for ej:get, and is then refused by the field's own check.
func hasKeyUpdateField(body map[string]any) bool {
	for _, f := range []string{"expiration_date", "name", "public_key", "create_key"} {
		if _, ok := body[f]; ok {
			return true
		}
	}
	return false
}

// validateKeyFields checks a key body as chef_key:parse_binary_json does,
// returning erchef's error message or "". On create (required) name,
// expiration_date and exactly one of public_key and a true create_key must be
// present; on update each is optional, but create_key and public_key are still
// exclusive. A field that is present is checked whatever its value, so an
// empty string or null is invalid, not absent.
func validateKeyFields(body map[string]any, required bool) string {
	// validate_name
	if v, ok := body["name"]; ok {
		if s, _ := v.(string); !validKeyName(s) {
			return "Field 'name' invalid"
		}
	} else if required {
		return "Field 'name' missing"
	}

	// chef_key_base:validate_public_key_fields
	if _, ok := body["private_key"]; ok {
		return privateKeyFieldMessage
	}
	createKey, hasCreate := body["create_key"]
	if hasCreate {
		if _, ok := createKey.(bool); !ok {
			return "Field 'create_key' invalid"
		}
	}
	pub, hasPub := body["public_key"]
	if hasPub {
		s, ok := pub.(string)
		if !ok {
			return "Field 'public_key' invalid"
		}
		if !validPublicKey(s) {
			return invalidPublicKeyMessage
		}
	}
	switch {
	case required && !hasPub && !hasCreate:
		return createOrPubkeyMissingMessage
	case hasPub && createKey == true:
		return createAndPubkeySpecifiedMessage
	case required && !hasPub && createKey == false:
		// erchef passes this body to chef_key:new_record, which fails on the
		// missing public_key with a 500; refuse it as the missing key it is.
		return createOrPubkeyMissingMessage
	}

	// validate_expiration_date
	if v, ok := body["expiration_date"]; ok {
		s, isString := v.(string)
		if !isString {
			return "Field 'expiration_date' invalid"
		}
		if !validExpirationDate(s) {
			return badExpirationDateMessage
		}
	} else if required {
		return "Field 'expiration_date' missing"
	}
	return ""
}
