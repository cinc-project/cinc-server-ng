package server

import (
	"encoding/json"
	"strings"
	"testing"
)

// validUserBody fills in the fields a user create or update must carry (a
// display_name, an email and a password), unless the body already sets them,
// so tests that only care about a user's name can keep saying so.
func validUserBody(t *testing.T, body string) string {
	t.Helper()
	var obj map[string]any
	if err := json.Unmarshal([]byte(body), &obj); err != nil {
		t.Fatalf("user body %s: %v", body, err)
	}
	name, _ := obj["name"].(string)
	if name == "" {
		name, _ = obj["username"].(string)
	}
	defaults := map[string]any{
		"display_name": "User " + name,
		"email":        strings.ToLower(name) + "@example.test",
		"password":     "pw-123456",
	}
	for k, v := range defaults {
		if _, ok := obj[k]; !ok {
			obj[k] = v
		}
	}
	out, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}
