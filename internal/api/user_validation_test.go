package api

import (
	"encoding/json"
	"strings"
	"testing"
)

// validUser returns a user create body erchef accepts for name, with extra
// fields merged over it (a nil value drops the field).
func validUser(name string, extra map[string]any) string {
	body := map[string]any{
		"username":     name,
		"display_name": "User " + name,
		"email":        name + "@example.test",
		"password":     "pw-123456",
	}
	for k, v := range extra {
		if v == nil {
			delete(body, k)
			continue
		}
		body[k] = v
	}
	return string(mustEncode(body))
}

// userBody fills in the fields a user create must carry (a display_name, an
// email and a password) unless the body already sets them, so tests that only
// care about a user's name can keep saying so.
func userBody(body string) string {
	var obj map[string]any
	if err := json.Unmarshal([]byte(body), &obj); err != nil {
		panic("userBody: " + err.Error())
	}
	name, _ := obj["name"].(string)
	if name == "" {
		name, _ = obj["username"].(string)
	}
	for k, v := range map[string]any{
		"display_name": "User " + name,
		"email":        name + "@example.test",
		"password":     "pw-123456",
	} {
		if _, ok := obj[k]; !ok {
			obj[k] = v
		}
	}
	return string(mustEncode(obj))
}

func getUser(t *testing.T, url string) map[string]any {
	t.Helper()
	resp, body := do(t, "GET", url, "")
	if resp.StatusCode != 200 {
		t.Fatalf("GET %s = %d: %s", url, resp.StatusCode, body)
	}
	var u map[string]any
	if err := json.Unmarshal([]byte(body), &u); err != nil {
		t.Fatal(err)
	}
	return u
}

// User create validates the record the way erchef's chef_user does: a
// well-formed name, a display_name, and, for a locally authenticated user, a
// valid email and a password of at least 6 characters. A refused user is not
// created.
func TestUserCreateValidation(t *testing.T) {
	srv, _ := newTestAPI(t)
	cases := []struct {
		what, name string
		extra      map[string]any
		want       string
	}{
		{"upper case name", "T-User-1", nil, "Malformed user name. Must only contain a-z, 0-9, _, or -"},
		{"space in name", "t_user 1", nil, "Malformed user name. Must only contain a-z, 0-9, _, or -"},
		{"dot in name", "t.user", nil, "Malformed user name. Must only contain a-z, 0-9, _, or -"},
		{"no display_name", "u1", map[string]any{"display_name": nil}, "Field 'display_name' missing"},
		{"non-string display_name", "u1b", map[string]any{"display_name": 7}, "Field 'display_name' invalid"},
		{"no email", "u2", map[string]any{"email": nil}, "Field 'email' missing"},
		{"bad email", "u3", map[string]any{"email": "not-an-email"}, "email must be valid"},
		{"no password", "u4", map[string]any{"password": nil}, "Field 'password' missing"},
		{"short password", "u5", map[string]any{"password": "abc"}, "Password must have at least 6 characters"},
		{"non-string password", "u5b", map[string]any{"password": 123456}, "Password must have at least 6 characters"},
	}
	for _, c := range cases {
		resp, body := do(t, "POST", srv.URL+"/users", validUser(c.name, c.extra))
		if resp.StatusCode != 400 {
			t.Errorf("%s: create = %d, want 400: %s", c.what, resp.StatusCode, body)
			continue
		}
		if !strings.Contains(body, c.want) {
			t.Errorf("%s: body = %s, want %q", c.what, body, c.want)
		}
		if resp, _ := do(t, "GET", srv.URL+"/users/"+c.name, ""); resp.StatusCode != 404 {
			t.Errorf("%s: refused user was created anyway (GET = %d)", c.what, resp.StatusCode)
		}
	}

	// "name" is checked like "username".
	resp, body := do(t, "POST", srv.URL+"/users", `{"name":"Bad Name","display_name":"B","email":"b@example.test","password":"pw-123456"}`)
	if resp.StatusCode != 400 || !strings.Contains(body, "Malformed user name") {
		t.Errorf("malformed name field = %d %s, want 400", resp.StatusCode, body)
	}
}

// An externally authenticated user needs neither an email nor a password.
func TestUserCreateExternalAuthSkipsLocalFields(t *testing.T) {
	srv, _ := newTestAPI(t)
	resp, body := do(t, "POST", srv.URL+"/users",
		`{"username":"ext","display_name":"Ext","external_authentication_uid":"ldap-ext"}`)
	if resp.StatusCode != 201 {
		t.Fatalf("create external user = %d, want 201: %s", resp.StatusCode, body)
	}
	// A password it does send is still held to the length rule.
	resp, body = do(t, "POST", srv.URL+"/users",
		`{"username":"ext2","display_name":"Ext","external_authentication_uid":"ldap-ext2","password":"abc"}`)
	if resp.StatusCode != 400 {
		t.Fatalf("external user with short password = %d, want 400: %s", resp.StatusCode, body)
	}
}

// erchef stores an email lower-cased on create and on update, so addresses
// that differ only in case are the same address.
func TestUserEmailIsLowerCased(t *testing.T) {
	srv, _ := newTestAPI(t)
	if resp, body := do(t, "POST", srv.URL+"/users", validUser("u6", map[string]any{"email": "Mixed.U6@Example.TEST"})); resp.StatusCode != 201 {
		t.Fatalf("create = %d: %s", resp.StatusCode, body)
	}
	if got := getUser(t, srv.URL+"/users/u6")["email"]; got != "mixed.u6@example.test" {
		t.Fatalf("stored email = %v, want lower-cased", got)
	}
	if resp, body := do(t, "PUT", srv.URL+"/users/u6", `{"username":"u6","display_name":"U6","email":"Other.U6@EXAMPLE.test"}`); resp.StatusCode != 200 {
		t.Fatalf("update = %d: %s", resp.StatusCode, body)
	}
	if got := getUser(t, srv.URL+"/users/u6")["email"]; got != "other.u6@example.test" {
		t.Fatalf("updated email = %v, want lower-cased", got)
	}
}

// User update is validated like create, except that a password is optional.
func TestUserUpdateValidation(t *testing.T) {
	srv, _ := newTestAPI(t)
	if resp, body := do(t, "POST", srv.URL+"/users", validUser("u7", nil)); resp.StatusCode != 201 {
		t.Fatalf("create = %d: %s", resp.StatusCode, body)
	}
	cases := []struct {
		what, body, want string
	}{
		{"short password", `{"username":"u7","display_name":"U","email":"u7@example.test","password":"abc"}`, "Password must have at least 6 characters"},
		{"no display_name", `{"username":"u7","email":"u7@example.test"}`, "Field 'display_name' missing"},
		{"no email", `{"username":"u7","display_name":"U"}`, "Field 'email' missing"},
		{"bad email", `{"username":"u7","display_name":"U","email":"nope"}`, "email must be valid"},
		{"malformed name", `{"username":"U7","display_name":"U","email":"u7@example.test"}`, "Malformed user name"},
	}
	for _, c := range cases {
		resp, body := do(t, "PUT", srv.URL+"/users/u7", c.body)
		if resp.StatusCode != 400 {
			t.Errorf("%s: update = %d, want 400: %s", c.what, resp.StatusCode, body)
			continue
		}
		if !strings.Contains(body, c.want) {
			t.Errorf("%s: body = %s, want %q", c.what, body, c.want)
		}
	}
	if got := getUser(t, srv.URL+"/users/u7")["display_name"]; got != "User u7" {
		t.Errorf("display_name after refused updates = %v, want unchanged", got)
	}
	// A valid update with no password, or a long enough one, is accepted.
	for _, body := range []string{
		`{"username":"u7","display_name":"U","email":"u7@example.test"}`,
		`{"username":"u7","display_name":"U","email":"u7@example.test","password":"n3w-pass"}`,
	} {
		if resp, out := do(t, "PUT", srv.URL+"/users/u7", body); resp.StatusCode != 200 {
			t.Errorf("valid update %s = %d: %s", body, resp.StatusCode, out)
		}
	}
}

// An update of an externally authenticated user may omit email, since the
// stored record says it is not locally authenticated.
func TestUserUpdateExternalAuthUsesStoredUID(t *testing.T) {
	srv, _ := newTestAPI(t)
	do(t, "POST", srv.URL+"/users", `{"username":"ext","display_name":"Ext","external_authentication_uid":"ldap-ext"}`)
	if resp, body := do(t, "PUT", srv.URL+"/users/ext", `{"username":"ext","display_name":"Ext Renamed"}`); resp.StatusCode != 200 {
		t.Fatalf("update external user without email = %d, want 200: %s", resp.StatusCode, body)
	}
}

// erchef merges an update into the stored user: a field the body omits keeps
// its value, and only an explicit null removes it.
func TestUserUpdateMergesIntoStoredRecord(t *testing.T) {
	srv, _ := newTestAPI(t)
	if resp, body := do(t, "POST", srv.URL+"/users", validUser("u8", map[string]any{
		"first_name": "Test", "last_name": "User", "city": "Portland",
	})); resp.StatusCode != 201 {
		t.Fatalf("create = %d: %s", resp.StatusCode, body)
	}
	if resp, body := do(t, "PUT", srv.URL+"/users/u8",
		`{"username":"u8","display_name":"Partial Edit","email":"u8@example.test","city":null}`); resp.StatusCode != 200 {
		t.Fatalf("update = %d: %s", resp.StatusCode, body)
	}
	u := getUser(t, srv.URL+"/users/u8")
	if u["display_name"] != "Partial Edit" {
		t.Errorf("display_name = %v, want the update", u["display_name"])
	}
	if u["first_name"] != "Test" || u["last_name"] != "User" {
		t.Errorf("first/last name = %v/%v, want kept", u["first_name"], u["last_name"])
	}
	if _, ok := u["city"]; ok {
		t.Errorf("city = %v, want removed by the explicit null", u["city"])
	}
	if pk, _ := u["public_key"].(string); pk == "" {
		t.Error("public_key lost on update")
	}
}
