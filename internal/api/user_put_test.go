package api

import (
	"encoding/json"
	"testing"
)

// erchef answers a user update with the user's URI alone
// (oc_chef_wm_named_user:finalize_update_body), not the user: client, org and
// group updates echo the object, but a user update keeps opscode-account's
// reply.
func TestUserUpdateAnswersURI(t *testing.T) {
	srv, _ := newTestAPI(t)
	if resp, body := do(t, "POST", srv.URL+"/users", validUser("u9", nil)); resp.StatusCode != 201 {
		t.Fatalf("create = %d: %s", resp.StatusCode, body)
	}
	update := `{"username":"u9","display_name":"Z2","email":"u9@example.test","first_name":"Z"}`
	for _, version := range []string{"0", "1"} {
		resp, body := doAt(t, version, "PUT", srv.URL+"/users/u9", update)
		if resp.StatusCode != 200 {
			t.Fatalf("v%s update = %d: %s", version, resp.StatusCode, body)
		}
		var got map[string]any
		if err := json.Unmarshal([]byte(body), &got); err != nil {
			t.Fatalf("v%s update body %q: %v", version, body, err)
		}
		want := map[string]any{"uri": srv.URL + "/users/u9"}
		if len(got) != len(want) || got["uri"] != want["uri"] {
			t.Errorf("v%s update body = %s, want %v", version, body, want)
		}
	}
	if got := getUser(t, srv.URL+"/users/u9")["display_name"]; got != "Z2" {
		t.Errorf("display_name = %v, want the update applied", got)
	}
}

// A v0 update that regenerates the key ("private_key": true, as `knife user
// reregister` sends) answers the URI and the new private key, nothing else.
func TestUserUpdateRegeneratedKeyAnswersURIAndKey(t *testing.T) {
	srv, _ := newTestAPI(t)
	if resp, body := do(t, "POST", srv.URL+"/users", validUser("u10", nil)); resp.StatusCode != 201 {
		t.Fatalf("create = %d: %s", resp.StatusCode, body)
	}
	resp, body := doAt(t, "0", "PUT", srv.URL+"/users/u10",
		`{"username":"u10","display_name":"U","email":"u10@example.test","private_key":true}`)
	if resp.StatusCode != 200 {
		t.Fatalf("reregister = %d: %s", resp.StatusCode, body)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("reregister body %q: %v", body, err)
	}
	if got["uri"] != srv.URL+"/users/u10" {
		t.Errorf("uri = %v, want %s", got["uri"], srv.URL+"/users/u10")
	}
	if pk, _ := got["private_key"].(string); pk == "" {
		t.Errorf("private_key missing from %s", body)
	}
	if len(got) != 2 {
		t.Errorf("reregister body = %s, want only uri and private_key", body)
	}
}
