package api

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDataBagLifecycle(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"

	// Empty bag list.
	resp, body := do(t, "GET", base+"/data", "")
	if resp.StatusCode != 200 || strings.TrimSpace(body) != "{}" {
		t.Fatalf("empty data list = %d %s", resp.StatusCode, body)
	}

	// Create a bag.
	resp, body = do(t, "POST", base+"/data", `{"name":"secrets"}`)
	if resp.StatusCode != 201 {
		t.Fatalf("create bag = %d: %s", resp.StatusCode, body)
	}

	// Bag appears in the list.
	_, body = do(t, "GET", base+"/data", "")
	var bags map[string]string
	json.Unmarshal([]byte(body), &bags)
	if !strings.HasSuffix(bags["secrets"], "/data/secrets") {
		t.Fatalf("bag list = %s", body)
	}

	// Empty item list for the bag.
	resp, body = do(t, "GET", base+"/data/secrets", "")
	if resp.StatusCode != 200 || strings.TrimSpace(body) != "{}" {
		t.Fatalf("empty item list = %d %s", resp.StatusCode, body)
	}

	// Create an item (keyed by "id").
	resp, body = do(t, "POST", base+"/data/secrets", `{"id":"db_password","value":"hunter2"}`)
	if resp.StatusCode != 201 {
		t.Fatalf("create item = %d: %s", resp.StatusCode, body)
	}

	// Get the item back.
	resp, body = do(t, "GET", base+"/data/secrets/db_password", "")
	if resp.StatusCode != 200 {
		t.Fatalf("get item = %d", resp.StatusCode)
	}
	var item map[string]any
	json.Unmarshal([]byte(body), &item)
	if item["value"] != "hunter2" {
		t.Fatalf("item = %s", body)
	}

	// Update the item.
	resp, _ = do(t, "PUT", base+"/data/secrets/db_password", `{"id":"db_password","value":"changed"}`)
	if resp.StatusCode != 200 {
		t.Fatalf("put item = %d", resp.StatusCode)
	}
	_, body = do(t, "GET", base+"/data/secrets/db_password", "")
	json.Unmarshal([]byte(body), &item)
	if item["value"] != "changed" {
		t.Fatalf("item not updated: %s", body)
	}

	// Item list now shows the item.
	_, body = do(t, "GET", base+"/data/secrets", "")
	var items map[string]string
	json.Unmarshal([]byte(body), &items)
	if _, ok := items["db_password"]; !ok {
		t.Fatalf("item list = %s", body)
	}

	// Delete the item.
	resp, _ = do(t, "DELETE", base+"/data/secrets/db_password", "")
	if resp.StatusCode != 200 {
		t.Fatalf("delete item = %d", resp.StatusCode)
	}
	resp, _ = do(t, "GET", base+"/data/secrets/db_password", "")
	if resp.StatusCode != 404 {
		t.Fatalf("get deleted item = %d", resp.StatusCode)
	}
}

func TestDataBagDeleteRemovesItems(t *testing.T) {
	srv, st := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	do(t, "POST", base+"/data", `{"name":"secrets"}`)
	do(t, "POST", base+"/data/secrets", `{"id":"a"}`)
	do(t, "POST", base+"/data/secrets", `{"id":"b"}`)

	resp, _ := do(t, "DELETE", base+"/data/secrets", "")
	if resp.StatusCode != 200 {
		t.Fatalf("delete bag = %d", resp.StatusCode)
	}
	// The bag and its items are gone.
	resp, _ = do(t, "GET", base+"/data/secrets", "")
	if resp.StatusCode != 404 {
		t.Fatalf("get deleted bag = %d", resp.StatusCode)
	}
	org, _, err := st.Org("acme")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := org.Keys("databag_items:secrets")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatal("items not removed with bag")
	}
}

func TestDataBagItemRequiresID(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	do(t, "POST", base+"/data", `{"name":"secrets"}`)
	resp, _ := do(t, "POST", base+"/data/secrets", `{"value":"no id"}`)
	if resp.StatusCode != 400 {
		t.Fatalf("item without id = %d, want 400", resp.StatusCode)
	}
}

func TestDataBagItemInMissingBag404(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	resp, _ := do(t, "GET", base+"/data/ghost", "")
	if resp.StatusCode != 404 {
		t.Fatalf("missing bag = %d", resp.StatusCode)
	}
	resp, _ = do(t, "POST", base+"/data/ghost", `{"id":"x"}`)
	if resp.StatusCode != 404 {
		t.Fatalf("item in missing bag = %d", resp.StatusCode)
	}
}

// erchef matches a data bag's name and an item's id against
// chef_regex's data_bag_name / data_bag_item_id rule (letters, digits, _, -,
// :, .) and refuses anything else with a 400, creating nothing.
func TestDataBagRejectsInvalidName(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	for _, name := range []string{"bad name", "bad!name", "bad/name", "bad@name"} {
		body, _ := json.Marshal(map[string]string{"name": name})
		resp, out := do(t, "POST", base+"/data", string(body))
		if resp.StatusCode != 400 || !strings.Contains(out, "Field 'name' invalid") {
			t.Errorf("create bag %q = %d %s, want 400 Field 'name' invalid", name, resp.StatusCode, out)
		}
	}
	_, out := do(t, "GET", base+"/data", "")
	if strings.TrimSpace(out) != "{}" {
		t.Errorf("refused bags were created: %s", out)
	}
	for _, name := range []string{"good", "Good_1.2-x", "a:b"} {
		body, _ := json.Marshal(map[string]string{"name": name})
		if resp, out := do(t, "POST", base+"/data", string(body)); resp.StatusCode != 201 {
			t.Errorf("create bag %q = %d %s, want 201", name, resp.StatusCode, out)
		}
	}
}

func TestDataBagItemRejectsInvalidID(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	do(t, "POST", base+"/data", `{"name":"secrets"}`)
	for _, id := range []string{"bad id", "bad/id", "bad!id"} {
		body, _ := json.Marshal(map[string]string{"id": id})
		resp, out := do(t, "POST", base+"/data/secrets", string(body))
		if resp.StatusCode != 400 || !strings.Contains(out, "Field 'id' invalid") {
			t.Errorf("create item %q = %d %s, want 400 Field 'id' invalid", id, resp.StatusCode, out)
		}
	}
	_, out := do(t, "GET", base+"/data/secrets", "")
	if strings.TrimSpace(out) != "{}" {
		t.Errorf("refused items were created: %s", out)
	}
	if resp, out := do(t, "POST", base+"/data/secrets", `{"id":"ok_1.2-x:y"}`); resp.StatusCode != 201 {
		t.Errorf("valid item = %d %s, want 201", resp.StatusCode, out)
	}
}

// TestDataBagItemAcceptsWrappedForm covers the body Chef::DataBagItem#save
// sends: the item's fields under raw_data, with name, json_class, chef_type and
// data_bag alongside. knife tries a PUT and falls back to POST on a 404, so
// both have to unwrap it and store the item's own fields, as erchef does.
func TestDataBagItemAcceptsWrappedForm(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	if resp, body := do(t, "POST", base+"/data", `{"name":"secrets"}`); resp.StatusCode != 201 {
		t.Fatalf("create bag = %d: %s", resp.StatusCode, body)
	}
	wrapped := func(v string) string {
		return `{"name":"data_bag_item_secrets_db","json_class":"Chef::DataBagItem","chef_type":"data_bag_item",` +
			`"data_bag":"secrets","raw_data":{"id":"db","value":"` + v + `"}}`
	}
	stored := func() map[string]any {
		t.Helper()
		resp, body := do(t, "GET", base+"/data/secrets/db", "")
		if resp.StatusCode != 200 {
			t.Fatalf("get item = %d: %s", resp.StatusCode, body)
		}
		var item map[string]any
		if err := json.Unmarshal([]byte(body), &item); err != nil {
			t.Fatal(err)
		}
		if _, ok := item["raw_data"]; ok {
			t.Errorf("item stored still wrapped: %s", body)
		}
		return item
	}

	if resp, body := do(t, "POST", base+"/data/secrets", wrapped("one")); resp.StatusCode != 201 {
		t.Fatalf("create wrapped item = %d: %s", resp.StatusCode, body)
	}
	if got := stored()["value"]; got != "one" {
		t.Errorf("value after create = %v, want one", got)
	}
	if resp, body := do(t, "PUT", base+"/data/secrets/db", wrapped("two")); resp.StatusCode != 200 {
		t.Fatalf("update wrapped item = %d: %s", resp.StatusCode, body)
	}
	if got := stored()["value"]; got != "two" {
		t.Errorf("value after update = %v, want two", got)
	}
}
