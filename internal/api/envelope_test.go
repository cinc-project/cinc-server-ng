package api

import (
	"encoding/json"
	"testing"
)

// Chef wraps some responses in an object envelope — chef_type, json_class and
// friends — that clients deserialize on. Chef::DataBagItem and
// Chef::ApiClient reconstruct themselves from json_class, so a response
// missing it is not the object the client expected.
//
// Which envelope appears where is not consistent in Chef, and these
// expectations come from diffing against a real server rather than from
// reasoning about what would be tidy:
//
//   - Creating a data bag item returns the item with chef_type and data_bag
//     added, but otherwise flat.
//   - Reading one back returns it flat, with no envelope at all.
//   - Deleting one, and finding one through search, returns the fully wrapped
//     form with the item's own fields moved under raw_data.

func decode(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("not JSON: %v: %s", err, raw)
	}
	return doc
}

func TestDataBagItemCreateEnvelope(t *testing.T) {
	srv, _ := newTestAPI(t)
	do(t, "POST", srv.URL+"/organizations/acme/data", `{"name":"bag"}`)
	_, body := do(t, "POST", srv.URL+"/organizations/acme/data/bag", `{"id":"item","secret":"value"}`)

	doc := decode(t, []byte(body))
	if got := doc["chef_type"]; got != "data_bag_item" {
		t.Errorf("chef_type = %v, want data_bag_item", got)
	}
	if got := doc["data_bag"]; got != "bag" {
		t.Errorf("data_bag = %v, want bag", got)
	}
	// The item's own fields stay at the top level on create.
	if got := doc["secret"]; got != "value" {
		t.Errorf("secret = %v, want value (create keeps the item flat)", got)
	}
	if _, wrapped := doc["raw_data"]; wrapped {
		t.Error("create must not wrap the item under raw_data")
	}
}

func TestDataBagItemReadStaysFlat(t *testing.T) {
	srv, _ := newTestAPI(t)
	do(t, "POST", srv.URL+"/organizations/acme/data", `{"name":"bag"}`)
	do(t, "POST", srv.URL+"/organizations/acme/data/bag", `{"id":"item","secret":"value"}`)

	_, body := do(t, "GET", srv.URL+"/organizations/acme/data/bag/item", "")
	doc := decode(t, []byte(body))
	if got := doc["secret"]; got != "value" {
		t.Errorf("secret = %v, want value", got)
	}
	for _, field := range []string{"chef_type", "json_class", "raw_data"} {
		if _, present := doc[field]; present {
			t.Errorf("read added %q; Chef returns the item unwrapped here", field)
		}
	}
}

func TestDataBagItemDeleteIsWrapped(t *testing.T) {
	srv, _ := newTestAPI(t)
	do(t, "POST", srv.URL+"/organizations/acme/data", `{"name":"bag"}`)
	do(t, "POST", srv.URL+"/organizations/acme/data/bag", `{"id":"item","secret":"value"}`)

	_, body := do(t, "DELETE", srv.URL+"/organizations/acme/data/bag/item", "")
	doc := decode(t, []byte(body))
	for field, want := range map[string]any{
		"chef_type":  "data_bag_item",
		"data_bag":   "bag",
		"json_class": "Chef::DataBagItem",
		"name":       "data_bag_item_bag_item",
	} {
		if got := doc[field]; got != want {
			t.Errorf("%s = %v, want %v", field, got, want)
		}
	}
	raw, ok := doc["raw_data"].(map[string]any)
	if !ok {
		t.Fatalf("raw_data missing or not an object: %v", doc["raw_data"])
	}
	if raw["secret"] != "value" || raw["id"] != "item" {
		t.Errorf("raw_data = %v, want the item's own fields", raw)
	}
	if _, leaked := doc["secret"]; leaked {
		t.Error("the item's fields must move under raw_data, not sit alongside it")
	}
}

func TestDataBagDeleteEnvelope(t *testing.T) {
	srv, _ := newTestAPI(t)
	do(t, "POST", srv.URL+"/organizations/acme/data", `{"name":"bag"}`)

	_, body := do(t, "DELETE", srv.URL+"/organizations/acme/data/bag", "")
	doc := decode(t, []byte(body))
	if got := doc["chef_type"]; got != "data_bag" {
		t.Errorf("chef_type = %v, want data_bag", got)
	}
	if got := doc["json_class"]; got != "Chef::DataBag" {
		t.Errorf("json_class = %v, want Chef::DataBag", got)
	}
}

func TestClientEnvelope(t *testing.T) {
	srv, _ := newTestAPI(t)
	do(t, "POST", srv.URL+"/organizations/acme/clients", `{"name":"node1"}`)

	for _, route := range []struct{ name, method string }{
		{"read", "GET"},
		{"delete", "DELETE"},
	} {
		t.Run(route.name, func(t *testing.T) {
			_, body := do(t, route.method, srv.URL+"/organizations/acme/clients/node1", "")
			doc := decode(t, []byte(body))
			for field, want := range map[string]any{
				"chef_type":  "client",
				"clientname": "node1",
				"json_class": "Chef::ApiClient",
				"orgname":    "acme",
				"name":       "node1",
			} {
				if got := doc[field]; got != want {
					t.Errorf("%s = %v, want %v", field, got, want)
				}
			}
		})
	}
}

// A group names the organization it belongs to.
func TestGroupEnvelope(t *testing.T) {
	srv, _ := newTestAPI(t)
	do(t, "POST", srv.URL+"/organizations/acme/groups", `{"name":"devs"}`)

	_, body := do(t, "GET", srv.URL+"/organizations/acme/groups/devs", "")
	doc := decode(t, []byte(body))
	if got := doc["orgname"]; got != "acme" {
		t.Errorf("orgname = %v, want acme", got)
	}
	if got := doc["groupname"]; got != "devs" {
		t.Errorf("groupname = %v, want devs", got)
	}
}

// Search returns data bag items in the wrapped form, not the raw item.
func TestDataBagSearchReturnsWrappedItems(t *testing.T) {
	srv, _ := newTestAPI(t)
	do(t, "POST", srv.URL+"/organizations/acme/data", `{"name":"bag"}`)
	do(t, "POST", srv.URL+"/organizations/acme/data/bag", `{"id":"item","secret":"value"}`)

	_, body := do(t, "GET", srv.URL+"/organizations/acme/search/bag?q=*:*", "")
	var result struct {
		Rows []map[string]any `json:"rows"`
	}
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		t.Fatalf("search body: %v: %s", err, body)
	}
	if len(result.Rows) != 1 {
		t.Fatalf("got %d rows, want 1: %s", len(result.Rows), body)
	}
	row := result.Rows[0]
	if got := row["json_class"]; got != "Chef::DataBagItem" {
		t.Errorf("json_class = %v, want Chef::DataBagItem", got)
	}
	if got := row["chef_type"]; got != "data_bag_item" {
		t.Errorf("chef_type = %v, want data_bag_item", got)
	}
	raw, ok := row["raw_data"].(map[string]any)
	if !ok || raw["secret"] != "value" {
		t.Errorf("raw_data = %v, want the item's fields", row["raw_data"])
	}
}
