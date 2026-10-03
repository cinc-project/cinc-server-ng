package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// Documents a client writes come back the way a real Chef Infra Server returns
// them. Every expected body here was captured from erchef (Cinc Server) given
// the same request; see internal/chefjson for the rules they follow.

// A body with the client's member order, numbers that a float64 cannot hold,
// floats that look like integers, and escapes erchef rewrites.
const fidelityNode = `{"normal":{"zeta":1,"alpha":2,"Mid":{"b":1,"a":2},"big":12345678901234567890,` +
	`"odd":9007199254740993,"neg":-9007199254740993,"one":1.0,"onetens":1.10,"exp":1e3,` +
	`"expneg":1.5E-7,"negzero":-0,"negzerof":-0.0,"frac":0.1,"third":0.333333333333333333333,` +
	`"int0":0,"arr":[3,1,{"y":1,"x":2}]},"name":"p-node1","run_list":[],"chef_type":"node",` +
	`"json_class":"Chef::Node","chef_environment":"_default","automatic":{},"override":{},"default":{}}`

const fidelityNodeStored = `{"normal":{"zeta":1,"alpha":2,"Mid":{"b":1,"a":2},"big":12345678901234567890,` +
	`"odd":9007199254740993,"neg":-9007199254740993,"one":1.0,"onetens":1.1,"exp":1000.0,` +
	`"expneg":1.5e-7,"negzero":0,"negzerof":0.0,"frac":0.1,"third":0.3333333333333333,` +
	`"int0":0,"arr":[3,1,{"y":1,"x":2}]},"name":"p-node1","run_list":[],"chef_type":"node",` +
	`"json_class":"Chef::Node","chef_environment":"_default","automatic":{},"override":{},"default":{}}`

func wantStatusBody(t *testing.T, what string, resp *http.Response, body string, status int, want string) {
	t.Helper()
	body = strings.TrimSuffix(body, "\n") // writeJSON ends its body with a newline
	if resp.StatusCode != status || body != want {
		t.Errorf("%s = %d\n got %s\nwant %d %s", what, resp.StatusCode, body, status, want)
	}
}

func TestNodeRoundTripsLikeErchef(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"

	if resp, body := do(t, "POST", base+"/nodes", fidelityNode); resp.StatusCode != 201 {
		t.Fatalf("create = %d: %s", resp.StatusCode, body)
	}
	resp, body := do(t, "GET", base+"/nodes/p-node1", "")
	wantStatusBody(t, "GET", resp, body, 200, fidelityNodeStored)

	update := `{"name":"p-node1","chef_environment":"_default","json_class":"Chef::Node","chef_type":"node",` +
		`"default":{},"override":{},"automatic":{},"run_list":[],"normal":{"z":12345678901234567890,"a":1.0,"m":1e3}}`
	stored := `{"name":"p-node1","chef_environment":"_default","json_class":"Chef::Node","chef_type":"node",` +
		`"default":{},"override":{},"automatic":{},"run_list":[],"normal":{"z":12345678901234567890,"a":1.0,"m":1000.0}}`
	resp, body = do(t, "PUT", base+"/nodes/p-node1", update)
	wantStatusBody(t, "PUT", resp, body, 200, stored)
	resp, body = do(t, "GET", base+"/nodes/p-node1", "")
	wantStatusBody(t, "GET after PUT", resp, body, 200, stored)
}

func TestNodeStringsAndDuplicatesLikeErchef(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"

	do(t, "POST", base+"/nodes", `{"name":"q-keys","normal":{"ék":"café","a\/b":"\u0001","k":1,"k":2}}`)
	resp, body := do(t, "GET", base+"/nodes/q-keys", "")
	wantStatusBody(t, "GET", resp, body, 200, `{"name":"q-keys","normal":{"ék":"café","a/b":"\u0001","k":1,"k":2}}`)

	// A repeated name is kept verbatim, and the first one names the node.
	if resp, body := do(t, "POST", base+"/nodes", `{"name":"p-node4a","name":"p-node4b"}`); resp.StatusCode != 201 ||
		!strings.Contains(body, `/nodes/p-node4a"}`) {
		t.Fatalf("create with repeated name = %d: %s", resp.StatusCode, body)
	}
	resp, body = do(t, "GET", base+"/nodes/p-node4a", "")
	wantStatusBody(t, "GET first name", resp, body, 200, `{"name":"p-node4a","name":"p-node4b"}`)
	if resp, _ := do(t, "GET", base+"/nodes/p-node4b", ""); resp.StatusCode != 404 {
		t.Errorf("GET second name = %d, want 404", resp.StatusCode)
	}
}

func TestInvalidJSONIsRejectedLikeErchef(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	for name, body := range map[string]string{
		"invalid UTF-8":    "{\"name\":\"p5\",\"normal\":{\"bad\":\"a\xff\xfeb\"}}",
		"lone surrogate":   `{"name":"p5","normal":{"v":"\ud800x"}}`,
		"trailing garbage": `{"name":"p5"} x`,
		"overflow":         `{"name":"p5","normal":{"huge":1e400}}`,
	} {
		for _, target := range []struct{ method, path string }{
			{"POST", "/nodes"}, {"POST", "/roles"}, {"POST", "/environments"},
		} {
			if resp, got := do(t, target.method, base+target.path, body); resp.StatusCode != 400 {
				t.Errorf("%s %s with %s = %d: %s", target.method, target.path, name, resp.StatusCode, got)
			}
		}
	}
}

func TestRoleAndEnvironmentRoundTripLikeErchef(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"

	do(t, "POST", base+"/roles", `{"override_attributes":{"z":1,"a":12345678901234567890,"f":1.0},"name":"p-role1",`+
		`"description":"d","json_class":"Chef::Role","chef_type":"role","default_attributes":{"y":1e3,"b":2},"run_list":[],"env_run_lists":{}}`)
	resp, body := do(t, "GET", base+"/roles/p-role1", "")
	wantStatusBody(t, "role", resp, body, 200, `{"override_attributes":{"z":1,"a":12345678901234567890,"f":1.0},"name":"p-role1",`+
		`"description":"d","json_class":"Chef::Role","chef_type":"role","default_attributes":{"y":1000.0,"b":2},"run_list":[],"env_run_lists":{}}`)

	do(t, "POST", base+"/environments", `{"override_attributes":{"z":1,"a":12345678901234567890,"f":1.0},"name":"p-env1",`+
		`"description":"d","json_class":"Chef::Environment","chef_type":"environment","default_attributes":{"y":1e3},"cookbook_versions":{}}`)
	resp, body = do(t, "GET", base+"/environments/p-env1", "")
	wantStatusBody(t, "environment", resp, body, 200, `{"override_attributes":{"z":1,"a":12345678901234567890,"f":1.0},"name":"p-env1",`+
		`"description":"d","json_class":"Chef::Environment","chef_type":"environment","default_attributes":{"y":1000.0},"cookbook_versions":{}}`)
}

// erchef validates the first member of a repeated name, and keeps the rest.
func TestRepeatedNameValidatesTheFirstLikeErchef(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"

	resp, body := do(t, "POST", base+"/roles", `{"name":"q-role-a","name":"q-role-b!","json_class":"Chef::Role"}`)
	if resp.StatusCode != 201 {
		t.Fatalf("valid first name = %d: %s", resp.StatusCode, body)
	}
	resp, body = do(t, "GET", base+"/roles/q-role-a", "")
	wantStatusBody(t, "GET", resp, body, 200, `{"name":"q-role-a","name":"q-role-b!","json_class":"Chef::Role"}`)

	resp, body = do(t, "POST", base+"/roles", `{"name":"q-role c!","name":"q-role-d"}`)
	wantStatusBody(t, "invalid first name", resp, body, 400, `{"error":["Field 'name' invalid"]}`)

	do(t, "POST", base+"/data", `{"name":"q-bag"}`)
	resp, body = do(t, "POST", base+"/data/q-bag", `{"id":"bad id!","id":"q-ok"}`)
	wantStatusBody(t, "invalid first id", resp, body, 400, `{"error":["Field 'id' invalid"]}`)

	resp, body = do(t, "POST", base+"/environments", `{"name":"q-env-a","name":"q-env-b","description":"x"}`)
	if resp.StatusCode != 201 || !strings.Contains(body, `/environments/q-env-a"}`) {
		t.Errorf("environment with repeated name = %d: %s", resp.StatusCode, body)
	}
}

func TestDataBagItemRoundTripsLikeErchef(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	do(t, "POST", base+"/data", `{"name":"p-bag"}`)

	resp, body := do(t, "POST", base+"/data/p-bag",
		`{"zeta":1,"id":"p-item1","big":12345678901234567890,"one":1.0,"exp":1e3,"nest":{"b":1,"a":2},"s":"café\/<>"}`)
	wantStatusBody(t, "create", resp, body, 201,
		`{"zeta":1,"id":"p-item1","big":12345678901234567890,"one":1.0,"exp":1000.0,"nest":{"b":1,"a":2},"s":"café/<>","chef_type":"data_bag_item","data_bag":"p-bag"}`)
	resp, body = do(t, "GET", base+"/data/p-bag/p-item1", "")
	wantStatusBody(t, "GET", resp, body, 200,
		`{"zeta":1,"id":"p-item1","big":12345678901234567890,"one":1.0,"exp":1000.0,"nest":{"b":1,"a":2},"s":"café/<>"}`)

	do(t, "PUT", base+"/data/p-bag/p-item1", `{"zeta":2,"id":"p-item1","big":12345678901234567891,"one":2.0,"zeta":3}`)
	resp, body = do(t, "GET", base+"/data/p-bag/p-item1", "")
	wantStatusBody(t, "GET after PUT", resp, body, 200, `{"zeta":2,"id":"p-item1","big":12345678901234567891,"one":2.0,"zeta":3}`)

	// The Chef::DataBagItem wire form is unwrapped, keeping the item's order.
	resp, body = do(t, "POST", base+"/data/p-bag", `{"json_class":"Chef::DataBagItem","chef_type":"data_bag_item","data_bag":"p-bag",`+
		`"name":"data_bag_item_p-bag_q-w","raw_data":{"z":1,"id":"q-w","a":1.0}}`)
	wantStatusBody(t, "create wrapped", resp, body, 201, `{"z":1,"id":"q-w","a":1.0,"chef_type":"data_bag_item","data_bag":"p-bag"}`)
	resp, body = do(t, "GET", base+"/data/p-bag/q-w", "")
	wantStatusBody(t, "GET wrapped", resp, body, 200, `{"z":1,"id":"q-w","a":1.0}`)
}

func TestPolicyRevisionRoundTripsLikeErchef(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	rev := `{"run_list":["recipe[p::default]"],"revision_id":"909c26701e291510eacdc6c06d626b9fa5350d25","name":"p-policy",` +
		`"cookbook_locks":{"p":{"version":"1.2.3","identifier":"f04cc40faf628253fe7d9566d66a1733fb1afbe9"}},` +
		`"default_attributes":{"z":1,"a":12345678901234567890,"f":1.0,"e":1e3},"override_attributes":{}}`
	stored := strings.Replace(rev, `"e":1e3`, `"e":1000.0`, 1)
	if resp, body := do(t, "PUT", base+"/policy_groups/p-group/policies/p-policy", rev); resp.StatusCode/100 != 2 || body != stored {
		t.Errorf("PUT = %d\n got %s\nwant %s", resp.StatusCode, body, stored)
	}
	resp, body := do(t, "GET", base+"/policy_groups/p-group/policies/p-policy", "")
	wantStatusBody(t, "GET via group", resp, body, 200, stored)
}

func TestCookbookRoundTripsLikeErchef(t *testing.T) {
	srv, st := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	org, _, err := st.Org("acme")
	if err != nil {
		t.Fatal(err)
	}
	sum := md5hex("package 'x'\n")
	if err := org.PutBlob(sum, []byte("package 'x'\n")); err != nil {
		t.Fatal(err)
	}

	manifest := `{"name":"qcb-1.2.3","cookbook_name":"qcb","version":"1.2.3","json_class":"Chef::CookbookVersion",` +
		`"chef_type":"cookbook_version","frozen?":false,"metadata":{"version":"1.2.3","name":"qcb",` +
		`"dependencies":{"zz":">= 0.0.0","aa":">= 0.0.0"},"custom":{"n":12345678901234567890,"f":1.0}},` +
		`"recipes":[{"path":"recipes/default.rb","name":"default.rb","checksum":"` + sum + `","specificity":"default"}],"attributes":[]}`
	resp, put := do(t, "PUT", base+"/cookbooks/qcb/1.2.3", manifest)
	if resp.StatusCode != 201 {
		t.Fatalf("PUT = %d: %s", resp.StatusCode, put)
	}
	resp, body := do(t, "GET", base+"/cookbooks/qcb/1.2.3", "")
	if resp.StatusCode != 200 || body != put {
		t.Fatalf("GET = %d, want the PUT response\n got %s\nwant %s", resp.StatusCode, body, put)
	}
	// The file entry gains its download URL as a last member; everything else
	// is as stored.
	const before = `"specificity":"default","url":"`
	i := strings.Index(body, before)
	if i < 0 {
		t.Fatalf("file entry has no trailing url: %s", body)
	}
	end := i + len(before) + strings.Index(body[i+len(before):], `"`) + 1
	if got := body[:i] + `"specificity":"default"` + body[end:]; got != manifest {
		t.Errorf("GET without the url\n got %s\nwant %s", got, manifest)
	}
}

func TestSearchMatchesStoredNumbersLikeErchef(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	do(t, "POST", base+"/nodes", fidelityNode)

	for q, want := range map[string]int{
		"big:12345678901234567890": 1,
		"big:12345678901234567000": 0,
		"one:1.0":                  1,
		"one:1":                    0,
	} {
		_, body := do(t, "GET", base+"/search/node?q="+q, "")
		var res struct {
			Total int               `json:"total"`
			Rows  []json.RawMessage `json:"rows"`
		}
		if err := json.Unmarshal([]byte(body), &res); err != nil {
			t.Fatalf("%s: %v (%s)", q, err, body)
		}
		if res.Total != want {
			t.Errorf("search %s: total = %d, want %d", q, res.Total, want)
		}
		if want == 1 && (len(res.Rows) != 1 || string(res.Rows[0]) != fidelityNodeStored) {
			t.Errorf("search %s row\n got %s\nwant %s", q, res.Rows, fidelityNodeStored)
		}
	}

	// A partial search returns the stored number, not a float64 of it.
	resp, body := do(t, "POST", base+"/search/node?q=name:p-node1", `{"b":["big"],"o":["one"]}`)
	if resp.StatusCode != 200 || !strings.Contains(body, `"b":12345678901234567890`) || !strings.Contains(body, `"o":1.0`) {
		t.Errorf("partial search = %d: %s", resp.StatusCode, body)
	}
}

// A manifest names the files the server signs download URLs for and keeps
// blobs alive for, so it must say one thing: with a repeated name, the
// server's checks would read one member and a Ruby client (last member wins)
// another, letting an unuploaded checksum through the upload check.
func TestManifestWithRepeatedNamesIsRejected(t *testing.T) {
	srv, st := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	org, _, err := st.Org("acme")
	if err != nil {
		t.Fatal(err)
	}
	sum := md5hex("package 'x'\n")
	if err := org.PutBlob(sum, []byte("package 'x'\n")); err != nil {
		t.Fatal(err)
	}
	missing := md5hex("never uploaded")
	file := func(s string) string {
		return `{"path":"recipes/default.rb","name":"default.rb","checksum":"` + s + `","specificity":"default"}`
	}
	head := `{"name":"qcb-1.2.3","cookbook_name":"qcb","version":"1.2.3","metadata":{"name":"qcb","version":"1.2.3"},`

	// Baseline: the same manifest without a repeat is accepted.
	if resp, body := do(t, "PUT", base+"/cookbooks/qcb/1.2.3", head+`"recipes":[`+file(sum)+`]}`); resp.StatusCode != 201 {
		t.Fatalf("baseline PUT = %d: %s", resp.StatusCode, body)
	}
	for name, manifest := range map[string]string{
		"repeated segment":  head + `"recipes":[` + file(sum) + `],"recipes":[` + file(missing) + `]}`,
		"repeated checksum": head + `"recipes":[{"path":"recipes/default.rb","checksum":"` + sum + `","checksum":"` + missing + `"}]}`,
	} {
		if resp, body := do(t, "PUT", base+"/cookbooks/qcb/1.2.4", manifest); resp.StatusCode != 400 {
			t.Errorf("cookbook with %s = %d: %s", name, resp.StatusCode, body)
		}
		ident := md5hex(name) + "00000000"
		if resp, body := do(t, "PUT", base+"/cookbook_artifacts/qcb/"+ident, manifest); resp.StatusCode != 400 {
			t.Errorf("artifact with %s = %d: %s", name, resp.StatusCode, body)
		}
	}
}
