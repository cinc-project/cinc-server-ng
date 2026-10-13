package api

import (
	"encoding/json"
	"strings"
	"testing"
)

// A cookbook version PUT is validated as erchef's
// chef_cookbook_version:parse_binary_json does: the URL version first, then
// the URL name, defaults for json_class, chef_type and frozen?, then the top
// level keys against the API version's list, then the spec in its order. The
// messages are chef_wm_malformed's and chef_wm_cookbook_version's.
func TestCookbookVersionPutValidation(t *testing.T) {
	srv, st := newTestAPI(t)
	base := srv.URL + "/organizations/acme/cookbooks/"
	org, _, _ := st.Org("acme")
	sum := md5hex("hello\n")
	if err := org.PutBlob(sum, []byte("hello\n")); err != nil {
		t.Fatal(err)
	}
	file := func(name string) string {
		return `{"name":"` + name + `","path":"recipes/default.rb","checksum":"` + sum + `","specificity":"default"}`
	}

	cases := []struct {
		what, apiVersion, url, body, want string
	}{
		{"all_files below v2", "1", "cb/1.0.0",
			`{"name":"cb-1.0.0","cookbook_name":"cb","version":"1.0.0","chef_type":"cookbook_version","all_files":[` + file("default.rb") + `]}`,
			"Invalid key all_files in request body"},
		{"segment at v2", "2", "cb/1.0.0",
			`{"name":"cb-1.0.0","cookbook_name":"cb","metadata":{"version":"1.0.0"},"recipes":[` + file("default.rb") + `]}`,
			"Invalid key recipes in request body"},
		{"unknown key, first in document order", "2", "cb/3.0.0",
			`{"name":"cb-3.0.0","bogus":1,"cookbook_name":"cb","metadata":{"version":"3.0.0"},"recipes":[]}`,
			"Invalid key bogus in request body"},
		{"metadata missing", "1", "cb/4.0.0",
			`{"name":"cb-4.0.0","cookbook_name":"cb","version":"4.0.0","recipes":[` + file("default.rb") + `]}`,
			"Field 'metadata' missing"},
		{"metadata not an object", "2", "cb/4.0.0",
			`{"name":"cb-4.0.0","cookbook_name":"cb","metadata":"4.0.0"}`,
			"Field 'metadata' invalid"},
		{"metadata.version missing", "2", "cb/4.0.0",
			`{"name":"cb-4.0.0","cookbook_name":"cb","metadata":{"name":"cb"}}`,
			"Field 'metadata.version' missing"},
		{"metadata.version differs from the URL", "2", "cb/2.0.0",
			`{"name":"cb-2.0.0","cookbook_name":"cb","version":"2.0.0","metadata":{"version":"9.9.9"},"all_files":[` + file("recipes/default.rb") + `]}`,
			"Field 'metadata.version' invalid"},
		{"name missing", "2", "cb/5.0.0",
			`{"cookbook_name":"cb","metadata":{"version":"5.0.0"}}`,
			"Field 'name' missing"},
		{"name for another cookbook", "2", "cb/5.0.0",
			`{"name":"other-1.0.0","cookbook_name":"other","version":"5.0.0","metadata":{"version":"5.0.0"},"all_files":[` + file("recipes/default.rb") + `]}`,
			"Field 'name' invalid"},
		{"cookbook_name for another cookbook", "2", "cb/5.0.0",
			`{"name":"cb-5.0.0","cookbook_name":"other","metadata":{"version":"5.0.0"}}`,
			"Field 'cookbook_name' invalid"},
		{"cookbook_name missing", "2", "cb/5.0.0",
			`{"name":"cb-5.0.0","metadata":{"version":"5.0.0"}}`,
			"Field 'cookbook_name' missing"},
		{"json_class wrong", "2", "cb/5.0.0",
			`{"name":"cb-5.0.0","cookbook_name":"cb","json_class":"Chef::Node","metadata":{"version":"5.0.0"}}`,
			"Field 'json_class' invalid"},
		{"chef_type null is not defaulted", "2", "cb/5.0.0",
			`{"name":"cb-5.0.0","cookbook_name":"cb","chef_type":null,"metadata":{"version":"5.0.0"}}`,
			"Field 'chef_type' invalid"},
		{"top-level version differs", "2", "cb/5.0.0",
			`{"name":"cb-5.0.0","cookbook_name":"cb","version":"5.0.1","metadata":{"version":"5.0.0"}}`,
			"Field 'version' invalid"},
		{"metadata.name malformed", "2", "cb/5.0.0",
			`{"name":"cb-5.0.0","cookbook_name":"cb","metadata":{"version":"5.0.0","name":"c b"}}`,
			"Field 'metadata.name' invalid"},
		{"metadata.maintainer null", "2", "cb/5.0.0",
			`{"name":"cb-5.0.0","cookbook_name":"cb","metadata":{"version":"5.0.0","maintainer":null}}`,
			"Field 'metadata.maintainer' invalid"},
		{"dependency name malformed", "2", "cb/5.0.0",
			`{"name":"cb-5.0.0","cookbook_name":"cb","metadata":{"version":"5.0.0","dependencies":{"ok":">= 0.0.0","b@d":">= 1.0"}}}`,
			"Invalid key 'b@d' for metadata.dependencies"},
		{"dependency constraint malformed", "2", "cb/5.0.0",
			`{"name":"cb-5.0.0","cookbook_name":"cb","metadata":{"version":"5.0.0","dependencies":{"apt":"bogus"}}}`,
			"Invalid value 'bogus' for metadata.dependencies"},
		{"platforms are a constraint map", "2", "cb/5.0.0",
			`{"name":"cb-5.0.0","cookbook_name":"cb","metadata":{"version":"5.0.0","platforms":{"ubuntu":">=1"}}}`,
			"Invalid value '>=1' for metadata.platforms"},
		{"v1 checks recommendations", "1", "cb/5.0.0",
			`{"name":"cb-5.0.0","cookbook_name":"cb","metadata":{"version":"5.0.0","recommendations":{"apt":"nope"}}}`,
			"Invalid value 'nope' for metadata.recommendations"},
		{"segment not an array", "1", "cb/5.0.0",
			`{"name":"cb-5.0.0","cookbook_name":"cb","metadata":{"version":"5.0.0"},"recipes":{}}`,
			"Field 'recipes' invalid"},
		{"segment entry incomplete", "1", "cb/5.0.0",
			`{"name":"cb-5.0.0","cookbook_name":"cb","metadata":{"version":"5.0.0"},"recipes":[{"name":"default.rb","path":"recipes/default.rb"}]}`,
			"Invalid element in array value of 'recipes'."},
		{"URL version malformed", "2", "cb/1.0.0.0",
			`{"name":"cb-1.0.0.0","cookbook_name":"cb","metadata":{"version":"1.0.0.0"}}`,
			"Invalid cookbook version '1.0.0.0'."},
	}
	for _, c := range cases {
		resp, body := doAt(t, c.apiVersion, "PUT", base+c.url, c.body)
		if resp.StatusCode != 400 {
			t.Errorf("%s: status %d %s, want 400", c.what, resp.StatusCode, body)
			continue
		}
		var got struct{ Error []string }
		if err := json.Unmarshal([]byte(body), &got); err != nil || len(got.Error) != 1 || got.Error[0] != c.want {
			t.Errorf("%s: body %s, want error %q", c.what, body, c.want)
		}
	}
	if resp, body := doAt(t, "2", "GET", base+"cb", ""); resp.StatusCode != 404 {
		t.Errorf("a rejected PUT stored a version: %d %s", resp.StatusCode, body)
	}
}

// What erchef accepts: the minimal manifest, with json_class, chef_type and
// frozen? filled in, and recommendations ignored under v2, whose spec does not
// list them.
func TestCookbookVersionPutDefaults(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme/cookbooks/"
	for _, c := range []struct{ apiVersion, url, body string }{
		{"0", "cb/1.0.0", `{"name":"cb-1.0.0","cookbook_name":"cb","metadata":{"version":"1.0.0"},"recipes":[]}`},
		{"2", "cb/2.0", `{"name":"cb-2.0","cookbook_name":"cb","metadata":{"version":"2.0","recommendations":{"apt":"nope"}},"all_files":[]}`},
	} {
		resp, body := doAt(t, c.apiVersion, "PUT", base+c.url, c.body)
		if resp.StatusCode != 201 {
			t.Fatalf("PUT %s at v%s = %d %s", c.url, c.apiVersion, resp.StatusCode, body)
		}
		for _, b := range []string{body, func() string { _, b := doAt(t, c.apiVersion, "GET", base+c.url, ""); return b }()} {
			var doc map[string]any
			if err := json.Unmarshal([]byte(b), &doc); err != nil {
				t.Fatal(err)
			}
			if doc["json_class"] != "Chef::CookbookVersion" || doc["chef_type"] != "cookbook_version" || doc["frozen?"] != false {
				t.Errorf("%s: defaults not filled: %s", c.url, b)
			}
		}
		if !strings.Contains(body, `"name":"cb-`) {
			t.Errorf("%s: body %s", c.url, body)
		}
	}
}
