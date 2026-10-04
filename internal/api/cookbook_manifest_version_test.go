package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// doAt is do with a server API version, which decides a cookbook manifest's
// shape: segment arrays ("recipes", "files", ...) up to v1, all_files from v2.
func doAt(t *testing.T, version, method, url, body string) (*http.Response, string) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, r)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Ops-Server-API-Version", version)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

// manifestFiles reduces a manifest to {segment: [name|path|checksum, ...]},
// dropping URLs, which differ per request.
func manifestFiles(t *testing.T, body string) map[string][]string {
	t.Helper()
	var doc map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("manifest: %v: %s", err, body)
	}
	out := map[string][]string{}
	for key, raw := range doc {
		var entries []map[string]any
		if json.Unmarshal(raw, &entries) != nil {
			continue
		}
		list := []string{}
		for _, e := range entries {
			list = append(list, e["name"].(string)+"|"+e["path"].(string)+"|"+e["checksum"].(string))
		}
		out[key] = list
	}
	return out
}

func manifestEqual(t *testing.T, what string, got, want map[string][]string) {
	t.Helper()
	g, _ := json.Marshal(got)
	w, _ := json.Marshal(want)
	if string(g) != string(w) {
		t.Errorf("%s\n got %s\nwant %s", what, g, w)
	}
}

// What follows is what a real Chef Infra Server (Cinc Server) returned for the
// same uploads, captured across API versions: a manifest is stored once and
// shown in the shape the requesting client speaks.
func TestCookbookManifestShapeFollowsAPIVersion(t *testing.T) {
	srv, st := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	org, _, _ := st.Org("acme")
	sums := map[string]string{}
	for _, path := range []string{"recipes/default.rb", "attributes/default.rb", "files/default/foo.conf",
		"templates/default/bar.erb", "libraries/lib.rb", "README.md", "metadata.rb"} {
		sums[path] = md5hex(path)
		if err := org.PutBlob(sums[path], []byte(path)); err != nil {
			t.Fatal(err)
		}
	}
	entry := func(name, path string) string {
		return `{"name":"` + name + `","path":"` + path + `","checksum":"` + sums[path] + `","specificity":"default"}`
	}
	head := func(v string) string {
		return `{"name":"probe-` + v + `","cookbook_name":"probe","version":"` + v + `","json_class":"Chef::CookbookVersion",` +
			`"chef_type":"cookbook_version","frozen?":false,"metadata":{"name":"probe","version":"` + v + `","dependencies":{}},`
	}
	allFiles := head("1.0.0") + `"all_files":[` + strings.Join([]string{
		entry("recipes/default.rb", "recipes/default.rb"), entry("attributes/default.rb", "attributes/default.rb"),
		entry("files/default/foo.conf", "files/default/foo.conf"), entry("templates/default/bar.erb", "templates/default/bar.erb"),
		entry("libraries/lib.rb", "libraries/lib.rb"), entry("root_files/README.md", "README.md"),
		entry("root_files/metadata.rb", "metadata.rb")}, ",") + `]}`
	segments := head("2.0.0") +
		`"recipes":[` + entry("default.rb", "recipes/default.rb") + `],` +
		`"attributes":[` + entry("default.rb", "attributes/default.rb") + `],` +
		`"files":[` + entry("foo.conf", "files/default/foo.conf") + `],` +
		`"templates":[` + entry("bar.erb", "templates/default/bar.erb") + `],` +
		`"libraries":[` + entry("lib.rb", "libraries/lib.rb") + `],` +
		`"root_files":[` + entry("README.md", "README.md") + `,` + entry("metadata.rb", "metadata.rb") + `],` +
		`"definitions":[],"providers":[],"resources":[]}`

	// Each shape is only accepted from a client that speaks it.
	if resp, body := doAt(t, "1", "PUT", base+"/cookbooks/probe/1.0.0", allFiles); resp.StatusCode != 400 ||
		!strings.Contains(body, "Invalid key all_files in request body") {
		t.Errorf("all_files at v1 = %d %s, want 400", resp.StatusCode, body)
	}
	if resp, body := doAt(t, "2", "PUT", base+"/cookbooks/probe/2.0.0", segments); resp.StatusCode != 400 ||
		!strings.Contains(body, "Invalid key recipes in request body") {
		t.Errorf("segments at v2 = %d %s, want 400", resp.StatusCode, body)
	}
	if resp, body := doAt(t, "2", "PUT", base+"/cookbooks/probe/1.0.0", allFiles); resp.StatusCode != 201 {
		t.Fatalf("all_files at v2 = %d %s", resp.StatusCode, body)
	}
	if resp, body := doAt(t, "1", "PUT", base+"/cookbooks/probe/2.0.0", segments); resp.StatusCode != 201 {
		t.Fatalf("segments at v1 = %d %s", resp.StatusCode, body)
	}

	f := func(name, path string) string { return name + "|" + path + "|" + sums[path] }
	// all_files shown to an older client: grouped by the segment its name
	// starts with, which is stripped from the name (a specificity directory is
	// kept), and every segment present.
	asSegments := map[string][]string{
		"attributes":  {f("default.rb", "attributes/default.rb")},
		"definitions": {},
		"files":       {f("default/foo.conf", "files/default/foo.conf")},
		"libraries":   {f("lib.rb", "libraries/lib.rb")},
		"providers":   {},
		"recipes":     {f("default.rb", "recipes/default.rb")},
		"resources":   {},
		"root_files":  {f("metadata.rb", "metadata.rb"), f("README.md", "README.md")},
		"templates":   {f("default/bar.erb", "templates/default/bar.erb")},
	}
	for _, v := range []string{"0", "1"} {
		_, body := doAt(t, v, "GET", base+"/cookbooks/probe/1.0.0", "")
		manifestEqual(t, "all_files manifest at v"+v, manifestFiles(t, body), asSegments)
	}
	_, body := doAt(t, "2", "GET", base+"/cookbooks/probe/1.0.0", "")
	manifestEqual(t, "all_files manifest at v2", manifestFiles(t, body), map[string][]string{"all_files": {
		f("recipes/default.rb", "recipes/default.rb"), f("attributes/default.rb", "attributes/default.rb"),
		f("files/default/foo.conf", "files/default/foo.conf"), f("templates/default/bar.erb", "templates/default/bar.erb"),
		f("libraries/lib.rb", "libraries/lib.rb"), f("root_files/README.md", "README.md"),
		f("root_files/metadata.rb", "metadata.rb")}})

	// Segments shown to a v2 client: one all_files list, segment by segment in
	// alphabetical order, each name prefixed with its segment.
	_, body = doAt(t, "2", "GET", base+"/cookbooks/probe/2.0.0", "")
	manifestEqual(t, "segment manifest at v2", manifestFiles(t, body), map[string][]string{"all_files": {
		f("attributes/default.rb", "attributes/default.rb"), f("files/foo.conf", "files/default/foo.conf"),
		f("libraries/lib.rb", "libraries/lib.rb"), f("recipes/default.rb", "recipes/default.rb"),
		f("root_files/README.md", "README.md"), f("root_files/metadata.rb", "metadata.rb"),
		f("templates/bar.erb", "templates/default/bar.erb")}})
	_, body = doAt(t, "1", "GET", base+"/cookbooks/probe/2.0.0", "")
	if files := manifestFiles(t, body); files["all_files"] != nil || len(files["recipes"]) != 1 {
		t.Errorf("segment manifest at v1 = %v, want its segments as stored", files)
	}

	// Artifacts follow the same rule.
	art := strings.Replace(allFiles, `"name":"probe-1.0.0"`, `"name":"probe","identifier":"1111111111111111111111111111111111111111"`, 1)
	if resp, body := doAt(t, "2", "PUT", base+"/cookbook_artifacts/probe/1111111111111111111111111111111111111111", art); resp.StatusCode != 201 {
		t.Fatalf("artifact at v2 = %d %s", resp.StatusCode, body)
	}
	_, body = doAt(t, "0", "GET", base+"/cookbook_artifacts/probe/1111111111111111111111111111111111111111", "")
	manifestEqual(t, "artifact at v0", manifestFiles(t, body), asSegments)

	// And so does the depsolver, which is how a client fetches its cookbooks.
	_, body = doAt(t, "0", "POST", base+"/environments/_default/cookbook_versions", `{"run_list":["probe"]}`)
	var solved map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &solved); err != nil || solved["probe"] == nil {
		t.Fatalf("depsolver = %s", body)
	}
	if files := manifestFiles(t, string(solved["probe"])); files["all_files"] != nil || files["recipes"] == nil {
		t.Errorf("depsolver manifest at v0 = %v, want segments", files)
	}
}
