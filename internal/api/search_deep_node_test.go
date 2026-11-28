package api

import (
	"strconv"
	"strings"
	"testing"
)

// A node whose attributes nest thousands of levels deep is still accepted and
// still found by name; indexing it no longer costs leaves x depth^2.
func TestSearchDeepNodeStaysBounded(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"

	var leaves strings.Builder
	for i := range 2000 {
		if i > 0 {
			leaves.WriteByte(',')
		}
		leaves.WriteString(`"l` + strconv.Itoa(i) + `":"v"`)
	}
	const depth = 3000
	attrs := strings.Repeat(`{"a":`, depth) + "{" + leaves.String() + "}" + strings.Repeat("}", depth)
	resp, b := do(t, "POST", base+"/nodes", `{"name":"deep","chef_environment":"prod","normal":`+attrs+`}`)
	if resp.StatusCode != 201 {
		t.Fatalf("create deep node: %d %s", resp.StatusCode, b)
	}
	for _, q := range []string{"name:deep", "chef_environment:prod", "l42:v"} {
		resp, b = do(t, "GET", base+"/search/node?q="+q, "")
		if resp.StatusCode != 200 || !strings.Contains(b, `"total":1`) {
			t.Fatalf("search %s: %d %.200s", q, resp.StatusCode, b)
		}
	}
}
