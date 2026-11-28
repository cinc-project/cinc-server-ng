package api

import (
	"net/http"
	"testing"

	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// Authorization and the handler must judge the same org. A request naming an
// org that does not exist passes authorization (there is nothing to check;
// the handler answers 404), so if the org is created between the two, the
// handler would act on a real org that no membership gate or ACL had judged.
// These tests create the org at exactly that point.

// TestRequestRacingOrgCreation drives each request at an org created after
// authorization and before the handler, by a user outside the org.
func TestRequestRacingOrgCreation(t *testing.T) {
	cases := []struct {
		name, method, path, body string
		// created reports whether the request's write landed in the org.
		created func(org *store.Org) bool
	}{
		{
			name: "register client", method: "POST", path: "/organizations/beta/clients",
			body:    `{"name":"evil"}`,
			created: func(org *store.Org) bool { _, ok, _ := org.Get("clients", "evil"); return ok },
		},
		{
			name: "create node", method: "POST", path: "/organizations/beta/nodes",
			body:    `{"name":"n1","json_class":"Chef::Node","chef_type":"node"}`,
			created: func(org *store.Org) bool { _, ok, _ := org.Get("nodes", "n1"); return ok },
		},
		{name: "read org", method: "GET", path: "/organizations/beta"},
		{name: "list nodes", method: "GET", path: "/organizations/beta/nodes"},
	}
	stranger := Actor{Name: "mallory"}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Baseline: with the org in place beforehand, the gate refuses.
			st := store.New()
			if _, err := CreateOrganization(st, "beta", "Beta"); err != nil {
				t.Fatal(err)
			}
			h := New(st, WithACLEnforcement(true)).Handler()
			if code, body := authzReq(t, h, stranger, tc.method, tc.path, tc.body); code != http.StatusForbidden {
				t.Fatalf("baseline: %s %s by a non-member = %d, want 403: %s", tc.method, tc.path, code, body)
			}

			// Race: the org appears once authorization has passed.
			st = store.New()
			a := New(st, WithACLEnforcement(true))
			a.afterAuthorize = func(*http.Request) {
				if _, err := CreateOrganization(st, "beta", "Beta"); err != nil {
					t.Error(err)
				}
			}
			h = a.Handler()
			code, body := authzReq(t, h, stranger, tc.method, tc.path, tc.body)
			if code != http.StatusNotFound || body != `{"error":["Cannot find org beta"]}`+"\n" {
				t.Errorf("%s %s with the org created after authorization = %d %s, want the missing org's 404", tc.method, tc.path, code, body)
			}
			if tc.created != nil {
				org, ok, err := st.Org("beta")
				if err != nil || !ok {
					t.Fatalf("org beta: ok=%v err=%v", ok, err)
				}
				if tc.created(org) {
					t.Error("the request wrote into the org it was never authorized against")
				}
			}
		})
	}
}
