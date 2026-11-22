package server

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A server-admins member may create an organization (a cinc-server-ng
// extension: on Chef Infra Server only the superuser can), and becomes a member
// and admin of the org it creates, since it could not join it afterwards.
func TestServerAdminCreatesOrganization(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			opts := Options{Orgs: []string{"acme"}, EnforceACL: true}
			if backend == "sqlite" {
				opts.Storage, opts.DB = "sqlite", filepath.Join(t.TempDir(), "x.db")
			}
			srv := startServer(t, opts)
			u := srv.URL()
			alice := []byte(createUser(t, srv, `{"name":"alice"}`))
			createUser(t, srv, `{"name":"bob"}`)
			as := func(method, path, body string) (int, string) {
				return doBody(t, signedAs(t, "alice", alice, method, u+path, body))
			}

			// Baseline: a plain user may not create an organization.
			if code, body := as("POST", "/organizations", `{"name":"before","full_name":"Before"}`); code != http.StatusForbidden {
				t.Fatalf("plain user POST /organizations = %d, want 403: %s", code, body)
			}

			if code, body := doBody(t, signed(t, srv, "PUT", u+"/_cinc/server_admins/alice", "")); code != http.StatusCreated {
				t.Fatalf("add alice to server-admins = %d: %s", code, body)
			}

			code, body := as("POST", "/organizations", `{"name":"newco","full_name":"New Co"}`)
			if code != http.StatusCreated {
				t.Fatalf("server-admin POST /organizations = %d, want 201: %s", code, body)
			}
			var created struct {
				ClientName string `json:"clientname"`
				PrivateKey string `json:"private_key"`
			}
			if err := json.Unmarshal([]byte(body), &created); err != nil {
				t.Fatalf("decode %s: %v", body, err)
			}
			if created.ClientName != "newco-validator" || !strings.Contains(created.PrivateKey, "PRIVATE KEY") {
				t.Errorf("create response = %s, want the validator and its key", body)
			}

			// The creator is a member and an admin of the new org.
			code, body = as("GET", "/organizations/newco/users", "")
			if code != http.StatusOK || !strings.Contains(body, `"username":"alice"`) {
				t.Errorf("GET newco/users as alice = %d %s, want alice listed", code, body)
			}
			for _, g := range []string{"users", "admins"} {
				if users := groupUsers(t, srv, "newco", g); !slices.Contains(users, "alice") {
					t.Errorf("newco %s group = %v, want alice", g, users)
				}
			}
			if code, body := as("POST", "/organizations/newco/nodes", `{"name":"web1","json_class":"Chef::Node","chef_type":"node"}`); code != http.StatusCreated {
				t.Errorf("creator POST newco/nodes = %d, want 201: %s", code, body)
			}
			if code, body := as("POST", "/organizations/newco/association_requests", `{"user":"bob"}`); code != http.StatusCreated {
				t.Errorf("creator invites bob to newco = %d, want 201: %s", code, body)
			}
			// Creating one org grants nothing in another.
			if code, _ := as("GET", "/organizations/acme/nodes", ""); code != http.StatusForbidden {
				t.Errorf("creator GET acme/nodes = %d, want 403", code)
			}

			// Leaving server-admins revokes the right to create orgs.
			if code, body := doBody(t, signed(t, srv, "DELETE", u+"/_cinc/server_admins/alice", "")); code != http.StatusOK {
				t.Fatalf("remove alice from server-admins = %d: %s", code, body)
			}
			if code, body := as("POST", "/organizations", `{"name":"after","full_name":"After"}`); code != http.StatusForbidden {
				t.Errorf("former server-admin POST /organizations = %d, want 403: %s", code, body)
			}
		})
	}
}

// The superuser's org creation is unchanged: like pivotal on Chef Infra Server,
// it does not become a member of the org it provisions.
func TestSuperuserCreatedOrgHasNoCreatorMember(t *testing.T) {
	srv := startServer(t, Options{EnforceACL: true})
	if code, body := doBody(t, signed(t, srv, "POST", srv.URL()+"/organizations", `{"name":"newco","full_name":"New Co"}`)); code != http.StatusCreated {
		t.Fatalf("POST /organizations = %d: %s", code, body)
	}
	code, body := doBody(t, signed(t, srv, "GET", srv.URL()+"/organizations/newco/users", ""))
	if code != http.StatusOK || strings.TrimSpace(body) != "[]" {
		t.Errorf("newco/users = %d %s, want []", code, body)
	}
	for _, g := range []string{"users", "admins"} {
		if users := groupUsers(t, srv, "newco", g); len(users) != 0 {
			t.Errorf("newco %s group = %v, want empty", g, users)
		}
	}
}
