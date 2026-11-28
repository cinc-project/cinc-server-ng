package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// orgRows snapshots every object stored in org.
func orgRows(t *testing.T, org *store.Org) map[[2]string][]byte {
	t.Helper()
	colls, err := org.Collections()
	if err != nil {
		t.Fatal(err)
	}
	rows := map[[2]string][]byte{}
	for _, c := range colls {
		if err := org.Range(c, func(k string, raw []byte) bool {
			rows[[2]string{c, k}] = bytes.Clone(raw)
			return true
		}); err != nil {
			t.Fatal(err)
		}
	}
	return rows
}

// TestRecreatedOrgInheritsNoLateWrites covers a request that found an org
// before it was deleted and wrote after: registering a client with the old
// validator key while an admin deletes the org. Its writes must not survive
// into an org later created under the same name, where they would make the
// registered client a member of the new org's clients group.
func TestRecreatedOrgInheritsNoLateWrites(t *testing.T) {
	for _, storage := range []string{"memory", "sqlite"} {
		t.Run(storage, func(t *testing.T) {
			opts := Options{Orgs: []string{"acme"}, EnforceACL: true, Storage: storage}
			if storage == "sqlite" {
				opts.DB = filepath.Join(t.TempDir(), "s.db")
			}
			srv := startServer(t, opts)
			base := srv.URL() + "/organizations/acme"

			// Register ghost as a node would, and record exactly what the
			// registration wrote.
			old, ok, err := srv.Store().Org("acme")
			if err != nil || !ok {
				t.Fatalf("Org(acme): ok=%v err=%v", ok, err)
			}
			before := orgRows(t, old)
			resp, err := http.DefaultClient.Do(signedAs(t, "acme-validator", srv.ValidatorKey("acme"),
				"POST", base+"/clients", `{"name":"ghost","create_key":true}`))
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusCreated {
				t.Fatalf("register ghost = %d: %s", resp.StatusCode, body)
			}
			var created struct {
				ChefKey struct {
					PrivateKey string `json:"private_key"`
				} `json:"chef_key"`
			}
			if err := json.Unmarshal(body, &created); err != nil {
				t.Fatal(err)
			}
			ghostKey := []byte(created.ChefKey.PrivateKey)
			late := map[[2]string][]byte{}
			for k, v := range orgRows(t, old) {
				if w, ok := before[k]; !ok || !bytes.Equal(w, v) {
					late[k] = v
				}
			}
			// Baseline: the registered client can act in the org.
			if code := statusOf(t, signedAs(t, "ghost", ghostKey, "GET", base+"/nodes", "")); code != http.StatusOK {
				t.Fatalf("ghost GET nodes before delete = %d, want 200", code)
			}

			if code := statusOf(t, signed(t, srv, "DELETE", base, "")); code != http.StatusOK {
				t.Fatalf("DELETE org = %d", code)
			}
			// The in-flight registration's writes land now, through the
			// handle it took before the delete. They must be refused.
			for k, v := range late {
				if err := old.Put(k[0], k[1], v); err == nil {
					t.Errorf("write of %s/%q into the deleted org succeeded", k[0], k[1])
				}
			}

			if code := statusOf(t, signed(t, srv, "POST", srv.URL()+"/organizations",
				`{"name":"acme","full_name":"Acme"}`)); code != http.StatusCreated {
				t.Fatalf("recreate org = %d", code)
			}
			if code := statusOf(t, signed(t, srv, "GET", base+"/clients/ghost", "")); code != http.StatusNotFound {
				t.Errorf("GET clients/ghost in the recreated org = %d, want 404", code)
			}
			resp, err = http.DefaultClient.Do(signed(t, srv, "GET", base+"/groups/clients", ""))
			if err != nil {
				t.Fatal(err)
			}
			body, _ = io.ReadAll(resp.Body)
			resp.Body.Close()
			if strings.Contains(string(body), "ghost") {
				t.Errorf("recreated org's clients group names ghost: %s", body)
			}
			if code := statusOf(t, signedAs(t, "ghost", ghostKey, "GET", base+"/nodes", "")); code != http.StatusUnauthorized {
				t.Errorf("ghost GET nodes in the recreated org = %d, want 401", code)
			}
		})
	}
}
