package api

import (
	"net/http"

	"github.com/tas50/cinc-zero/internal/store"
)

// defaultEnvironment is the immutable environment Chef guarantees in every org.
const defaultEnvironment = `{"name":"_default","description":"The default Chef environment","cookbook_versions":{},"json_class":"Chef::Environment","chef_type":"environment","default_attributes":{},"override_attributes":{}}`

// SeedOrg initializes a newly created organization with the objects Chef
// guarantees to exist: the _default environment. (Default authz groups and
// containers are added as those subsystems land.)
func SeedOrg(org *store.Org) error {
	_, ok, err := org.Get("environments", "_default")
	if err != nil {
		return err
	}
	if !ok {
		if err := org.Put("environments", "_default", []byte(defaultEnvironment)); err != nil {
			return err
		}
	}
	return seedAuthz(org)
}

// registerEnvironmentRoutes wires environments using the generic object CRUD
// but protects the immutable _default environment from mutation.
func (a *API) registerEnvironmentRoutes(mux *recordingMux) {
	a.registerObjectRoutes(mux, "environments")

	base := "/organizations/{org}/environments/_default"
	mux.HandleFunc("PUT "+base, func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusMethodNotAllowed, "The '_default' environment cannot be modified.")
	})
	mux.HandleFunc("DELETE "+base, func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusMethodNotAllowed, "The '_default' environment cannot be deleted.")
	})
}
