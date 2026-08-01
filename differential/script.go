package differential

// The comparison script.
//
// Steps are stateful and run in order: objects are created, read back, listed,
// updated, and deleted, so the script exercises each type through its lifecycle
// rather than only its happy-path read.
//
// Error responses get as much attention as successful ones. Status codes and
// error-body shapes are what clients branch on, they are easy to get subtly
// wrong, and nothing else in this repository compares them against the real
// thing.

// Script returns the sequence issued to both servers. Object names are prefixed
// so a run against a real server is easy to identify and clean up.
func Script() []Step {
	const node = `{"name":"diff-node","chef_environment":"_default","json_class":"Chef::Node",` +
		`"chef_type":"node","normal":{"role":"frontend"},"default":{},"override":{},"automatic":{},` +
		`"run_list":["recipe[diff-cookbook::default]"]}`

	return []Step{
		// --- server-level -------------------------------------------------
		{Name: "server api version", Method: "GET", Path: "/server_api_version", ServerRoot: true},
		{Name: "license", Method: "GET", Path: "/license", ServerRoot: true},

		// --- nodes ----------------------------------------------------------
		{Name: "node list empty", Method: "GET", Path: "/nodes"},
		{Name: "node create", Method: "POST", Path: "/nodes", Body: node},
		{Name: "node create conflict", Method: "POST", Path: "/nodes", Body: node},
		{Name: "node read", Method: "GET", Path: "/nodes/diff-node"},
		{Name: "node list", Method: "GET", Path: "/nodes"},
		{Name: "node update", Method: "PUT", Path: "/nodes/diff-node",
			Body: `{"name":"diff-node","chef_environment":"_default","json_class":"Chef::Node",` +
				`"chef_type":"node","normal":{"role":"backend"},"default":{},"override":{},` +
				`"automatic":{},"run_list":[]}`},
		{Name: "node read after update", Method: "GET", Path: "/nodes/diff-node"},
		{Name: "node missing", Method: "GET", Path: "/nodes/diff-absent"},
		{Name: "node acl", Method: "GET", Path: "/nodes/diff-node/_acl"},

		// --- roles ----------------------------------------------------------
		{Name: "role create", Method: "POST", Path: "/roles",
			Body: `{"name":"diff-role","description":"d","json_class":"Chef::Role",` +
				`"chef_type":"role","default_attributes":{},"override_attributes":{},` +
				`"run_list":["recipe[diff-cookbook]"],"env_run_lists":{}}`},
		{Name: "role read", Method: "GET", Path: "/roles/diff-role"},
		{Name: "role list", Method: "GET", Path: "/roles"},
		{Name: "role missing", Method: "GET", Path: "/roles/diff-absent"},

		// --- environments -----------------------------------------------
		{Name: "environment default", Method: "GET", Path: "/environments/_default"},
		{Name: "environment create", Method: "POST", Path: "/environments",
			Body: `{"name":"diff-env","description":"d","json_class":"Chef::Environment",` +
				`"chef_type":"environment","default_attributes":{},"override_attributes":{},` +
				`"cookbook_versions":{}}`},
		{Name: "environment read", Method: "GET", Path: "/environments/diff-env"},
		{Name: "environment list", Method: "GET", Path: "/environments"},

		// --- data bags ------------------------------------------------------
		{Name: "data bag create", Method: "POST", Path: "/data", Body: `{"name":"diff-bag"}`},
		{Name: "data bag list", Method: "GET", Path: "/data"},
		{Name: "data bag item create", Method: "POST", Path: "/data/diff-bag",
			Body: `{"id":"diff-item","secret":"value"}`},
		{Name: "data bag item read", Method: "GET", Path: "/data/diff-bag/diff-item"},
		{Name: "data bag contents", Method: "GET", Path: "/data/diff-bag"},
		{Name: "data bag missing", Method: "GET", Path: "/data/diff-absent"},

		// --- search -----------------------------------------------------------
		{Name: "search indexes", Method: "GET", Path: "/search"},
		{Name: "search nodes", Method: "GET", Path: "/search/node?q=role:backend"},
		{Name: "search nodes all", Method: "GET", Path: "/search/node?q=*:*"},
		{Name: "search data bag", Method: "GET", Path: "/search/diff-bag?q=*:*"},
		{Name: "search unknown index", Method: "GET", Path: "/search/diff-absent?q=*:*"},

		// --- authorization objects ------------------------------------------
		{Name: "group list", Method: "GET", Path: "/groups"},
		{Name: "group admins", Method: "GET", Path: "/groups/admins"},
		{Name: "container list", Method: "GET", Path: "/containers"},
		{Name: "org acl", Method: "GET", Path: "/_acl"},

		// --- clients ----------------------------------------------------------
		{Name: "client list", Method: "GET", Path: "/clients"},
		// Creation returns a freshly generated private key, so only the status
		// is comparable.
		{Name: "client create", Method: "POST", Path: "/clients",
			Body: `{"name":"diff-client","admin":false,"validator":false}`, SkipBody: true},
		{Name: "client read", Method: "GET", Path: "/clients/diff-client"},
		{Name: "client missing", Method: "GET", Path: "/clients/diff-absent"},

		// --- cookbooks and policies -------------------------------------------
		{Name: "cookbook list", Method: "GET", Path: "/cookbooks"},
		{Name: "cookbook missing", Method: "GET", Path: "/cookbooks/diff-absent"},
		{Name: "policy list", Method: "GET", Path: "/policies"},
		{Name: "policy group list", Method: "GET", Path: "/policy_groups"},
		{Name: "policy revision push", Method: "PUT", Path: "/policy_groups/diff-group/policies/diff-policy",
			Body: `{"name":"diff-policy","revision_id":"1111111111111111111111111111111111111111111111111111111111111111",` +
				`"run_list":["recipe[diff-cookbook::default]"],"cookbook_locks":{},"solution_dependencies":{}}`},
		{Name: "policy group read", Method: "GET", Path: "/policy_groups/diff-group"},
		{Name: "policy revision read", Method: "GET",
			Path: "/policies/diff-policy/revisions/1111111111111111111111111111111111111111111111111111111111111111"},

		// --- malformed input ---------------------------------------------------
		{Name: "node bad json", Method: "POST", Path: "/nodes", Body: `{"name":`},
		{Name: "node missing name", Method: "POST", Path: "/nodes", Body: `{}`},
		{Name: "unknown route", Method: "GET", Path: "/diff-nonexistent"},
		{Name: "method not allowed", Method: "DELETE", Path: "/search"},
		{Name: "bad search query", Method: "GET", Path: "/search/node?q=%5Bunclosed"},

		// --- teardown -----------------------------------------------------------
		{Name: "policy group delete", Method: "DELETE", Path: "/policy_groups/diff-group"},
		{Name: "policy revision delete", Method: "DELETE",
			Path: "/policies/diff-policy/revisions/1111111111111111111111111111111111111111111111111111111111111111"},
		{Name: "client delete", Method: "DELETE", Path: "/clients/diff-client"},
		{Name: "data bag item delete", Method: "DELETE", Path: "/data/diff-bag/diff-item"},
		{Name: "data bag delete", Method: "DELETE", Path: "/data/diff-bag"},
		{Name: "environment delete", Method: "DELETE", Path: "/environments/diff-env"},
		{Name: "role delete", Method: "DELETE", Path: "/roles/diff-role"},
		{Name: "node delete", Method: "DELETE", Path: "/nodes/diff-node"},
		{Name: "node delete missing", Method: "DELETE", Path: "/nodes/diff-node"},
	}
}
