//go:build conformance

package conformance

// The actors a Chef Infra Server knows about (clients, users, their keys,
// organizations, and the invitations that join users to them) driven through
// the knife commands that manage them. Each command is checked for its effect
// on the server and, where it changes a credential, for whether the result
// actually authenticates, since a key the server records but cannot verify is
// worse than no key at all.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// actorsUser creates a global user through knife as the superuser and returns
// a knife config acting as that user. When member is set the user is also
// associated with the org, as an ordinary (non-admin) member.
func actorsUser(t *testing.T, h *harness, name string, member bool) string {
	t.Helper()
	pem := filepath.Join(h.dir, name+".pem")
	h.runAs(t, h.superRB, "user", "create", name, "--email", name+"@example.com",
		"--password", "original-password", "--first-name", name, "--last-name", "Member",
		"--file", pem)
	if member {
		h.runAs(t, h.superRB, "org", "user", "add", orgName, name)
	}
	return h.writeConfig(t, name+".rb", name, pem)
}

// actorsEditAs is h.edit under a given identity: the org and user edit
// commands need the superuser or the user being edited.
func actorsEditAs(t *testing.T, h *harness, config, expr string, args ...string) string {
	t.Helper()
	script := filepath.Join(h.dir, fmt.Sprintf("actors-editor-%d.rb", time.Now().UnixNano()))
	write(t, script, "require 'json'\npath = ARGV.last\ndoc = JSON.parse(File.read(path))\n"+
		expr+"\nFile.write(path, JSON.pretty_generate(doc))\n")
	editor := rubyBin(t) + " " + script
	out, err := h.try(config, []string{"EDITOR=" + editor, "VISUAL=" + editor}, args...)
	if err != nil {
		t.Fatalf("knife %s (editing)\n  error: %v\n  output: %s", strings.Join(args, " "), err, out)
	}
	return out
}

// actorsCanAuth asserts that a config's identity authenticates and may read
// the org's node list, which every org member and client may do by default.
func actorsCanAuth(t *testing.T, h *harness, config, why string) {
	t.Helper()
	if out, err := h.tryAs(config, "node", "list"); err != nil {
		t.Fatalf("%s: expected a signed read to succeed: %v\n%s", why, err, out)
	}
}

// actorsRefused asserts that a command under config fails, and that the
// failure is the server refusing the request (401 for a credential it does not
// accept, 403 for an identity it does not permit) rather than anything else.
func actorsRefused(t *testing.T, h *harness, config, why string, args ...string) {
	t.Helper()
	out, err := h.tryAs(config, args...)
	if err == nil {
		t.Fatalf("%s: knife %s succeeded, want a refusal:\n%s", why, strings.Join(args, " "), out)
	}
	lower := strings.ToLower(out)
	if !deniedForAuthorization(out) && !strings.Contains(lower, "401") &&
		!strings.Contains(lower, "unauthorized") && !strings.Contains(lower, "failed to authenticate") {
		t.Errorf("%s: knife %s failed, but not as a refusal:\n%s", why, strings.Join(args, " "), out)
	}
}

// actorsCannotAuth asserts that a config's credential is no longer accepted.
func actorsCannotAuth(t *testing.T, h *harness, config, why string) {
	t.Helper()
	out, err := h.tryAs(config, "node", "list")
	if err == nil {
		t.Fatalf("%s: a signed read still succeeds:\n%s", why, out)
	}
	if lower := strings.ToLower(out); !strings.Contains(lower, "401") && !strings.Contains(lower, "unauthorized") &&
		!strings.Contains(lower, "authenticat") {
		t.Errorf("%s: the read failed, but not as an authentication failure:\n%s", why, out)
	}
}

// actorsJSON decodes the JSON value (object or array) in a command's output.
func actorsJSON(t *testing.T, what, out string) any {
	t.Helper()
	if i := strings.IndexAny(out, "{["); i > 0 {
		out = out[i:]
	}
	var v any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("%s: output is not JSON: %v\n%s", what, err, out)
	}
	return v
}

// actorsOrgUsers returns the usernames associated with an org, read as the
// superuser.
func actorsOrgUsers(t *testing.T, h *harness, org string) []string {
	t.Helper()
	out := h.runAs(t, h.superRB, "raw", h.srv.URL()+"/organizations/"+org+"/users")
	var names []string
	list, ok := actorsJSON(t, "org users", out).([]any)
	if !ok {
		t.Fatalf("org users is not a list:\n%s", out)
	}
	for _, e := range list {
		if u, ok := e.(map[string]any)["user"].(map[string]any); ok {
			names = append(names, fmt.Sprint(u["username"]))
		}
	}
	return names
}

func actorsContains(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}

func actorsReadFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func TestKnifeClientsLifecycle(t *testing.T) {
	t.Parallel()
	h := setup(t)

	// create -f: the key knife writes must authenticate as the new client.
	webPEM := filepath.Join(h.dir, "web1.pem")
	h.run(t, "client", "create", "web1", "-d", "-f", webPEM)
	if !strings.Contains(actorsReadFile(t, webPEM), "PRIVATE KEY") {
		t.Fatalf("client create -f wrote no private key")
	}
	webCfg := h.writeConfig(t, "web1.rb", "web1", webPEM)
	actorsCanAuth(t, h, webCfg, "a newly created client's key")

	if out := h.run(t, "client", "list"); !strings.Contains(out, "web1") {
		t.Fatalf("client list missing web1:\n%s", out)
	}
	show := h.showJSON(t, "client", "show", "web1")
	if got := field(t, show, "name"); got != "web1" {
		t.Errorf("client show name = %v, want web1", got)
	}
	if got := field(t, show, "validator"); got != false {
		t.Errorf("client show validator = %v, want false", got)
	}

	// --validator: the flag is recorded on the client.
	h.run(t, "client", "create", "val1", "--validator", "-d", "-f", filepath.Join(h.dir, "val1.pem"))
	if got := field(t, h.showJSON(t, "client", "show", "val1"), "validator"); got != true {
		t.Errorf("client created --validator has validator = %v, want true", got)
	}

	// edit: the change the editor makes is what the server stores.
	h.edit(t, "doc['validator'] = true", "client", "edit", "web1")
	if got := field(t, h.showJSON(t, "client", "show", "web1"), "validator"); got != true {
		t.Errorf("after client edit, validator = %v, want true", got)
	}

	// reregister: the old key stops working, the new one works.
	rrOld := filepath.Join(h.dir, "rr1.pem")
	h.run(t, "client", "create", "rr1", "-d", "-f", rrOld)
	rrOldCfg := h.writeConfig(t, "rr1-old.rb", "rr1", rrOld)
	actorsCanAuth(t, h, rrOldCfg, "rr1 before reregister")
	rrNew := filepath.Join(h.dir, "rr1-new.pem")
	h.run(t, "client", "reregister", "rr1", "-f", rrNew)
	actorsCannotAuth(t, h, rrOldCfg, "rr1's key replaced by reregister")
	actorsCanAuth(t, h, h.writeConfig(t, "rr1-new.rb", "rr1", rrNew), "rr1's reregistered key")

	// delete: the client is gone, and so is its ability to authenticate.
	h.run(t, "client", "delete", "web1", "--delete-validators", "-y") // web1 became a validator by the edit above
	if out, err := h.tryAs(h.userRB, "client", "show", "web1"); err == nil || !strings.Contains(out, "could not be found") {
		t.Errorf("client show after delete: err=%v, want not found:\n%s", err, out)
	}
	actorsCannotAuth(t, h, webCfg, "a deleted client")

	// bulk delete: only the clients matching the regex go.
	for _, name := range []string{"bulk-a", "bulk-b", "keep1"} {
		h.run(t, "client", "create", name, "-d", "-f", filepath.Join(h.dir, name+".pem"))
	}
	h.run(t, "client", "bulk", "delete", "^bulk-", "-y")
	out := h.run(t, "client", "list")
	if strings.Contains(out, "bulk-a") || strings.Contains(out, "bulk-b") {
		t.Errorf("client bulk delete left a matching client:\n%s", out)
	}
	if !strings.Contains(out, "keep1") || !strings.Contains(out, "rr1") {
		t.Errorf("client bulk delete removed a client the regex does not match:\n%s", out)
	}
}

// A client that is not an admin of anything may not create clients; the
// org admin may. Chef's clients container grants create to admins (and the
// validator), not to the clients group.
func TestKnifeClientsCreateDenied(t *testing.T) {
	t.Parallel()
	h := setup(t)
	pem := h.createClient(t, "plain1")
	cfg := h.writeConfig(t, "plain1.rb", "plain1", pem)
	actorsCanAuth(t, h, cfg, "baseline: plain1 authenticates")
	actorsRefused(t, h, cfg, "an ordinary client creating a client", "client", "create", "rogue", "-d")
	if out := h.run(t, "client", "list"); strings.Contains(out, "rogue") {
		t.Errorf("refused client create still created the client:\n%s", out)
	}
}

func TestKnifeClientsKeys(t *testing.T) {
	t.Parallel()
	h := setup(t)
	defPEM := h.createClient(t, "k1")
	defCfg := h.writeConfig(t, "k1.rb", "k1", defPEM)

	// key create with an expiration date in the future: listed, shown with
	// that date, and usable.
	secondPEM := filepath.Join(h.dir, "k1-second.pem")
	h.run(t, "client", "key", "create", "k1", "-k", "second", "-e", "2099-01-01T00:00:00Z", "-f", secondPEM, "-d")
	secondCfg := h.writeConfig(t, "k1-second.rb", "k1", secondPEM)
	actorsCanAuth(t, h, secondCfg, "an unexpired additional client key")

	if out := h.run(t, "client", "key", "list", "k1"); !strings.Contains(out, "default") || !strings.Contains(out, "second") {
		t.Fatalf("client key list missing default or second:\n%s", out)
	}
	key := h.showJSON(t, "client", "key", "show", "k1", "second")
	if got := field(t, key, "name"); got != "second" {
		t.Errorf("client key show name = %v, want second", got)
	}
	if got := field(t, key, "expiration_date"); got != "2099-01-01T00:00:00Z" {
		t.Errorf("client key show expiration_date = %v, want 2099-01-01T00:00:00Z", got)
	}

	// A key created already expired is refused.
	expiredPEM := filepath.Join(h.dir, "k1-expired.pem")
	h.run(t, "client", "key", "create", "k1", "-k", "expired", "-e", "2001-01-01T00:00:00Z", "-f", expiredPEM, "-d")
	actorsCannotAuth(t, h, h.writeConfig(t, "k1-expired.rb", "k1", expiredPEM), "an expired client key")

	// key edit: expiring a working key makes it stop working; the default key
	// is unaffected.
	h.run(t, "client", "key", "edit", "k1", "second", "-e", "2001-01-01T00:00:00Z", "-d")
	if got := field(t, h.showJSON(t, "client", "key", "show", "k1", "second"), "expiration_date"); got != "2001-01-01T00:00:00Z" {
		t.Errorf("after key edit, expiration_date = %v, want 2001-01-01T00:00:00Z", got)
	}
	actorsCannotAuth(t, h, secondCfg, "a client key expired by key edit")
	actorsCanAuth(t, h, defCfg, "the client's untouched default key")

	// key delete: gone from the list.
	h.run(t, "client", "key", "delete", "k1", "second", "-y")
	if out := h.run(t, "client", "key", "list", "k1"); strings.Contains(out, "second") {
		t.Errorf("client key list still shows a deleted key:\n%s", out)
	}
}

func TestKnifeUsersLifecycle(t *testing.T) {
	t.Parallel()
	h := setup(t)
	bobCfg := actorsUser(t, h, "bob", true)
	actorsCanAuth(t, h, bobCfg, "baseline: bob is an org member")

	// knife user list reads GET /organizations/ORG/users (the org's members),
	// not the global /users collection.
	out := h.run(t, "user", "list")
	if !strings.Contains(out, "alice") || !strings.Contains(out, "bob") {
		t.Fatalf("user list missing alice or bob:\n%s", out)
	}
	// show: a user may read its own record.
	show := decodeObject(t, "user show", h.runAs(t, bobCfg, "user", "show", "bob", "--format", "json"))
	if got := field(t, show, "username"); got != "bob" {
		t.Errorf("user show username = %v, want bob", got)
	}
	if got := field(t, show, "email"); got != "bob@example.com" {
		t.Errorf("user show email = %v, want bob@example.com", got)
	}

	// A non-admin org member may not create users; only the superuser may (it
	// just did, above, creating bob). Nor may it read the global user list.
	actorsRefused(t, h, bobCfg, "an org member creating a user",
		"user", "create", "mallory", "--email", "m@example.com", "--password", "pw-pw-pw-pw",
		"--first-name", "M", "--last-name", "M")
	h.runAs(t, h.superRB, "raw", h.srv.URL()+"/users")
	actorsRefused(t, h, bobCfg, "an org member reading the global user list", "raw", h.srv.URL()+"/users")

	// edit: alice edits her own record and the server keeps the change.
	actorsEditAs(t, h, h.userRB, "doc['display_name'] = 'Alice the Admin'", "user", "edit", userName)
	if got := field(t, decodeObject(t, "user show", h.run(t, "user", "show", userName, "--format", "json")),
		"display_name"); got != "Alice the Admin" {
		t.Errorf("after user edit, display_name = %v, want Alice the Admin", got)
	}

	// password: the new password authenticates and the old one does not.
	authBody := func(name, pw string) string {
		p := filepath.Join(h.dir, fmt.Sprintf("auth-%s-%d.json", name, time.Now().UnixNano()))
		write(t, p, `{"username":"`+name+`","password":"`+pw+`"}`)
		return p
	}
	authURL := h.srv.URL() + "/authenticate_user"
	h.runAs(t, h.superRB, "raw", "-m", "POST", authURL, "-i", authBody("bob", "original-password"))
	h.runAs(t, h.superRB, "user", "password", "bob", "brand-new-password")
	h.runAs(t, h.superRB, "raw", "-m", "POST", authURL, "-i", authBody("bob", "brand-new-password"))
	if out, err := h.tryAs(h.superRB, "raw", "-m", "POST", authURL, "-i", authBody("bob", "original-password")); err == nil {
		t.Errorf("the replaced password still authenticates:\n%s", out)
	}

	// reregister: the old key stops working, the new one works.
	newPEM := filepath.Join(h.dir, "bob-new.pem")
	h.runAs(t, h.superRB, "user", "reregister", "bob", "-f", newPEM)
	actorsCannotAuth(t, h, bobCfg, "bob's key replaced by reregister")
	bobCfg = h.writeConfig(t, "bob-new.rb", "bob", newPEM)
	actorsCanAuth(t, h, bobCfg, "bob's reregistered key")

	// dissociate: alice (an org admin) removes bob from the org, after which
	// he is not a member and may not read the org's objects.
	h.run(t, "user", "dissociate", "bob", "-y")
	if users := actorsOrgUsers(t, h, orgName); actorsContains(users, "bob") || !actorsContains(users, userName) {
		t.Errorf("after dissociate, org users = %v; want alice without bob", users)
	}
	actorsRefused(t, h, bobCfg, "a dissociated user reading org objects", "node", "list")

	// delete: the user is gone, and its key no longer authenticates anywhere.
	h.runAs(t, h.superRB, "user", "delete", "bob", "-y")
	if out, err := h.tryAs(h.superRB, "user", "show", "bob"); err == nil || !strings.Contains(out, "could not be found") {
		t.Errorf("user show after delete: err=%v, want not found:\n%s", err, out)
	}
	actorsRefused(t, h, bobCfg, "a deleted user", "user", "show", "bob")
}

func TestKnifeUsersInvites(t *testing.T) {
	t.Parallel()
	h := setup(t)
	daveCfg := actorsUser(t, h, "dave", false)
	bobCfg := actorsUser(t, h, "bob", true)

	// Before joining, dave cannot read the org.
	actorsRefused(t, h, daveCfg, "a user outside the org", "node", "list")

	// add / list / rescind as the org admin.
	h.run(t, "user", "invite", "add", "dave")
	if out := h.run(t, "user", "invite", "list"); !strings.Contains(out, "dave") {
		t.Fatalf("user invite list missing dave:\n%s", out)
	}
	h.run(t, "user", "invite", "rescind", "dave", "-y")
	if out := h.run(t, "user", "invite", "list"); strings.Contains(out, "dave") {
		t.Fatalf("user invite list still shows a rescinded invite:\n%s", out)
	}

	// An ordinary member may not invite: inviting needs update on the org,
	// which only the admins group has. alice's invite above is the baseline.
	actorsRefused(t, h, bobCfg, "a non-admin member inviting a user", "user", "invite", "add", "dave")

	// Invite again, and dave accepts it himself.
	h.run(t, "user", "invite", "add", "dave")
	pending := actorsJSON(t, "dave's invites",
		h.runAs(t, daveCfg, "raw", h.srv.URL()+"/users/dave/association_requests"))
	list, ok := pending.([]any)
	if !ok || len(list) != 1 {
		t.Fatalf("dave's pending invitations = %v, want one", pending)
	}
	inv := list[0].(map[string]any)
	if inv["orgname"] != orgName {
		t.Errorf("invitation orgname = %v, want %s", inv["orgname"], orgName)
	}
	id := fmt.Sprint(inv["id"])
	accept := filepath.Join(h.dir, "accept.json")
	write(t, accept, `{"response":"accept"}`)
	h.runAs(t, daveCfg, "raw", "-m", "PUT", h.srv.URL()+"/users/dave/association_requests/"+id, "-i", accept)

	if users := actorsOrgUsers(t, h, orgName); !actorsContains(users, "dave") {
		t.Errorf("after accepting, org users = %v; want dave", users)
	}
	if out := h.run(t, "user", "invite", "list"); strings.Contains(out, "dave") {
		t.Errorf("an accepted invite is still pending:\n%s", out)
	}
	actorsCanAuth(t, h, daveCfg, "dave after joining the org")
}

func TestKnifeUsersKeys(t *testing.T) {
	t.Parallel()
	h := setup(t)
	bobCfg := actorsUser(t, h, "bob", true)

	// alice manages her own keys.
	laptopPEM := filepath.Join(h.dir, "alice-laptop.pem")
	h.run(t, "user", "key", "create", userName, "-k", "laptop", "-e", "2099-01-01T00:00:00Z", "-f", laptopPEM, "-d")
	laptopCfg := h.writeConfig(t, "alice-laptop.rb", userName, laptopPEM)
	actorsCanAuth(t, h, laptopCfg, "alice's additional key")

	if out := h.run(t, "user", "key", "list", userName); !strings.Contains(out, "default") || !strings.Contains(out, "laptop") {
		t.Fatalf("user key list missing default or laptop:\n%s", out)
	}
	key := h.showJSON(t, "user", "key", "show", userName, "laptop")
	if got := field(t, key, "expiration_date"); got != "2099-01-01T00:00:00Z" {
		t.Errorf("user key show expiration_date = %v, want 2099-01-01T00:00:00Z", got)
	}
	if got := field(t, key, "public_key"); !strings.Contains(fmt.Sprint(got), "PUBLIC KEY") {
		t.Errorf("user key show public_key = %v, want a PEM public key", got)
	}

	// Another user may not add a key to alice's account: that would be an
	// account takeover. alice's own key create above is the baseline.
	actorsRefused(t, h, bobCfg, "bob adding a key to alice",
		"user", "key", "create", userName, "-k", "stolen", "-d")

	// edit: rename and expire. The expired key is refused.
	h.run(t, "user", "key", "edit", userName, "laptop", "-k", "old-laptop", "-e", "2001-01-01T00:00:00Z", "-d")
	edited := h.showJSON(t, "user", "key", "show", userName, "old-laptop")
	if got := field(t, edited, "expiration_date"); got != "2001-01-01T00:00:00Z" {
		t.Errorf("after user key edit, expiration_date = %v, want 2001-01-01T00:00:00Z", got)
	}
	actorsCannotAuth(t, h, laptopCfg, "alice's key expired by key edit")
	actorsCanAuth(t, h, h.userRB, "alice's untouched default key")

	h.run(t, "user", "key", "delete", userName, "old-laptop", "-y")
	if out := h.run(t, "user", "key", "list", userName); strings.Contains(out, "laptop") {
		t.Errorf("user key list still shows a deleted key:\n%s", out)
	}
}

func TestKnifeOrgs(t *testing.T) {
	t.Parallel()
	h := setup(t)

	if out := h.runAs(t, h.superRB, "org", "list"); !strings.Contains(out, orgName) {
		t.Fatalf("org list missing %s:\n%s", orgName, out)
	}
	show := decodeObject(t, "org show", h.runAs(t, h.superRB, "org", "show", orgName, "--format", "json"))
	if got := field(t, show, "name"); got != orgName {
		t.Errorf("org show name = %v, want %s", got, orgName)
	}

	// Provisioning an org is a server-level operation: an org admin who is not
	// the superuser is refused. The superuser's create below is the baseline.
	actorsRefused(t, h, h.userRB, "an org admin creating an org", "org", "create", "rogue", "Rogue Inc")

	validator := filepath.Join(h.dir, "beta-validator.pem")
	h.runAs(t, h.superRB, "org", "create", "beta", "Beta Inc", "-f", validator)
	if out := h.runAs(t, h.superRB, "org", "list"); !strings.Contains(out, "beta") || strings.Contains(out, "rogue") {
		t.Fatalf("org list after create = %s; want beta and not rogue", out)
	}
	if got := field(t, decodeObject(t, "org show", h.runAs(t, h.superRB, "org", "show", "beta", "--format", "json")),
		"full_name"); got != "Beta Inc" {
		t.Errorf("new org full_name = %v, want Beta Inc", got)
	}
	// The validator key org create writes registers clients in the new org,
	// which is what it exists for.
	betaURL := h.srv.URL() + "/organizations/beta"
	valCfg := filepath.Join(h.dir, "beta-validator.rb")
	write(t, valCfg, "node_name 'beta-validator'\nclient_key '"+validator+"'\nchef_server_url '"+betaURL+"'\n")
	h.runAs(t, valCfg, "client", "create", "beta-node", "-d", "-f", filepath.Join(h.dir, "beta-node.pem"))

	actorsEditAs(t, h, h.superRB, "doc['full_name'] = 'Beta Two'", "org", "edit", "beta")
	if got := field(t, decodeObject(t, "org show", h.runAs(t, h.superRB, "org", "show", "beta", "--format", "json")),
		"full_name"); got != "Beta Two" {
		t.Errorf("after org edit, full_name = %v, want Beta Two", got)
	}

	// org user remove: alice, added to beta, can read it; once removed she
	// cannot.
	aliceBeta := filepath.Join(h.dir, "alice-beta.rb")
	write(t, aliceBeta, "node_name '"+userName+"'\nclient_key '"+filepath.Join(h.dir, userName+".pem")+
		"'\nchef_server_url '"+betaURL+"'\n")
	h.runAs(t, h.superRB, "org", "user", "add", "beta", userName)
	if out, err := h.tryAs(aliceBeta, "client", "list"); err != nil || !strings.Contains(out, "beta-node") {
		t.Fatalf("baseline: alice as a beta member should list its clients: %v\n%s", err, out)
	}
	h.runAs(t, h.superRB, "org", "user", "remove", "beta", userName, "-y")
	if users := actorsOrgUsers(t, h, "beta"); actorsContains(users, userName) {
		t.Errorf("after org user remove, beta users = %v; want no alice", users)
	}
	actorsRefused(t, h, aliceBeta, "a user removed from the org", "client", "list")

	h.runAs(t, h.superRB, "org", "delete", "beta", "-y")
	if out := h.runAs(t, h.superRB, "org", "list"); strings.Contains(out, "beta") {
		t.Errorf("org list still shows a deleted org:\n%s", out)
	}
	if out, err := h.tryAs(h.superRB, "org", "show", "beta"); err == nil || !strings.Contains(out, "Cannot find org beta") {
		t.Errorf("org show after delete: err=%v, want not found:\n%s", err, out)
	}
}
