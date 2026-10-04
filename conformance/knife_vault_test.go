//go:build conformance

package conformance

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// chef-vault is how most Chef shops keep secrets: a data bag item encrypted
// with a random shared secret, plus an "<item>_keys" item holding that secret
// encrypted once for each admin's and client's public key. It works against a
// server only if the server serves search (to find the nodes a vault is for),
// public keys (/clients/X/keys/default and /users/X/keys/default) to whoever
// encrypts, and the data bag items to the clients that decrypt. Every command
// here runs in -M client mode, which is what a node and an operator use against
// a server; the default ("solo") mode reads a local directory instead.

// vaultNode registers a client named name, has it create its own node carrying
// vault_group=group (as a bootstrap would), and returns its knife config.
func vaultNode(t *testing.T, h *harness, name, group string) string {
	t.Helper()
	key := h.createClient(t, name)
	cfg := h.writeConfig(t, name+".rb", name, key)
	path := filepath.Join(h.dir, name+"-node.json")
	write(t, path, `{"name":"`+name+`","chef_environment":"_default","json_class":"Chef::Node",`+
		`"chef_type":"node","normal":{"vault_group":"`+group+`"}}`)
	h.runAs(t, cfg, "node", "from", "file", path)
	return cfg
}

// vaultShow decrypts bag/item under cfg and returns the plaintext values.
func vaultShow(t *testing.T, h *harness, cfg, bag, item string) map[string]any {
	t.Helper()
	out := h.runAs(t, cfg, "vault", "show", bag, item, "-M", "client", "-F", "json")
	return decodeObject(t, "vault show "+bag+" "+item, out)
}

// vaultDenied asserts that cfg cannot decrypt bag/item, and for the reason a
// vault refuses: the secret is not encrypted for it. Any other failure (a 403
// reading the item, a broken config) would make the denial prove nothing.
func vaultDenied(t *testing.T, h *harness, cfg, bag, item, why string) {
	t.Helper()
	out, err := h.tryAs(cfg, "vault", "show", bag, item, "-M", "client", "-F", "json")
	if err == nil {
		t.Fatalf("%s: decrypted %s/%s anyway:\n%s", why, bag, item, out)
	}
	if !strings.Contains(out, "not encrypted with your public key") {
		t.Fatalf("%s: refused for the wrong reason (want: not encrypted with your public key):\n%s", why, out)
	}
}

// vaultKeys reads the keys item raw and returns its admins and clients lists
// and the whole document.
func vaultKeys(t *testing.T, h *harness, bag, item string) (admins, clients []string, doc map[string]any) {
	t.Helper()
	doc = h.raw(t, "/data/"+bag+"/"+item+"_keys")
	return vaultStrings(t, doc["admins"]), vaultStrings(t, doc["clients"]), doc
}

func vaultStrings(t *testing.T, v any) []string {
	t.Helper()
	list, ok := v.([]any)
	if !ok {
		t.Fatalf("expected a JSON array, got %T %v", v, v)
	}
	var out []string
	for _, e := range list {
		out = append(out, e.(string))
	}
	slices.Sort(out)
	return out
}

// vaultAssertEncrypted asserts that the stored item holds field encrypted, and
// that the plaintext appears nowhere in what the server stores.
func vaultAssertEncrypted(t *testing.T, h *harness, bag, item, field, plaintext string) {
	t.Helper()
	out := h.run(t, "raw", "/data/"+bag+"/"+item)
	if strings.Contains(out, plaintext) {
		t.Fatalf("stored vault item %s/%s contains the plaintext %q:\n%s", bag, item, plaintext, out)
	}
	doc := decodeObject(t, "raw vault item", out)
	enc, ok := doc[field].(map[string]any)
	if !ok {
		t.Fatalf("stored %s/%s field %q is not an encrypted envelope: %v", bag, item, field, doc[field])
	}
	if s, _ := enc["encrypted_data"].(string); s == "" {
		t.Fatalf("stored %s/%s field %q has no encrypted_data: %v", bag, item, field, enc)
	}
}

func TestKnifeVaultCreateShowAndAccess(t *testing.T) {
	t.Parallel()
	h := setup(t)

	db1 := vaultNode(t, h, "db1", "db")
	web1 := vaultNode(t, h, "web1", "web")

	h.run(t, "vault", "create", "secrets", "dbpass", `{"password":"hunter2"}`,
		"-S", "vault_group:db", "-A", userName, "-M", "client")

	// The server stores ciphertext, and the keys item names who may decrypt.
	vaultAssertEncrypted(t, h, "secrets", "dbpass", "password", "hunter2")
	admins, clients, keys := vaultKeys(t, h, "secrets", "dbpass")
	if !slices.Equal(admins, []string{userName}) {
		t.Errorf("vault admins = %v, want [%s]", admins, userName)
	}
	if !slices.Equal(clients, []string{"db1"}) {
		t.Errorf("vault clients = %v, want [db1] (the search should match db1 only)", clients)
	}
	for _, actor := range []string{userName, "db1"} {
		if s, _ := keys[actor].(string); s == "" {
			t.Errorf("keys item has no encrypted secret for %s: %v", actor, keys)
		}
	}
	if q := field(t, keys, "search_query"); q != "vault_group:db" {
		t.Errorf("keys item search_query = %v, want vault_group:db", q)
	}

	// The admin who created it decrypts; so does the client the search
	// matched, with its own key; the client it did not match cannot.
	if got := field(t, vaultShow(t, h, h.knifeRB, "secrets", "dbpass"), "password"); got != "hunter2" {
		t.Errorf("admin decrypted password = %v, want hunter2", got)
	}
	if got := field(t, vaultShow(t, h, db1, "secrets", "dbpass"), "password"); got != "hunter2" {
		t.Errorf("db1 decrypted password = %v, want hunter2", got)
	}
	vaultDenied(t, h, web1, "secrets", "dbpass", "web1 is not a client of the vault")

	// show -p prints the vault's metadata alongside the values.
	out := h.run(t, "vault", "show", "secrets", "dbpass", "-p", "all", "-M", "client")
	for _, want := range []string{"db1", userName, "vault_group:db"} {
		if !strings.Contains(out, want) {
			t.Errorf("vault show -p all lacks %q:\n%s", want, out)
		}
	}
	// show VAULT without an item lists the vault's items, not the keys items.
	out = h.run(t, "vault", "show", "secrets", "-M", "client")
	if !strings.Contains(out, "dbpass") || strings.Contains(out, "dbpass_keys") {
		t.Errorf("vault show secrets = %q, want dbpass listed without dbpass_keys", out)
	}

	// isvault and itemtype tell a vault from a plain data bag item.
	h.run(t, "data", "bag", "create", "plain")
	write(t, filepath.Join(h.dir, "plainitem.json"), `{"id":"plainitem","x":"y"}`)
	h.run(t, "data", "bag", "from", "file", "plain", filepath.Join(h.dir, "plainitem.json"))
	if _, err := h.tryAs(h.knifeRB, "vault", "isvault", "secrets", "dbpass", "-M", "client"); err != nil {
		t.Errorf("isvault secrets/dbpass should succeed: %v", err)
	}
	if out, err := h.tryAs(h.knifeRB, "vault", "isvault", "plain", "plainitem", "-M", "client"); err == nil {
		t.Errorf("isvault plain/plainitem should fail, got success:\n%s", out)
	}
	if out := h.run(t, "vault", "itemtype", "secrets", "dbpass", "-M", "client"); !strings.Contains(out, "vault") {
		t.Errorf("itemtype secrets/dbpass = %q, want vault", out)
	}
	if out := h.run(t, "vault", "itemtype", "plain", "plainitem", "-M", "client"); !strings.Contains(out, "normal") {
		t.Errorf("itemtype plain/plainitem = %q, want normal", out)
	}

	// list names the vault bag and not the plain one.
	out = h.run(t, "vault", "list", "-M", "client")
	if !strings.Contains(out, "secrets") || strings.Contains(out, "plain") {
		t.Errorf("vault list = %q, want secrets and not plain", out)
	}
}

func TestKnifeVaultUpdateAndRemove(t *testing.T) {
	t.Parallel()
	h := setup(t)

	db1 := vaultNode(t, h, "db1", "db")
	app1 := vaultNode(t, h, "app1", "app")

	h.run(t, "vault", "create", "secrets", "api", `{"token":"t0ken"}`,
		"-C", "db1", "-A", userName, "-M", "client")
	vaultDenied(t, h, app1, "secrets", "api", "app1 was not granted the vault")

	// update adds values and clients; both are visible to the new client.
	h.run(t, "vault", "update", "secrets", "api", `{"extra":"more"}`, "-C", "app1", "-M", "client")
	if _, clients, _ := vaultKeys(t, h, "secrets", "api"); !slices.Equal(clients, []string{"app1", "db1"}) {
		t.Errorf("clients after update = %v, want [app1 db1]", clients)
	}
	vaultAssertEncrypted(t, h, "secrets", "api", "extra", "more")
	got := vaultShow(t, h, app1, "secrets", "api")
	if got["token"] != "t0ken" || got["extra"] != "more" {
		t.Errorf("app1 decrypted %v, want token=t0ken extra=more", got)
	}

	// remove VALUES drops a value.
	h.run(t, "vault", "remove", "secrets", "api", `["extra"]`, "-M", "client")
	got = vaultShow(t, h, db1, "secrets", "api")
	if _, ok := got["extra"]; ok || got["token"] != "t0ken" {
		t.Errorf("after removing extra, db1 decrypted %v, want token only", got)
	}

	// remove -C revokes a client: it leaves the keys item and loses access.
	h.run(t, "vault", "remove", "secrets", "api", "-C", "app1", "-M", "client")
	_, clients, keys := vaultKeys(t, h, "secrets", "api")
	if !slices.Equal(clients, []string{"db1"}) {
		t.Errorf("clients after remove -C app1 = %v, want [db1]", clients)
	}
	if _, ok := keys["app1"]; ok {
		t.Errorf("keys item still holds an encrypted secret for app1: %v", keys)
	}
	vaultDenied(t, h, app1, "secrets", "api", "app1 was removed from the vault")
	if got := field(t, vaultShow(t, h, db1, "secrets", "api"), "token"); got != "t0ken" {
		t.Errorf("db1 decrypted token = %v after app1's removal, want t0ken", got)
	}

	// An admin is added with update -A and removed with remove -A. bob's key
	// is read from /users/bob/keys/default.
	bobPEM := filepath.Join(h.dir, "bob.pem")
	h.runAs(t, h.superRB, "user", "create", "bob", "--email", "bob@example.com",
		"--password", "correct-horse-battery", "--first-name", "Bob", "--last-name", "B",
		"--file", bobPEM)
	h.runAs(t, h.superRB, "org", "user", "add", orgName, "bob")
	bob := h.writeConfig(t, "bob.rb", "bob", bobPEM)
	vaultDenied(t, h, bob, "secrets", "api", "bob is not an admin of the vault")
	h.run(t, "vault", "update", "secrets", "api", "-A", "bob", "-M", "client")
	if admins, _, _ := vaultKeys(t, h, "secrets", "api"); !slices.Equal(admins, []string{userName, "bob"}) {
		t.Errorf("admins after update -A bob = %v, want [alice bob]", admins)
	}
	if got := field(t, vaultShow(t, h, bob, "secrets", "api"), "token"); got != "t0ken" {
		t.Errorf("bob decrypted token = %v, want t0ken", got)
	}
	h.run(t, "vault", "remove", "secrets", "api", "-A", "bob", "-M", "client")
	if admins, _, _ := vaultKeys(t, h, "secrets", "api"); !slices.Equal(admins, []string{userName}) {
		t.Errorf("admins after remove -A bob = %v, want [alice]", admins)
	}
	vaultDenied(t, h, bob, "secrets", "api", "bob was removed from the vault")
}

func TestKnifeVaultEditDownloadDelete(t *testing.T) {
	t.Parallel()
	h := setup(t)

	db1 := vaultNode(t, h, "db1", "db")

	// edit opens the decrypted values in $EDITOR and re-encrypts the result.
	h.run(t, "vault", "create", "secrets", "conf", `{"password":"old"}`,
		"-C", "db1", "-A", userName, "-M", "client")
	h.edit(t, `doc["password"] = "new"; doc["added"] = "yes"`,
		"vault", "edit", "secrets", "conf", "-M", "client")
	vaultAssertEncrypted(t, h, "secrets", "conf", "password", "new")
	got := vaultShow(t, h, db1, "secrets", "conf")
	if got["password"] != "new" || got["added"] != "yes" {
		t.Errorf("after edit db1 decrypted %v, want password=new added=yes", got)
	}

	// A file stored with --file comes back byte for byte from download.
	content := "-----BEGIN CERT-----\nnot really a cert\n-----END CERT-----\n"
	src := filepath.Join(h.dir, "server.crt")
	write(t, src, content)
	h.run(t, "vault", "create", "certs", "web", "--file", src,
		"-C", "db1", "-A", userName, "-M", "client")
	vaultAssertEncrypted(t, h, "certs", "web", "file-content", "not really a cert")
	dst := filepath.Join(h.dir, "downloaded.crt")
	h.runAs(t, db1, "vault", "download", "certs", "web", dst, "-M", "client")
	if b, err := os.ReadFile(dst); err != nil || string(b) != content {
		t.Errorf("downloaded file = %q (%v), want %q", b, err, content)
	}

	// delete removes the item and its keys item.
	h.run(t, "vault", "delete", "secrets", "conf", "-M", "client", "-y")
	for _, item := range []string{"conf", "conf_keys"} {
		if out, err := h.tryAs(h.knifeRB, "raw", "/data/secrets/"+item); err == nil {
			t.Errorf("secrets/%s survives vault delete:\n%s", item, out)
		}
	}
}

func TestKnifeVaultRefreshAndRotate(t *testing.T) {
	t.Parallel()
	h := setup(t)

	db1 := vaultNode(t, h, "db1", "db")
	h.run(t, "vault", "create", "secrets", "dbpass", `{"password":"hunter2"}`,
		"-S", "vault_group:db", "-A", userName, "-M", "client")

	// A node that matches the search after the vault was made is not a client
	// until the vault is refreshed.
	db2 := vaultNode(t, h, "db2", "db")
	vaultDenied(t, h, db2, "secrets", "dbpass", "db2 registered after the vault was created")
	h.run(t, "vault", "refresh", "secrets", "dbpass", "-M", "client")
	if _, clients, _ := vaultKeys(t, h, "secrets", "dbpass"); !slices.Equal(clients, []string{"db1", "db2"}) {
		t.Errorf("clients after refresh = %v, want [db1 db2]", clients)
	}
	if got := field(t, vaultShow(t, h, db2, "secrets", "dbpass"), "password"); got != "hunter2" {
		t.Errorf("db2 decrypted password = %v after refresh, want hunter2", got)
	}

	// rotate keys re-encrypts under a new shared secret: every actor's entry
	// in the keys item and the ciphertext change, and access still works.
	_, _, before := vaultKeys(t, h, "secrets", "dbpass")
	itemBefore := h.raw(t, "/data/secrets/dbpass")
	h.run(t, "vault", "rotate", "keys", "secrets", "dbpass", "-M", "client")
	_, _, after := vaultKeys(t, h, "secrets", "dbpass")
	for _, actor := range []string{userName, "db1", "db2"} {
		if before[actor] == after[actor] {
			t.Errorf("rotate keys left %s's encrypted secret unchanged", actor)
		}
	}
	itemAfter := h.raw(t, "/data/secrets/dbpass")
	if field(t, itemBefore, "password", "encrypted_data") == field(t, itemAfter, "password", "encrypted_data") {
		t.Errorf("rotate keys left the ciphertext unchanged")
	}
	for _, cfg := range []string{h.knifeRB, db1, db2} {
		if got := field(t, vaultShow(t, h, cfg, "secrets", "dbpass"), "password"); got != "hunter2" {
			t.Errorf("after rotate keys, decrypted password = %v, want hunter2", got)
		}
	}

	// rotate all keys does the same for every vault on the server.
	h.run(t, "vault", "create", "other", "x", `{"v":"1"}`, "-C", "db1", "-A", userName, "-M", "client")
	_, _, secretsBefore := vaultKeys(t, h, "secrets", "dbpass")
	_, _, otherBefore := vaultKeys(t, h, "other", "x")
	h.run(t, "vault", "rotate", "all", "keys", "-M", "client")
	_, _, secretsAfter := vaultKeys(t, h, "secrets", "dbpass")
	_, _, otherAfter := vaultKeys(t, h, "other", "x")
	if secretsBefore["db1"] == secretsAfter["db1"] || otherBefore["db1"] == otherAfter["db1"] {
		t.Errorf("rotate all keys left an encrypted secret unchanged")
	}
	if got := field(t, vaultShow(t, h, db1, "other", "x"), "v"); got != "1" {
		t.Errorf("after rotate all keys, db1 decrypted other/x v = %v, want 1", got)
	}
	if got := field(t, vaultShow(t, h, db2, "secrets", "dbpass"), "password"); got != "hunter2" {
		t.Errorf("after rotate all keys, db2 decrypted password = %v, want hunter2", got)
	}
}
