package api

import (
	"encoding/json"
	"net/http"

	"github.com/cinc-project/cinc-server-ng/internal/auth"
	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// Keys shared between same-named actors.
//
// A signed request names its signer only by name, and a user and an org
// client may share one, so authentication tries every actor of the name and
// takes the first whose key verifies, the user first (see server/auth.go
// resolveAuth). The order settles which of the two a key shared between them
// authenticates, and either answer hands one actor's requests to the other: a
// client registered with a user's public key would sign as the user were the
// client tried first, and a user holding a client's public key does sign as
// that client's requests now, since the user is tried first. Public keys are
// readable by anyone (principals, the keys API), and a user may rename itself
// onto any client's name.
//
// So, unlike erchef, which keeps no such rule, a key may not be given to an
// actor when an actor of the same name of the other kind already holds it:
// not by an actor create or update, the keys API, or a rename. Each actor's
// keys stay its own, and the order of the candidates never decides anything.
// Clients of one name in different orgs are never candidates for the same
// request, so they may share a key.

// sameNameKeyMessage is the 409 for a key an actor of the same name holds.
func sameNameKeyMessage(name string) string {
	return "Public key already held by another user or client named '" + name + "'"
}

// actorKeyPEMs returns every public key an actor holds, expired or not: its
// record's public_key and each row in its keys collection.
func actorKeyPEMs(org *store.Org, segment, name string) ([]string, error) {
	var out []string
	pub, err := storedPublicKey(org, segment, name)
	if err != nil {
		return nil, err
	}
	if pub != "" {
		out = append(out, pub)
	}
	err = org.Range(keysColl(segment, name), func(_ string, raw []byte) bool {
		var k storedKey
		if json.Unmarshal(raw, &k) == nil && k.PublicKey != "" {
			out = append(out, k.PublicKey)
		}
		return true
	})
	return out, err
}

// sameNameHoldsKey reports whether an actor of the other kind answering to
// name holds one of pems: the global user, for a client (segment "clients"),
// or the client of that name in any org, for a user.
func (a *API) sameNameHoldsKey(segment, name string, pems []string) (bool, error) {
	var want []string
	for _, p := range pems {
		if p != "" {
			want = append(want, p)
		}
	}
	if len(want) == 0 {
		return false, nil
	}
	holds := func(org *store.Org, seg string) (bool, error) {
		held, err := actorKeyPEMs(org, seg, name)
		if err != nil {
			return false, err
		}
		for _, h := range held {
			for _, p := range want {
				if sameKey(h, p) {
					return true, nil
				}
			}
		}
		return false, nil
	}
	if segment == "clients" {
		return holds(a.store.Global(), "users")
	}
	orgs, err := a.store.ListOrgs()
	if err != nil {
		return false, err
	}
	for _, on := range orgs {
		org, ok, err := a.store.Org(on)
		if err != nil {
			return false, err
		}
		if !ok {
			continue
		}
		if found, err := holds(org, "clients"); err != nil || found {
			return found, err
		}
	}
	return false, nil
}

// sameKey reports whether two PEM public keys are the same key, whatever
// their encoding (PKCS#1 or SPKI, line wrapping).
func sameKey(x, y string) bool {
	if x == y {
		return true
	}
	kx, err := auth.ParsePublicKey([]byte(x))
	if err != nil {
		return false
	}
	ky, err := auth.ParsePublicKey([]byte(y))
	if err != nil {
		return false
	}
	return kx.Equal(ky)
}

// refuseSameNameKey writes the 409 and returns true when an actor of the
// other kind answering to name holds one of pems.
func (a *API) refuseSameNameKey(w http.ResponseWriter, segment, name string, pems ...string) bool {
	held, err := a.sameNameHoldsKey(segment, name, pems)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return true
	}
	if held {
		writeError(w, http.StatusConflict, sameNameKeyMessage(name))
		return true
	}
	return false
}
