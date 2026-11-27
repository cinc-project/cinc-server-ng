package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cinc-project/cinc-server-ng/internal/auth"
	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// BootstrapUser describes the first human administrator a server creates at
// startup, so a fresh server has someone who can log in to a web console
// (which authenticates users by password, then signs as them with the webui
// key). A fresh server otherwise holds only the key-based superuser.
type BootstrapUser struct {
	Name     string
	Password string
	// Email is the user's address. erchef requires one on a locally
	// authenticated user, on create and on every later update; when empty it
	// defaults to DefaultBootstrapEmail(Name).
	Email string
}

// DefaultBootstrapEmail is the placeholder address a bootstrap user gets when
// none is configured. It satisfies erchef's email rule, so the user can later
// be updated through PUT /users/{name} like any other.
func DefaultBootstrapEmail(name string) string {
	return name + "@localhost.localdomain"
}

func (b BootstrapUser) email() string {
	if b.Email != "" {
		return b.Email
	}
	return DefaultBootstrapEmail(b.Name)
}

// body is the user as a POST /users body would carry it.
func (b BootstrapUser) body() map[string]any {
	return map[string]any{
		"name":         b.Name,
		"display_name": b.Name,
		"email":        b.email(),
		"password":     b.Password,
	}
}

// Validate checks the user the way POST /users checks a new one.
func (b BootstrapUser) Validate() error {
	if b.Name == "" {
		return errors.New("bootstrap user: name missing")
	}
	if b.Password == "" {
		return errors.New("bootstrap user: password missing")
	}
	if msg := validateUser(b.body(), nil, true); msg != "" {
		return fmt.Errorf("bootstrap user %q: %s", b.Name, msg)
	}
	return nil
}

// bootstrapUsersColl is a private global collection recording, under the
// bootstrap user's name, which user record the bootstrap created or adopted:
// its creation time, which the server sets and no request can.
const bootstrapUsersColl = "bootstrap_users"

// bootstrapMark is what bootstrapUsersColl holds for a name.
type bootstrapMark struct {
	CreatedAt time.Time `json:"created_at"`
}

// BootstrapResult reports what Apply did.
type BootstrapResult struct {
	// Created is set when Apply created the user.
	Created bool
	// Refused, when set, says why a user of the name was left without the
	// bootstrap memberships: it is not the user the bootstrap created.
	Refused string
}

// Apply creates the user, unless it already exists, then makes it a member of
// server-admins and a member and admin of each of orgs. An existing user is
// left exactly as it is (its password and profile may have been changed since
// it was first created); only the memberships are ensured, each write being
// idempotent. It runs in one transaction. It is meant for startup, before the
// API serves requests, so it does not take API.membership.
//
// The memberships go only to the user the bootstrap created. Once that user is
// deleted or renamed, anyone may take the name (a user can rename itself), and
// must not become a server admin at the next restart for it. So creating the
// user records its creation time (bootstrapUsersColl), and an existing user of
// the name is granted only if its record is that one; otherwise Apply grants
// nothing and says why in Refused. Startup does not fail: the server is still
// usable through the superuser, which can sort the name out.
//
// A store written before the record existed has none. There an existing user
// is adopted, and recorded, if it is already a server admin, as the earlier
// bootstrap made it: granting it the org memberships gives it nothing a server
// admin could not take. A user who is not a server admin is refused, unless
// trustExisting says the store held nothing before this startup, so the user
// came from the operator's own state or repo load.
func (b BootstrapUser) Apply(st *store.Store, orgs []string, trustExisting bool) (res BootstrapResult, err error) {
	if err := b.Validate(); err != nil {
		return res, err
	}
	err = st.Tx(func(tx *store.Store) error {
		res = BootstrapResult{}
		global := tx.Global()
		_, exists, err := global.Get("users", b.Name)
		if err != nil {
			return err
		}
		if exists {
			ok, why, err := b.isBootstrapped(global, trustExisting)
			if err != nil {
				return err
			}
			if !ok {
				res.Refused = why
				return nil
			}
		} else {
			obj := b.body()
			lowerEmail(obj)
			// A user with no key cannot be impersonated through the webui key
			// either (resolving the requestor needs a usable key, as erchef's
			// keys_by_name join does), so the user gets one, as POST /users
			// with create_key would give it. Its private half is discarded:
			// the user logs in by password, and keys are managed through
			// /users/{name}/keys like any other user's.
			key, err := auth.GenerateKey()
			if err != nil {
				return err
			}
			pub, err := auth.EncodePublicKeyPEM(&key.PublicKey)
			if err != nil {
				return err
			}
			obj["public_key"] = string(pub)
			// The same out-of-band, hashed storage POST /users uses.
			if _, err := StashPassword(global, b.Name, obj); err != nil {
				return err
			}
			if err := global.Create("users", b.Name, mustEncode(obj)); err != nil {
				return err
			}
			if err := b.mark(global); err != nil {
				return err
			}
			res.Created = true
		}
		if err := global.Put(serverAdminsColl, b.Name, []byte(`{}`)); err != nil {
			return err
		}
		for _, name := range orgs {
			org, ok, err := tx.Org(name)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("bootstrap user: organization %q not found", name)
			}
			if err := joinOrgAsAdmin(org, b.Name); err != nil {
				return err
			}
		}
		return nil
	})
	return res, err
}

// mark records the user record now under the name as the bootstrap user.
func (b BootstrapUser) mark(global *store.Org) error {
	md, ok, err := global.Meta("users", b.Name)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("bootstrap user %q disappeared", b.Name)
	}
	return global.Put(bootstrapUsersColl, b.Name, mustEncode(bootstrapMark{CreatedAt: md.CreatedAt}))
}

// isBootstrapped reports whether the existing user of the name is the one the
// bootstrap created (see Apply), adopting it on a store with no record, and if
// not, why.
func (b BootstrapUser) isBootstrapped(global *store.Org, trustExisting bool) (bool, string, error) {
	raw, marked, err := global.Get(bootstrapUsersColl, b.Name)
	if err != nil {
		return false, "", err
	}
	if marked {
		var mark bootstrapMark
		if err := json.Unmarshal(raw, &mark); err != nil {
			return false, "", fmt.Errorf("bootstrap user %q: stored record: %w", b.Name, err)
		}
		md, _, err := global.Meta("users", b.Name)
		if err != nil {
			return false, "", err
		}
		if md.CreatedAt.Equal(mark.CreatedAt) {
			return true, "", nil
		}
		return false, fmt.Sprintf("bootstrap user %q was not granted server-admin or org admin: the user of that name is not the one the bootstrap created (that one was deleted or renamed since)", b.Name), nil
	}
	if !trustExisting {
		_, admin, err := global.Get(serverAdminsColl, b.Name)
		if err != nil {
			return false, "", err
		}
		if !admin {
			return false, fmt.Sprintf("bootstrap user %q was not granted server-admin or org admin: a user of that name exists that the bootstrap did not create", b.Name), nil
		}
	}
	return true, "", b.mark(global)
}
