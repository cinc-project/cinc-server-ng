package api

import (
	"errors"
	"fmt"

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

// Apply creates the user, unless it already exists, then makes it a member of
// server-admins and a member and admin of each of orgs. An existing user is
// left exactly as it is (its password and profile may have been changed since
// it was first created); only the memberships are ensured, each write being
// idempotent. It runs in one transaction and reports whether it created the
// user. It is meant for startup, before the API serves requests, so it does not
// take API.membership.
func (b BootstrapUser) Apply(st *store.Store, orgs []string) (created bool, err error) {
	if err := b.Validate(); err != nil {
		return false, err
	}
	err = st.Tx(func(tx *store.Store) error {
		global := tx.Global()
		_, exists, err := global.Get("users", b.Name)
		if err != nil {
			return err
		}
		if !exists {
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
			created = true
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
	return created, err
}
