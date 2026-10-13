package api

import (
	"bytes"
	"slices"

	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// erchef creates every organization by running one declarative policy
// (oc_chef_authz_org_creator:DEFAULT_EC_EXPANDED_ORG) that writes an ACL on
// each default container, each default group and the organization itself. The
// tables below are that policy, so an org here reports and enforces what an
// erchef org does:
//
//	admins     all five permissions on every container, on the admins,
//	           clients and users groups, and on the organization;
//	           read and update on public_key_read_access
//	users      create/read/update/delete on cookbooks, data, nodes, roles,
//	           environments, policies, policy_groups, cookbook_artifacts;
//	           read and delete on clients; read on groups, containers and the
//	           organization; create on sandboxes
//	clients    read and create on nodes; read on policies, policy_groups,
//	           cookbook_artifacts, data, cookbooks, environments, roles
//	billing-admins  read and update on the billing-admins group, and nothing
//	           else (not even the admins group holds anything on it)
//
// erchef also names the creating superuser (pivotal) as an actor on every one
// of these ACLs. Here the superuser bypasses ACLs, so it is not recorded.
//
// They are applied as the fallback for an object with no stored ACL (see
// fallbackACL), so they hold for orgs whatever version created them, with no
// per-org rows to write.

// containerUserPerms and containerClientPerms are the users and clients
// groups' grants on each default container; admins hold every permission on
// all of them.
var (
	containerUserPerms = map[string][]string{
		"cookbooks":          {"create", "read", "update", "delete"},
		"data":               {"create", "read", "update", "delete"},
		"nodes":              {"create", "read", "update", "delete"},
		"roles":              {"create", "read", "update", "delete"},
		"environments":       {"create", "read", "update", "delete"},
		"policies":           {"create", "read", "update", "delete"},
		"policy_groups":      {"create", "read", "update", "delete"},
		"cookbook_artifacts": {"create", "read", "update", "delete"},
		"clients":            {"read", "delete"},
		"groups":             {"read"},
		"containers":         {"read"},
		"sandboxes":          {"create"},
	}
	containerClientPerms = map[string][]string{
		"nodes":              {"create", "read"},
		"policies":           {"read"},
		"policy_groups":      {"read"},
		"cookbook_artifacts": {"read"},
		"data":               {"read"},
		"cookbooks":          {"read"},
		"environments":       {"read"},
		"roles":              {"read"},
	}
)

// policyACL builds an ACL from group -> permissions grants, listing groups in
// the order given.
func policyACL(grants ...grant) map[string]any {
	acl := map[string]any{}
	for _, p := range aclPerms {
		groups := []string{}
		for _, g := range grants {
			if slices.Contains(g.perms, p) {
				groups = append(groups, g.group)
			}
		}
		acl[p] = map[string]any{"actors": []string{}, "groups": groups}
	}
	return acl
}

type grant struct {
	group string
	perms []string
}

// containerACL is the ACL erchef's org policy gives the named container. A
// container outside the default set (one created through POST /containers)
// takes the containers container's ACL, which is what erchef copies onto an
// object created in a container.
func containerACL(name string) map[string]any {
	if _, ok := containerUserPerms[name]; !ok {
		name = "containers"
	}
	return policyACL(
		grant{"admins", aclPerms},
		grant{"users", containerUserPerms[name]},
		grant{"clients", containerClientPerms[name]},
	)
}

// groupACL is the ACL erchef's org policy gives the named default group. A
// group created later takes the groups container's ACL, as in erchef.
func groupACL(name string) map[string]any {
	switch name {
	case "admins", "clients", "users":
		return policyACL(grant{"admins", aclPerms})
	case "billing-admins":
		return policyACL(grant{"billing-admins", []string{"read", "update"}})
	case "public_key_read_access":
		return policyACL(grant{"admins", []string{"read", "update"}})
	}
	return containerACL("groups")
}

// orgACL is the ACL erchef's org policy gives the organization: everything to
// admins, read to users. Update on it is what invites, rescinds and removes
// members, so it must stay with the admins.
func orgACL() map[string]any {
	return policyACL(grant{"admins", aclPerms}, grant{"users", []string{"read"}})
}

// validatorClientsACL is the clients container ACL stored at org creation:
// erchef's, plus the org's validator on create so the validator key can
// register clients. (erchef keeps the validator out of the ACL and lets it
// create clients through a special case in the clients handler instead.)
func validatorClientsACL(validator string) map[string]any {
	acl := containerACL("clients")
	acl["create"].(map[string]any)["actors"] = []string{validator}
	return acl
}

// legacyClientsACL is the clients container ACL versions before this table
// stored at org creation: the permissive object default, which gives the
// clients group read on the clients container, with the validator on create.
func legacyClientsACL(validator string) map[string]any {
	acl := defaultACL()
	acl["create"] = map[string]any{"actors": []string{validator}, "groups": []string{"admins", "users"}}
	return acl
}

// UpgradeOrgACLs brings the stored ACLs of an org created by an older version
// to erchef's org policy. Only the clients container ACL was ever stored at org
// creation; it is rewritten when it is still byte for byte the legacy seeded
// form, so an ACL an operator has since changed is left as they set it. Every
// other default container, group and the organization had no stored ACL and
// already falls back to the policy table. It is idempotent.
func UpgradeOrgACLs(org *store.Org) error {
	validator := org.Name() + "-validator"
	key := aclKey("containers", "clients")
	raw, ok, err := org.Get("acls", key)
	if err != nil || !ok {
		return err
	}
	if !bytes.Equal(raw, mustEncode(legacyClientsACL(validator))) {
		return nil
	}
	return org.Put("acls", key, mustEncode(validatorClientsACL(validator)))
}
