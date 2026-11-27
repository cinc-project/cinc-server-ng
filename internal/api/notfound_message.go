package api

import "net/http"

// notFoundMessage is erchef's 404 text for the missing object name in the
// collection segment, as its named-object resource words it. The wording is
// per type (chef_wm_util:not_found_message/2; groups and containers build
// their own in oc_chef_wm_named_group and oc_chef_wm_named_container), so a
// client written against erchef recognizes it.
func notFoundMessage(segment, name string) string {
	switch segment {
	case "nodes":
		return "node '" + name + "' not found"
	case "roles":
		return "Cannot load role " + name
	case "environments":
		return "Cannot load environment " + name
	case "clients":
		return "Cannot load client " + name
	case "users":
		return "Could not find user " + name
	case "groups":
		return "Cannot load group " + name
	case "containers":
		return "Cannot load container " + name
	case "data", dataBagsColl:
		return "Cannot load data bag " + name
	case "cookbooks":
		return "Cannot find a cookbook named " + name
	case "cookbook_artifacts":
		return "Cannot find a cookbook artifact named " + name
	case "policies":
		return "policy '" + name + "' not found"
	case "policy_groups":
		return "policy_group '" + name + "' not found"
	}
	return "Cannot find " + segment + " " + name
}

// aclNotFoundMessage is the 404 text for the _acl of a missing object.
// oc_chef_wm_acl calls not_found_message/2 for every type, so a group reads
// as chef_wm_util words it rather than as its named endpoint does.
func aclNotFoundMessage(typ, name string) string {
	if typ == "groups" {
		return "group '" + name + "' not found"
	}
	return notFoundMessage(typ, name)
}

// dataBagNotFoundMessage is the 404 text for /data/{bag} when the bag is
// missing (chef_wm_named_data:custom_404_msg/2): a POST, which adds an item,
// gets its own.
func dataBagNotFoundMessage(method, bag string) string {
	if method == http.MethodPost {
		return "No data bag '" + bag + "' could be found. Please create this data bag before adding items to it."
	}
	return notFoundMessage(dataBagsColl, bag)
}

// dataBagItemNotFoundMessage is the 404 text for /data/{bag}/{item} when the
// bag or the item is missing; erchef words both the same, by method
// (chef_wm_named_data_item:custom_404_msg/3).
func dataBagItemNotFoundMessage(method, bag, item string) string {
	if method == http.MethodDelete {
		return "Cannot load data bag " + bag + " item " + item
	}
	return "Cannot load data bag item " + item + " for data bag " + bag
}
