package api

import "encoding/json"

// Chef's object envelopes.
//
// Several responses carry type information — chef_type, json_class — that
// clients deserialize on: Chef::DataBagItem and Chef::ApiClient reconstruct
// themselves from json_class, so a response without it is not the object the
// client was expecting, however correct its contents.
//
// Which envelope appears on which route is not consistent, and what follows was
// established by diffing against a real server rather than by deciding what
// would be tidy. Creating a data bag item returns it flat with two fields
// added; reading it back returns it flat with none; deleting it, or finding it
// through search, returns it fully wrapped with the item's own fields moved
// under raw_data.
//
// These are applied to responses only. The stored document keeps its plain
// shape, because that is what search flattens and what the authentication layer
// reads, and burying either under an envelope would be a much larger change
// than making the API say what Chef says.

// Chef type and class names.
const (
	chefTypeDataBagItem  = "data_bag_item"
	chefTypeDataBag      = "data_bag"
	chefTypeClient       = "client"
	jsonClassDataBagItem = "Chef::DataBagItem"
	jsonClassDataBag     = "Chef::DataBag"
	jsonClassAPIClient   = "Chef::ApiClient"
)

// dataBagItemName is the identifier Chef gives a wrapped item.
func dataBagItemName(bag, id string) string {
	return "data_bag_item_" + bag + "_" + id
}

// withCreateEnvelope returns a created data bag item as Chef returns it: the
// item's own fields, plus the two that say what it is.
func withCreateEnvelope(bag string, item map[string]any) map[string]any {
	out := make(map[string]any, len(item)+2)
	for k, v := range item {
		out[k] = v
	}
	out["chef_type"] = chefTypeDataBagItem
	out["data_bag"] = bag
	return out
}

// wrapDataBagItem returns the fully wrapped Chef::DataBagItem form, with the
// item's own fields moved under raw_data.
func wrapDataBagItem(bag, id string, item map[string]any) map[string]any {
	if actualID, ok := item["id"].(string); ok && actualID != "" {
		id = actualID
	}
	return map[string]any{
		"name":       dataBagItemName(bag, id),
		"json_class": jsonClassDataBagItem,
		"chef_type":  chefTypeDataBagItem,
		"data_bag":   bag,
		"raw_data":   item,
	}
}

// wrapStoredDataBagItem wraps a stored item, returning the original bytes
// unchanged if they are not a JSON object — a caller should never turn a
// response it cannot parse into a malformed envelope.
func wrapStoredDataBagItem(bag, id string, raw []byte) []byte {
	var item map[string]any
	if json.Unmarshal(raw, &item) != nil {
		return raw
	}
	return mustEncode(wrapDataBagItem(bag, id, item))
}

// withClientEnvelope adds the fields Chef reports on an API client.
func withClientEnvelope(org string, doc map[string]any) map[string]any {
	name, _ := doc["name"].(string)
	if name == "" {
		name, _ = doc["clientname"].(string)
	}
	out := make(map[string]any, len(doc)+4)
	for k, v := range doc {
		out[k] = v
	}
	out["chef_type"] = chefTypeClient
	out["json_class"] = jsonClassAPIClient
	out["clientname"] = name
	out["name"] = name
	out["orgname"] = org
	return out
}

// enveloped decorates a stored actor document for the response. Only clients
// carry an envelope; a user has a different shape, and adding client fields to
// one would be a fidelity bug of its own.
func enveloped(segment, org string, raw []byte) []byte {
	if segment != "clients" {
		return raw
	}
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil {
		return raw
	}
	return mustEncode(withClientEnvelope(org, doc))
}
