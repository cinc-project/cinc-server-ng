package api

import (
	"net/http"
	"strings"

	"github.com/cinc-project/cinc-server-ng/internal/chefjson"
)

// A cookbook manifest lists its files in one of two shapes, chosen by the
// server API version: up to v1, in segment arrays ("recipes", "files", ...)
// whose entries are named relative to the segment; from v2, in one all_files
// array whose entries are named "<segment>/<name>". Chef Infra Server accepts
// each shape only from a client that speaks it, stores the manifest once, and
// shows it to every client in that client's shape. The rules below were
// captured from a real server.

// cookbookSegments are the v0/v1 segments, in the order Chef writes them.
var cookbookSegments = []string{
	"attributes", "definitions", "files", "libraries", "providers",
	"recipes", "resources", "root_files", "templates",
}

// manifestShapeError reports a manifest in the shape another API version uses;
// its text is Chef's 400 message.
type manifestShapeError string

func (e manifestShapeError) Error() string { return string(e) }

// checkManifestShape rejects a manifest whose shape the request's API version
// does not use: all_files below v2, a segment from v2.
func checkManifestShape(r *http.Request, raw []byte) error {
	tree, err := chefjson.Parse(raw)
	if err != nil {
		return err
	}
	obj, ok := tree.(*chefjson.Object)
	if !ok {
		return nil
	}
	v2 := requestAPIVersion(r) >= 2
	for _, m := range obj.Members {
		if (!v2 && m.Name == "all_files") || (v2 && isCookbookSegment(m.Name)) {
			return manifestShapeError("Invalid key " + m.Name + " in request body")
		}
	}
	return nil
}

func isCookbookSegment(name string) bool {
	for _, s := range cookbookSegments {
		if s == name {
			return true
		}
	}
	return false
}

// shapeManifest rewrites a stored manifest into the shape version uses, in
// place. A manifest already in that shape is left alone.
func shapeManifest(obj *chefjson.Object, version int) {
	if version >= 2 {
		toAllFiles(obj)
	} else {
		toSegments(obj)
	}
}

// toSegments turns all_files into the nine segments, every one present. A
// file belongs to the segment its name starts with, and loses that prefix
// ("files/default/foo.conf" is "default/foo.conf" in files; Chef keeps the
// specificity directory), and each segment lists its files most recent first,
// as Chef does.
func toSegments(obj *chefjson.Object) {
	all, ok := obj.Get("all_files")
	if !ok {
		return
	}
	files, _ := all.([]any)
	bySegment := map[string][]any{}
	for _, f := range files {
		entry, ok := f.(*chefjson.Object)
		if !ok {
			continue
		}
		name, _ := entry.Get("name")
		segment, rest, found := strings.Cut(asString(name), "/")
		if !found || !isCookbookSegment(segment) {
			segment, rest = "root_files", asString(name)
		}
		entry.Set("name", rest)
		bySegment[segment] = append([]any{entry}, bySegment[segment]...)
	}
	segments := make([]chefjson.Member, 0, len(cookbookSegments))
	for _, s := range cookbookSegments {
		list := bySegment[s]
		if list == nil {
			list = []any{}
		}
		segments = append(segments, chefjson.Member{Name: s, Value: list})
	}
	replaceMember(obj, "all_files", segments)
}

// toAllFiles turns segments into all_files: segment by segment in alphabetical
// order, each file named "<segment>/<name>", empty segments contributing
// nothing.
func toAllFiles(obj *chefjson.Object) {
	first := ""
	var files []any
	for _, s := range cookbookSegments {
		v, ok := obj.Get(s)
		if !ok {
			continue
		}
		if first == "" {
			first = s
		}
		list, _ := v.([]any)
		for _, f := range list {
			if entry, ok := f.(*chefjson.Object); ok {
				name, _ := entry.Get("name")
				entry.Set("name", s+"/"+asString(name))
				files = append(files, entry)
			}
		}
	}
	if first == "" {
		return
	}
	if files == nil {
		files = []any{}
	}
	replaceMember(obj, first, []chefjson.Member{{Name: "all_files", Value: files}})
	kept := obj.Members[:0]
	for _, m := range obj.Members {
		if !isCookbookSegment(m.Name) {
			kept = append(kept, m)
		}
	}
	obj.Members = kept
}

// replaceMember puts with in place of the member called name.
func replaceMember(obj *chefjson.Object, name string, with []chefjson.Member) {
	for i, m := range obj.Members {
		if m.Name == name {
			members := append([]chefjson.Member{}, obj.Members[:i]...)
			members = append(members, with...)
			obj.Members = append(members, obj.Members[i+1:]...)
			return
		}
	}
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}
