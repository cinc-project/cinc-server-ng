package repo

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/tas50/cinc-server-ng/internal/store"
)

// Cookbook directories are loaded by checksumming every file into the blob
// store and synthesizing a manifest (the modern "all_files" shape) that the
// cookbook GET endpoints serve. Metadata is read from metadata.json when
// present, otherwise best-effort from metadata.rb's name/version/depends lines.

const defaultCookbookVersion = "0.0.0"

var (
	rbName            = regexp.MustCompile(`(?m)^\s*name\s+['"]([^'"]+)['"]`)
	rbVersion         = regexp.MustCompile(`(?m)^\s*version\s+['"]([^'"]+)['"]`)
	rbLicense         = regexp.MustCompile(`(?m)^\s*license\s+['"]([^'"]+)['"]`)
	rbDescription     = regexp.MustCompile(`(?m)^\s*description\s+['"]([^'"]+)['"]`)
	rbMaintainer      = regexp.MustCompile(`(?m)^\s*maintainer\s+['"]([^'"]+)['"]`)
	rbMaintainerEmail = regexp.MustCompile(`(?m)^\s*maintainer_email\s+['"]([^'"]+)['"]`)
	rbSourceURL       = regexp.MustCompile(`(?m)^\s*source_url\s+['"]([^'"]+)['"]`)
	rbIssuesURL       = regexp.MustCompile(`(?m)^\s*issues_url\s+['"]([^'"]+)['"]`)
	rbDepends         = regexp.MustCompile(`(?m)^\s*depends\s+['"]([^'"]+)['"]\s*(?:,\s*['"]([^'"]+)['"])?`)
)

type cookbookMetadata struct {
	name            string
	version         string
	license         string
	description     string
	maintainer      string
	maintainerEmail string
	sourceURL       string
	issuesURL       string
	dependencies    map[string]string
}

// loadCookbooks loads every cookbook directory under dir, returning the count.
func loadCookbooks(org *store.Org, dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	count := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if err := loadCookbook(org, filepath.Join(dir, e.Name()), e.Name()); err != nil {
			return 0, err
		}
		count++
	}
	return count, nil
}

func loadCookbook(org *store.Org, cbDir, dirName string) error {
	meta, err := readCookbookMetadata(cbDir, dirName)
	if err != nil {
		return err
	}

	allFiles := make([]map[string]any, 0)
	walkErr := filepath.WalkDir(cbDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(cbDir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)

		sum := md5.Sum(content)
		checksum := hex.EncodeToString(sum[:])
		if err := org.PutBlob(checksum, content); err != nil {
			return err
		}
		allFiles = append(allFiles, map[string]any{
			"name":        rel,
			"path":        rel,
			"checksum":    checksum,
			"specificity": "default",
		})
		return nil
	})
	if walkErr != nil {
		return walkErr
	}

	manifest := map[string]any{
		"name":          meta.name + "-" + meta.version,
		"cookbook_name": meta.name,
		"version":       meta.version,
		"chef_type":     "cookbook_version",
		"json_class":    "Chef::CookbookVersion",
		"all_files":     allFiles,
		"metadata": map[string]any{
			"name":             meta.name,
			"version":          meta.version,
			"license":          meta.license,
			"description":      meta.description,
			"maintainer":       meta.maintainer,
			"maintainer_email": meta.maintainerEmail,
			"source_url":       meta.sourceURL,
			"issues_url":       meta.issuesURL,
			"dependencies":     meta.dependencies,
		},
	}
	return org.Put("cookbooks", meta.name+"/"+meta.version, canonicalize(manifest))
}

// readCookbookMetadata reads metadata.json if present, else parses metadata.rb,
// falling back to the directory name and a default version.
func readCookbookMetadata(cbDir, dirName string) (cookbookMetadata, error) {
	meta := cookbookMetadata{name: dirName, version: defaultCookbookVersion, dependencies: map[string]string{}}

	if data, err := os.ReadFile(filepath.Join(cbDir, "metadata.json")); err == nil {
		var parsed struct {
			Name            string            `json:"name"`
			Version         string            `json:"version"`
			License         string            `json:"license"`
			Description     string            `json:"description"`
			Maintainer      string            `json:"maintainer"`
			MaintainerEmail string            `json:"maintainer_email"`
			SourceURL       string            `json:"source_url"`
			IssuesURL       string            `json:"issues_url"`
			Dependencies    map[string]string `json:"dependencies"`
		}
		if err := json.Unmarshal(data, &parsed); err != nil {
			return meta, err
		}
		if parsed.Name != "" {
			meta.name = parsed.Name
		}
		if parsed.Version != "" {
			meta.version = parsed.Version
		}
		meta.license = parsed.License
		meta.description = parsed.Description
		meta.maintainer = parsed.Maintainer
		meta.maintainerEmail = parsed.MaintainerEmail
		meta.sourceURL = parsed.SourceURL
		meta.issuesURL = parsed.IssuesURL
		if parsed.Dependencies != nil {
			meta.dependencies = parsed.Dependencies
		}
		return meta, nil
	}

	if data, err := os.ReadFile(filepath.Join(cbDir, "metadata.rb")); err == nil {
		text := string(data)
		if m := rbName.FindStringSubmatch(text); m != nil {
			meta.name = m[1]
		}
		if m := rbVersion.FindStringSubmatch(text); m != nil {
			meta.version = m[1]
		}
		if m := rbLicense.FindStringSubmatch(text); m != nil {
			meta.license = m[1]
		}
		if m := rbDescription.FindStringSubmatch(text); m != nil {
			meta.description = m[1]
		}
		if m := rbMaintainer.FindStringSubmatch(text); m != nil {
			meta.maintainer = m[1]
		}
		if m := rbMaintainerEmail.FindStringSubmatch(text); m != nil {
			meta.maintainerEmail = m[1]
		}
		if m := rbSourceURL.FindStringSubmatch(text); m != nil {
			meta.sourceURL = m[1]
		}
		if m := rbIssuesURL.FindStringSubmatch(text); m != nil {
			meta.issuesURL = m[1]
		}
		for _, m := range rbDepends.FindAllStringSubmatch(text, -1) {
			meta.dependencies[m[1]] = strings.TrimSpace(m[2])
		}
	}
	return meta, nil
}
