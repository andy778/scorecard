// Copyright 2026 OpenSSF Scorecard Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package raw

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"sort"
	"strings"

	"golang.org/x/mod/semver"

	"github.com/ossf/scorecard/v5/checker"
	"github.com/ossf/scorecard/v5/internal/packageclient"
)

// maxRegistryPackages caps the registry lookups for large monorepos.
const maxRegistryPackages = 10

type packageJSON struct {
	Name       string                `json:"name"`
	Workspaces packageJSONWorkspaces `json:"workspaces"`
	Private    bool                  `json:"private"`
}

// packageJSONWorkspaces is either ["packages/*"] or {"packages": ["packages/*"]}.
type packageJSONWorkspaces []string

func (w *packageJSONWorkspaces) UnmarshalJSON(b []byte) error {
	var list []string
	if err := json.Unmarshal(b, &list); err == nil {
		*w = list
		return nil
	}
	var obj struct {
		Packages []string `json:"packages"`
	}
	if err := json.Unmarshal(b, &obj); err != nil {
		return nil //nolint:nilerr // an unusual workspaces field shouldn't hide the root package
	}
	*w = obj.Packages
	return nil
}

// RegistryPackages looks up how the packages published from the repository
// were published to their registry. Only npm is supported.
//
// Lookup failures are logged at debug level and never fail the check: a
// package that can't be looked up is left out.
func RegistryPackages(c *checker.CheckRequest) []checker.RegistryPackage {
	if c.NPMClient == nil {
		return nil
	}

	names, err := npmPackageNames(c)
	if err != nil {
		debugf(c, "finding npm packages: %v", err)
		return nil
	}
	if len(names) == 0 {
		return nil
	}

	// The account that owns the repository is part of the project, even when
	// the forge doesn't list it as a contributor.
	var owner string
	if parts := strings.Split(c.Repo.URI(), "/"); len(parts) >= 3 {
		owner = strings.ToLower(parts[1])
	}

	var contributors map[string]bool
	contributorsLoaded := false
	isContributor := func(login string) *bool {
		login = strings.ToLower(login)
		if login != "" && login == owner {
			ok := true
			return &ok
		}
		if !contributorsLoaded {
			contributorsLoaded = true
			users, err := c.RepoClient.ListContributors()
			if err != nil {
				debugf(c, "ListContributors: %v", err)
				return nil
			}
			contributors = make(map[string]bool, len(users))
			for _, u := range users {
				contributors[strings.ToLower(u.Login)] = true
			}
		}
		// GitHub lists no contributors when commit emails aren't linked to
		// accounts. That says nothing about who the publisher is.
		if len(contributors) == 0 {
			return nil
		}
		ok := contributors[login]
		return &ok
	}

	var pkgs []checker.RegistryPackage
	for _, name := range names {
		pkg, err := npmRegistryPackage(c, name, isContributor)
		if err != nil {
			debugf(c, "npm package %s: %v", name, err)
			continue
		}
		if pkg != nil {
			pkgs = append(pkgs, *pkg)
		}
	}
	return pkgs
}

func npmRegistryPackage(c *checker.CheckRequest, name string,
	isContributor func(string) *bool,
) (*checker.RegistryPackage, error) {
	latest, err := c.NPMClient.GetLatestVersion(c.Ctx, name)
	if errors.Is(err, packageclient.ErrNPMPackageNotFound) {
		debugf(c, "npm package %s is not published", name)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetLatestVersion: %w", err)
	}

	// The repo's package.json can name a package someone else owns (e.g. an
	// unpublished app called "server"). Only count packages that link back.
	if !RepoURLMatches(latest.Repository.URL, c.Repo.URI()) {
		debugf(c, "npm package %s links to %q, not this repository; ignoring it", name, latest.Repository.URL)
		return nil, nil
	}

	pkg := &checker.RegistryPackage{
		System:           "npm",
		Name:             latest.Name,
		Version:          latest.Version,
		Publisher:        latest.NPMUser.Name,
		TrustedPublisher: latest.TrustedPublisher(),
	}

	if latest.HasProvenance() {
		prov, err := c.NPMClient.GetProvenance(c.Ctx, name, latest.Version)
		if err != nil {
			return nil, fmt.Errorf("GetProvenance: %w", err)
		}
		if prov != nil {
			pkg.Provenance = &checker.RegistryProvenance{
				SourceRepository: prov.SourceRepository,
				Workflow:         prov.Workflow,
				Commit:           prov.Commit,
				MatchesRepo:      RepoURLMatches(prov.SourceRepository, c.Repo.URI()),
			}
		}
	} else {
		versions, err := c.NPMClient.ListVersionsWithProvenance(c.Ctx, name)
		if err != nil {
			return nil, fmt.Errorf("ListVersionsWithProvenance: %w", err)
		}
		pkg.PreviousVersionWithProvenance = newestVersion(versions)
	}

	if !pkg.TrustedPublisher {
		pkg.PublisherIsContributor = isContributor(pkg.Publisher)
	}
	return pkg, nil
}

// newestVersion returns the highest semver version that has provenance.
func newestVersion(versions map[string]bool) string {
	newest := ""
	for v, hasProvenance := range versions {
		if !hasProvenance || !semver.IsValid("v"+v) {
			continue
		}
		if newest == "" || semver.Compare("v"+v, "v"+newest) > 0 {
			newest = v
		}
	}
	return newest
}

// npmPackageNames returns the publishable (non-private) packages declared by
// the root package.json and its workspaces.
func npmPackageNames(c *checker.CheckRequest) ([]string, error) {
	root, err := readPackageJSON(c, "package.json")
	if err != nil {
		// No root package.json means no npm package.
		debugf(c, "reading package.json: %v", err)
		return nil, nil
	}

	seen := map[string]bool{}
	var names []string
	add := func(p *packageJSON) {
		if p.Private || p.Name == "" || seen[p.Name] {
			return
		}
		seen[p.Name] = true
		names = append(names, p.Name)
	}
	add(root)

	if len(root.Workspaces) > 0 {
		files, err := c.RepoClient.ListFiles(func(f string) (bool, error) {
			return isWorkspacePackageJSON(f, root.Workspaces), nil
		})
		if err != nil {
			return nil, fmt.Errorf("ListFiles: %w", err)
		}
		sort.Strings(files)
		for _, f := range files {
			p, err := readPackageJSON(c, f)
			if err != nil {
				debugf(c, "reading %s: %v", f, err)
				continue
			}
			add(p)
		}
	}

	if len(names) > maxRegistryPackages {
		debugf(c, "found %d npm packages, only looking up the first %d", len(names), maxRegistryPackages)
		names = names[:maxRegistryPackages]
	}
	return names, nil
}

func isWorkspacePackageJSON(f string, workspaces []string) bool {
	if path.Base(f) != "package.json" || f == "package.json" ||
		strings.Contains(f, "node_modules/") {
		return false
	}
	dir := path.Dir(f)
	for _, ws := range workspaces {
		ws = strings.TrimSuffix(strings.TrimPrefix(ws, "./"), "/")
		if strings.HasPrefix(ws, "!") {
			continue
		}
		// "packages/**" matches any depth below packages/.
		if prefix, ok := strings.CutSuffix(ws, "/**"); ok {
			if strings.HasPrefix(dir, prefix+"/") {
				return true
			}
			continue
		}
		if ok, err := path.Match(ws, dir); err == nil && ok {
			return true
		}
	}
	return false
}

func readPackageJSON(c *checker.CheckRequest, f string) (*packageJSON, error) {
	r, err := c.RepoClient.GetFileReader(f)
	if err != nil {
		return nil, fmt.Errorf("GetFileReader: %w", err)
	}
	defer r.Close()
	var p packageJSON
	if err := json.NewDecoder(io.LimitReader(r, 1<<20)).Decode(&p); err != nil {
		return nil, fmt.Errorf("parsing: %w", err)
	}
	return &p, nil
}

// RepoURLMatches reports whether a repository URL as written in package
// metadata (e.g. "git+https://github.com/o/r.git", "github:o/r",
// "git@github.com:o/r.git") points at repoURI ("github.com/o/r").
func RepoURLMatches(repoURL, repoURI string) bool {
	n := normalizeRepoURL(repoURL)
	uri := strings.ToLower(strings.TrimSuffix(repoURI, "/"))
	if n == "" || uri == "" {
		return false
	}
	// Allow deep links such as github.com/o/r/tree/main/packages/x.
	return n == uri || strings.HasPrefix(n, uri+"/")
}

var npmRepoShorthands = map[string]string{
	"github":    "github.com",
	"gitlab":    "gitlab.com",
	"bitbucket": "bitbucket.org",
}

func normalizeRepoURL(u string) string {
	u = strings.TrimSpace(u)
	u = strings.TrimPrefix(u, "git+")
	if i := strings.IndexAny(u, "#?"); i >= 0 {
		u = u[:i]
	}

	switch {
	case strings.Contains(u, "://"):
		parsed, err := url.Parse(u)
		if err != nil {
			return ""
		}
		u = parsed.Hostname() + parsed.Path
	case strings.HasPrefix(u, "git@"):
		// scp-like syntax: git@github.com:o/r.git
		u = strings.Replace(strings.TrimPrefix(u, "git@"), ":", "/", 1)
	default:
		if host, rest, ok := strings.Cut(u, ":"); ok {
			if h, known := npmRepoShorthands[host]; known {
				u = h + "/" + rest
			} else {
				return ""
			}
		} else if strings.Count(u, "/") == 1 && !strings.Contains(u, ".") {
			// "o/r" is shorthand for GitHub.
			u = "github.com/" + u
		}
	}

	u = strings.ToLower(strings.TrimSuffix(strings.TrimSuffix(u, "/"), ".git"))
	return strings.TrimPrefix(u, "www.")
}

func debugf(c *checker.CheckRequest, format string, args ...any) {
	if c.Dlogger != nil {
		c.Dlogger.Debug(&checker.LogMessage{Text: fmt.Sprintf(format, args...)})
	}
}
