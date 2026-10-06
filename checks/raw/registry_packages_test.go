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
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/mock/gomock"

	"github.com/ossf/scorecard/v5/checker"
	"github.com/ossf/scorecard/v5/clients"
	mockrepo "github.com/ossf/scorecard/v5/clients/mockclients"
	"github.com/ossf/scorecard/v5/internal/packageclient"
)

func TestRepoURLMatches(t *testing.T) {
	t.Parallel()
	const uri = "github.com/ossf/scorecard"
	tests := []struct {
		url  string
		want bool
	}{
		{"git+https://github.com/ossf/scorecard.git", true},
		{"https://github.com/ossf/scorecard", true},
		{"https://www.github.com/OSSF/Scorecard/", true},
		{"git://github.com/ossf/scorecard.git", true},
		{"git+ssh://git@github.com/ossf/scorecard.git", true},
		{"git@github.com:ossf/scorecard.git", true},
		{"github:ossf/scorecard", true},
		{"ossf/scorecard", true},
		{"https://github.com/ossf/scorecard/tree/main/packages/x", true},
		{"https://github.com/ossf/scorecard#readme", true},
		{"https://github.com/ossf/scorecard-action", false},
		{"https://github.com/evil/scorecard", false},
		{"gitlab:ossf/scorecard", false},
		{"https://example.com/ossf/scorecard", false},
		{"unknown:ossf/scorecard", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := RepoURLMatches(tt.url, uri); got != tt.want {
			t.Errorf("RepoURLMatches(%q) = %v, want %v", tt.url, got, tt.want)
		}
	}
	if !RepoURLMatches("gitlab:group/project", "gitlab.com/group/project") {
		t.Error("gitlab shorthand should match")
	}
}

func TestIsWorkspacePackageJSON(t *testing.T) {
	t.Parallel()
	workspaces := []string{"packages/*", "./tools/cli", "apps/**", "!packages/ignored"}
	tests := []struct {
		file string
		want bool
	}{
		{"package.json", false},
		{"packages/a/package.json", true},
		{"packages/a/b/package.json", false},
		{"tools/cli/package.json", true},
		{"apps/web/nested/package.json", true},
		{"packages/a/node_modules/x/package.json", false},
		{"examples/a/package.json", false},
		{"packages/a/tsconfig.json", false},
	}
	for _, tt := range tests {
		if got := isWorkspacePackageJSON(tt.file, workspaces); got != tt.want {
			t.Errorf("isWorkspacePackageJSON(%q) = %v, want %v", tt.file, got, tt.want)
		}
	}
}

func TestNewestVersion(t *testing.T) {
	t.Parallel()
	got := newestVersion(map[string]bool{
		"1.9.0": true, "1.10.0": true, "2.0.0": false, "not-semver": true,
	})
	if got != "1.10.0" {
		t.Errorf("newestVersion = %q, want 1.10.0", got)
	}
}

type fakeNPMClient struct {
	latest     map[string]*packageclient.NPMVersion
	versions   map[string]map[string]bool
	provenance map[string]*packageclient.NPMProvenance
}

func (f *fakeNPMClient) GetLatestVersion(_ context.Context, name string) (*packageclient.NPMVersion, error) {
	v, ok := f.latest[name]
	if !ok {
		return nil, packageclient.ErrNPMPackageNotFound
	}
	return v, nil
}

func (f *fakeNPMClient) ListVersionsWithProvenance(_ context.Context, name string) (map[string]bool, error) {
	return f.versions[name], nil
}

func (f *fakeNPMClient) GetProvenance(_ context.Context, name, version string) (*packageclient.NPMProvenance, error) {
	return f.provenance[name+"@"+version], nil
}

func npmVersion(name, version, repo, publisher string, trusted, provenance bool) *packageclient.NPMVersion {
	v := &packageclient.NPMVersion{Name: name, Version: version}
	v.Repository.URL = repo
	v.NPMUser.Name = publisher
	if trusted {
		v.NPMUser.TrustedPublisher = &struct {
			ID string `json:"id"`
		}{ID: "github"}
	}
	if provenance {
		err := json.Unmarshal([]byte(`{"provenance":{"predicateType":"https://slsa.dev/provenance/v1"}}`), &v.Dist.Attestations)
		if err != nil {
			panic(err)
		}
	}
	return v
}

func TestRegistryPackages(t *testing.T) {
	t.Parallel()
	const repoURL = "git+https://github.com/o/r.git"
	files := map[string]string{ //nolint:gosec // package.json contents, not credentials
		"package.json":                      `{"name": "root", "workspaces": {"packages": ["packages/*"]}}`,
		"packages/secure/package.json":      `{"name": "@o/secure"}`,
		"packages/token/package.json":       `{"name": "@o/token"}`,
		"packages/imposter/package.json":    `{"name": "@o/imposter"}`,
		"packages/collision/package.json":   `{"name": "server"}`,
		"packages/unpublished/package.json": `{"name": "@o/unpublished"}`,
		"packages/private/package.json":     `{"name": "@o/private", "private": true}`,
		"packages/broken/package.json":      `{not json`,
	}
	npm := &fakeNPMClient{
		latest: map[string]*packageclient.NPMVersion{
			"root":        npmVersion("root", "1.0.0", repoURL, "Alice", false, false),
			"@o/secure":   npmVersion("@o/secure", "2.0.0", repoURL, "GitHub Actions", true, true),
			"@o/token":    npmVersion("@o/token", "3.0.0", "github:o/r", "mallory", false, false),
			"@o/imposter": npmVersion("@o/imposter", "1.0.0", repoURL, "GitHub Actions", true, true),
			// Someone else's package that happens to share a name with one in the repo.
			"server": npmVersion("server", "9.0.0", "https://github.com/other/server", "bob", false, false),
		},
		versions: map[string]map[string]bool{
			"root":     {"0.9.0": true, "1.0.0": false},
			"@o/token": {"3.0.0": false},
		},
		provenance: map[string]*packageclient.NPMProvenance{
			"@o/secure@2.0.0": {
				SourceRepository: "https://github.com/o/r", Workflow: ".github/workflows/release.yml", Commit: "abc",
			},
			"@o/imposter@1.0.0": {SourceRepository: "https://github.com/evil/r", Workflow: "x.yml"},
		},
	}

	ctrl := gomock.NewController(t)
	repoClient := mockrepo.NewMockRepoClient(ctrl)
	repoClient.EXPECT().GetFileReader(gomock.Any()).DoAndReturn(func(f string) (io.ReadCloser, error) {
		content, ok := files[f]
		if !ok {
			return nil, errors.New("not found")
		}
		return io.NopCloser(strings.NewReader(content)), nil
	}).AnyTimes()
	repoClient.EXPECT().ListFiles(gomock.Any()).DoAndReturn(func(pred func(string) (bool, error)) ([]string, error) {
		var matched []string
		for f := range files {
			if ok, err := pred(f); err == nil && ok {
				matched = append(matched, f)
			}
		}
		return matched, nil
	})
	// Contributors are listed once, however many packages need them.
	repoClient.EXPECT().ListContributors().Return([]clients.User{{Login: "alice"}}, nil).Times(1)
	repo := mockrepo.NewMockRepo(ctrl)
	repo.EXPECT().URI().Return("github.com/o/r").AnyTimes()

	got := RegistryPackages(&checker.CheckRequest{
		Ctx:        context.Background(),
		RepoClient: repoClient,
		Repo:       repo,
		NPMClient:  npm,
	})

	yes, no := true, false
	want := []checker.RegistryPackage{
		{
			System: "npm", Name: "root", Version: "1.0.0", Publisher: "Alice",
			PublisherIsContributor: &yes, PreviousVersionWithProvenance: "0.9.0",
		},
		{
			System: "npm", Name: "@o/imposter", Version: "1.0.0", Publisher: "GitHub Actions", TrustedPublisher: true,
			Provenance: &checker.RegistryProvenance{SourceRepository: "https://github.com/evil/r", Workflow: "x.yml"},
		},
		{
			System: "npm", Name: "@o/secure", Version: "2.0.0", Publisher: "GitHub Actions", TrustedPublisher: true,
			Provenance: &checker.RegistryProvenance{
				SourceRepository: "https://github.com/o/r", Workflow: ".github/workflows/release.yml",
				Commit: "abc", MatchesRepo: true,
			},
		},
		{
			System: "npm", Name: "@o/token", Version: "3.0.0", Publisher: "mallory",
			PublisherIsContributor: &no,
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}

func TestRegistryPackages_noClient(t *testing.T) {
	t.Parallel()
	if got := RegistryPackages(&checker.CheckRequest{}); got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestRegistryPackages_noPackageJSON(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	repoClient := mockrepo.NewMockRepoClient(ctrl)
	repoClient.EXPECT().GetFileReader("package.json").Return(nil, errors.New("not found"))
	got := RegistryPackages(&checker.CheckRequest{
		Ctx: context.Background(), RepoClient: repoClient, NPMClient: &fakeNPMClient{},
	})
	if got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestRegistryPackages_publisherIsContributor(t *testing.T) {
	t.Parallel()
	yes := true
	tests := []struct {
		want         *bool
		name         string
		publisher    string
		contributors []clients.User
	}{
		{
			name:      "repository owner without listed contributors",
			publisher: "Owner",
			want:      &yes,
		},
		{
			// GitHub lists no contributors when commit emails aren't linked to accounts.
			name:      "no listed contributors",
			publisher: "someone",
			want:      nil,
		},
		{
			name:         "listed contributor",
			publisher:    "alice",
			contributors: []clients.User{{Login: "Alice"}},
			want:         &yes,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			repoClient := mockrepo.NewMockRepoClient(ctrl)
			repoClient.EXPECT().GetFileReader("package.json").
				Return(io.NopCloser(strings.NewReader(`{"name": "pkg"}`)), nil)
			repoClient.EXPECT().ListContributors().Return(tt.contributors, nil).AnyTimes()
			repo := mockrepo.NewMockRepo(ctrl)
			repo.EXPECT().URI().Return("github.com/owner/repo").AnyTimes()
			npm := &fakeNPMClient{latest: map[string]*packageclient.NPMVersion{
				"pkg": npmVersion("pkg", "1.0.0", "github:owner/repo", tt.publisher, false, false),
			}}

			got := RegistryPackages(&checker.CheckRequest{
				Ctx: context.Background(), RepoClient: repoClient, Repo: repo, NPMClient: npm,
			})
			if len(got) != 1 {
				t.Fatalf("got %d packages, want 1", len(got))
			}
			if diff := cmp.Diff(tt.want, got[0].PublisherIsContributor); diff != "" {
				t.Errorf("PublisherIsContributor mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
