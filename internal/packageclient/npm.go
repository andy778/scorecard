// Copyright 2026 OpenSSF Scorecard Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package packageclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	npmRegistryURL = "https://registry.npmjs.org"
	// Abbreviated ("corgi") metadata: much smaller than the full packument,
	// but still lists every version's dist.attestations.
	npmAbbreviatedAccept = "application/vnd.npm.install-v1+json"
	// Packuments of very popular packages can be tens of megabytes.
	npmMaxResponseBytes = 64 << 20

	slsaProvenanceV1  = "https://slsa.dev/provenance/v1"
	slsaProvenanceV02 = "https://slsa.dev/provenance/v0.2"
)

var (
	ErrNPMRegistry        = errors.New("npm registry")
	ErrNPMPackageNotFound = errors.New("package not found in npm registry")
)

// NPMClient looks up how packages were published to the npm registry.
type NPMClient interface {
	// GetLatestVersion returns the metadata of the version tagged "latest".
	GetLatestVersion(ctx context.Context, name string) (*NPMVersion, error)
	// ListVersionsWithProvenance returns all published versions of the package,
	// and whether each one has a provenance attestation.
	ListVersionsWithProvenance(ctx context.Context, name string) (map[string]bool, error)
	// GetProvenance returns the SLSA provenance the registry stores for a version,
	// or nil if it has none.
	GetProvenance(ctx context.Context, name, version string) (*NPMProvenance, error)
}

// NPMVersion is the subset of npm's version metadata Scorecard uses.
type NPMVersion struct {
	Dist struct {
		Attestations *npmAttestationsRef `json:"attestations"`
	} `json:"dist"`
	Name       string             `json:"name"`
	Version    string             `json:"version"`
	GitHead    string             `json:"gitHead"`
	Repository npmRepositoryField `json:"repository"`
	NPMUser    struct {
		TrustedPublisher *struct {
			ID string `json:"id"`
		} `json:"trustedPublisher"`
		Name  string `json:"name"`
		Email string `json:"email"`
	} `json:"_npmUser"`
}

// HasProvenance reports whether the registry lists a provenance attestation for the version.
func (v *NPMVersion) HasProvenance() bool {
	return v.Dist.Attestations != nil && v.Dist.Attestations.Provenance != nil
}

// TrustedPublisher reports whether the version was published with npm trusted publishing (OIDC).
func (v *NPMVersion) TrustedPublisher() bool {
	return v.NPMUser.TrustedPublisher != nil
}

type npmAttestationsRef struct {
	Provenance *struct {
		PredicateType string `json:"predicateType"`
	} `json:"provenance"`
	URL string `json:"url"`
}

// npmRepositoryField is either a string ("github:owner/repo") or {"type": "git", "url": "..."}.
type npmRepositoryField struct {
	URL string
}

func (r *npmRepositoryField) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		r.URL = s
		return nil
	}
	var o struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(b, &o); err != nil {
		// Malformed repository fields are common enough that they shouldn't fail the lookup.
		return nil //nolint:nilerr
	}
	r.URL = o.URL
	return nil
}

// NPMProvenance is the source information from a version's SLSA provenance.
type NPMProvenance struct {
	PredicateType string
	// SourceRepository is the repository the build ran from, e.g. "https://github.com/npm/node-semver".
	SourceRepository string
	// Workflow is the CI configuration that ran the build, e.g. ".github/workflows/release.yml".
	Workflow string
	Commit   string
}

type npmClient struct {
	client  *http.Client
	baseURL string
}

// CreateNPMClient returns a client for the public npm registry.
func CreateNPMClient() NPMClient {
	return &npmClient{client: &http.Client{}, baseURL: npmRegistryURL}
}

// CreateNPMClientWithURL returns a client for an npm-compatible registry at baseURL.
func CreateNPMClientWithURL(client *http.Client, baseURL string) NPMClient {
	return &npmClient{client: client, baseURL: strings.TrimSuffix(baseURL, "/")}
}

func (n *npmClient) get(ctx context.Context, path, accept string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, n.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("http.NewRequestWithContext: %w", err)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNPMRegistry, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return ErrNPMPackageNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: %s %s", ErrNPMRegistry, path, resp.Status)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, npmMaxResponseBytes)).Decode(v); err != nil {
		return fmt.Errorf("%w: decoding %s: %w", ErrNPMRegistry, path, err)
	}
	return nil
}

// escapeName escapes a (possibly scoped) package name for use in a registry URL path.
func escapeName(name string) string {
	return url.PathEscape(name)
}

func (n *npmClient) GetLatestVersion(ctx context.Context, name string) (*NPMVersion, error) {
	var v NPMVersion
	if err := n.get(ctx, "/"+escapeName(name)+"/latest", "", &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func (n *npmClient) ListVersionsWithProvenance(ctx context.Context, name string) (map[string]bool, error) {
	var doc struct {
		Versions map[string]struct {
			Dist struct {
				Attestations *npmAttestationsRef `json:"attestations"`
			} `json:"dist"`
		} `json:"versions"`
	}
	if err := n.get(ctx, "/"+escapeName(name), npmAbbreviatedAccept, &doc); err != nil {
		return nil, err
	}
	versions := make(map[string]bool, len(doc.Versions))
	for version, v := range doc.Versions {
		versions[version] = v.Dist.Attestations != nil && v.Dist.Attestations.Provenance != nil
	}
	return versions, nil
}

type npmAttestationsResponse struct {
	Attestations []struct {
		PredicateType string `json:"predicateType"`
		Bundle        struct {
			DSSEEnvelope struct {
				Payload string `json:"payload"`
			} `json:"dsseEnvelope"`
		} `json:"bundle"`
	} `json:"attestations"`
}

// slsaStatement holds the fields of SLSA provenance v1 and v0.2 that identify the source.
type slsaStatement struct {
	Predicate struct {
		// v0.2
		Invocation struct {
			ConfigSource struct {
				URI        string            `json:"uri"`
				Digest     map[string]string `json:"digest"`
				EntryPoint string            `json:"entryPoint"`
			} `json:"configSource"`
		} `json:"invocation"`
		// v1
		BuildDefinition struct {
			ExternalParameters struct {
				Workflow struct {
					Repository string `json:"repository"`
					Path       string `json:"path"`
				} `json:"workflow"`
			} `json:"externalParameters"`
			ResolvedDependencies []struct {
				Digest map[string]string `json:"digest"`
				URI    string            `json:"uri"`
			} `json:"resolvedDependencies"`
		} `json:"buildDefinition"`
	} `json:"predicate"`
}

func (n *npmClient) GetProvenance(ctx context.Context, name, version string) (*NPMProvenance, error) {
	var resp npmAttestationsResponse
	err := n.get(ctx, "/-/npm/v1/attestations/"+escapeName(name)+"@"+url.PathEscape(version), "", &resp)
	if errors.Is(err, ErrNPMPackageNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	for _, a := range resp.Attestations {
		if a.PredicateType != slsaProvenanceV1 && a.PredicateType != slsaProvenanceV02 {
			continue
		}
		payload, err := base64.StdEncoding.DecodeString(a.Bundle.DSSEEnvelope.Payload)
		if err != nil {
			return nil, fmt.Errorf("%w: decoding provenance payload: %w", ErrNPMRegistry, err)
		}
		var s slsaStatement
		if err := json.Unmarshal(payload, &s); err != nil {
			return nil, fmt.Errorf("%w: parsing provenance: %w", ErrNPMRegistry, err)
		}
		return provenanceFromStatement(a.PredicateType, &s), nil
	}
	return nil, nil
}

func provenanceFromStatement(predicateType string, s *slsaStatement) *NPMProvenance {
	p := &NPMProvenance{PredicateType: predicateType}
	if predicateType == slsaProvenanceV02 {
		cs := s.Predicate.Invocation.ConfigSource
		p.SourceRepository = stripGitRef(cs.URI)
		p.Commit = cs.Digest["sha1"]
		// entryPoint is "owner/repo/.github/workflows/publish.yml@refs/tags/v1".
		p.Workflow, _, _ = strings.Cut(cs.EntryPoint, "@")
		return p
	}

	bd := s.Predicate.BuildDefinition
	p.SourceRepository = bd.ExternalParameters.Workflow.Repository
	p.Workflow = bd.ExternalParameters.Workflow.Path
	if len(bd.ResolvedDependencies) > 0 {
		dep := bd.ResolvedDependencies[0]
		if p.SourceRepository == "" {
			// GitLab provenance has no workflow.repository.
			p.SourceRepository = stripGitRef(dep.URI)
		}
		p.Commit = dep.Digest["gitCommit"]
	}
	return p
}

// stripGitRef turns "git+https://github.com/o/r@refs/heads/main" into "https://github.com/o/r".
func stripGitRef(uri string) string {
	uri = strings.TrimPrefix(uri, "git+")
	if i := strings.LastIndex(uri, "@refs/"); i >= 0 {
		uri = uri[:i]
	}
	return uri
}
