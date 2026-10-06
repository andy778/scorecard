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
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func attestationsJSON(predicateType, statement string) string {
	payload := base64.StdEncoding.EncodeToString([]byte(statement))
	return `{"attestations":[
		{"predicateType":"https://github.com/npm/attestation/tree/main/specs/publish/v0.1",
		 "bundle":{"dsseEnvelope":{"payload":""}}},
		{"predicateType":"` + predicateType + `","bundle":{"dsseEnvelope":{"payload":"` + payload + `"}}}
	]}`
}

func newTestRegistry(t *testing.T) NPMClient {
	t.Helper()
	routes := map[string]string{
		"/@scope%2Fpkg/latest": `{
			"name": "@scope/pkg", "version": "2.0.0", "gitHead": "abc",
			"repository": {"type": "git", "url": "git+https://github.com/o/r.git"},
			"_npmUser": {"name": "GitHub Actions", "trustedPublisher": {"id": "github"}},
			"dist": {"attestations": {"url": "x", "provenance": {"predicateType": "https://slsa.dev/provenance/v1"}}}
		}`,
		"/legacy/latest": `{
			"name": "legacy", "version": "1.0.0", "repository": "github:o/legacy",
			"_npmUser": {"name": "alice"}, "dist": {}
		}`,
		"/legacy": `{"versions": {
			"0.9.0": {"dist": {"attestations": {"provenance": {"predicateType": "https://slsa.dev/provenance/v1"}}}},
			"1.0.0": {"dist": {}}
		}}`,
		"/-/npm/v1/attestations/@scope%2Fpkg@2.0.0": attestationsJSON("https://slsa.dev/provenance/v1", `{"predicate":{
			"buildDefinition":{
				"externalParameters":{"workflow":{"repository":"https://github.com/o/r","path":".github/workflows/release.yml"}},
				"resolvedDependencies":[{"uri":"git+https://github.com/o/r@refs/heads/main","digest":{"gitCommit":"abc"}}]
			}}}`),
		"/-/npm/v1/attestations/gitlab@1.0.0": attestationsJSON("https://slsa.dev/provenance/v1", `{"predicate":{
			"buildDefinition":{
				"resolvedDependencies":[{"uri":"git+https://gitlab.com/g/p@refs/tags/v1.0.0","digest":{"gitCommit":"def"}}]
			}}}`),
		"/-/npm/v1/attestations/old@1.0.0": attestationsJSON("https://slsa.dev/provenance/v0.2", `{"predicate":{
			"invocation":{"configSource":{
				"uri":"git+https://github.com/o/old@refs/tags/v1.0.0",
				"digest":{"sha1":"123"},
				"entryPoint":"o/old/.github/workflows/publish.yml@refs/tags/v1.0.0"
			}}}}`),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := routes[r.URL.EscapedPath()]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(body)) //nolint:errcheck
	}))
	t.Cleanup(srv.Close)
	return CreateNPMClientWithURL(srv.Client(), srv.URL)
}

func TestNPMClient_GetLatestVersion(t *testing.T) {
	t.Parallel()
	c := newTestRegistry(t)
	ctx := context.Background()

	v, err := c.GetLatestVersion(ctx, "@scope/pkg")
	if err != nil {
		t.Fatal(err)
	}
	if v.Version != "2.0.0" || !v.TrustedPublisher() || !v.HasProvenance() ||
		v.Repository.URL != "git+https://github.com/o/r.git" {
		t.Errorf("unexpected version metadata: %+v", v)
	}

	v, err = c.GetLatestVersion(ctx, "legacy")
	if err != nil {
		t.Fatal(err)
	}
	if v.TrustedPublisher() || v.HasProvenance() || v.Repository.URL != "github:o/legacy" || v.NPMUser.Name != "alice" {
		t.Errorf("unexpected version metadata: %+v", v)
	}

	if _, err := c.GetLatestVersion(ctx, "missing"); !errors.Is(err, ErrNPMPackageNotFound) {
		t.Errorf("got error %v, want ErrNPMPackageNotFound", err)
	}
}

func TestNPMClient_ListVersionsWithProvenance(t *testing.T) {
	t.Parallel()
	got, err := newTestRegistry(t).ListVersionsWithProvenance(context.Background(), "legacy")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"0.9.0": true, "1.0.0": false}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}

func TestNPMClient_GetProvenance(t *testing.T) {
	t.Parallel()
	c := newTestRegistry(t)
	tests := []struct {
		want    *NPMProvenance
		name    string
		version string
	}{
		{
			name: "@scope/pkg", version: "2.0.0",
			want: &NPMProvenance{
				PredicateType:    slsaProvenanceV1,
				SourceRepository: "https://github.com/o/r",
				Workflow:         ".github/workflows/release.yml",
				Commit:           "abc",
			},
		},
		{
			name: "gitlab", version: "1.0.0",
			want: &NPMProvenance{
				PredicateType:    slsaProvenanceV1,
				SourceRepository: "https://gitlab.com/g/p",
				Commit:           "def",
			},
		},
		{
			name: "old", version: "1.0.0",
			want: &NPMProvenance{
				PredicateType:    slsaProvenanceV02,
				SourceRepository: "https://github.com/o/old",
				Workflow:         "o/old/.github/workflows/publish.yml",
				Commit:           "123",
			},
		},
		{name: "none", version: "1.0.0", want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := c.GetProvenance(context.Background(), tt.name, tt.version)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
