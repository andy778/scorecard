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

package packagePublishedByRepoContributor

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/ossf/scorecard/v5/checker"
	"github.com/ossf/scorecard/v5/finding"
	"github.com/ossf/scorecard/v5/probes/internal/utils/test"
)

func Test_Run(t *testing.T) {
	t.Parallel()
	yes, no := true, false
	tests := []struct {
		name     string
		pkgs     []checker.RegistryPackage
		outcomes []finding.Outcome
	}{
		{
			name:     "no packages",
			outcomes: []finding.Outcome{finding.OutcomeNotApplicable},
		},
		{
			name: "published by this repo's CI",
			pkgs: []checker.RegistryPackage{{
				System: "npm", Name: "a", TrustedPublisher: true,
				Provenance: &checker.RegistryProvenance{MatchesRepo: true},
			}},
			outcomes: []finding.Outcome{finding.OutcomeTrue},
		},
		{
			name:     "published by a contributor",
			pkgs:     []checker.RegistryPackage{{System: "npm", Name: "a", PublisherIsContributor: &yes}},
			outcomes: []finding.Outcome{finding.OutcomeTrue},
		},
		{
			name:     "published by someone else",
			pkgs:     []checker.RegistryPackage{{System: "npm", Name: "a", PublisherIsContributor: &no}},
			outcomes: []finding.Outcome{finding.OutcomeFalse},
		},
		{
			name: "provenance from another repo, publisher unknown",
			pkgs: []checker.RegistryPackage{{
				System: "npm", Name: "a",
				Provenance: &checker.RegistryProvenance{MatchesRepo: false},
			}},
			outcomes: []finding.Outcome{finding.OutcomeNotAvailable},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			raw := &checker.RawResults{
				PackagingResults: checker.PackagingData{RegistryPackages: tt.pkgs},
			}
			findings, s, err := Run(raw)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if diff := cmp.Diff(Probe, s); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
			test.AssertOutcomes(t, findings, tt.outcomes)
		})
	}
}

func TestRun_nilRaw(t *testing.T) {
	t.Parallel()
	if _, _, err := Run(nil); err == nil {
		t.Error("expected an error")
	}
}
