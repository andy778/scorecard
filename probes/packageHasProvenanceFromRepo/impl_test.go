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

package packageHasProvenanceFromRepo

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/ossf/scorecard/v5/checker"
	"github.com/ossf/scorecard/v5/finding"
	"github.com/ossf/scorecard/v5/probes/internal/utils/test"
)

func Test_Run(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		pkgs     []checker.RegistryPackage
		outcomes []finding.Outcome
		reasons  []string
	}{
		{
			name:     "no packages",
			outcomes: []finding.Outcome{finding.OutcomeNotApplicable},
			reasons:  []string{""},
		},
		{
			name:     "no provenance",
			pkgs:     []checker.RegistryPackage{{System: "npm", Name: "a"}},
			outcomes: []finding.Outcome{finding.OutcomeFalse},
			reasons:  []string{ReasonMissing},
		},
		{
			name: "provenance from this repo",
			pkgs: []checker.RegistryPackage{{
				System: "npm", Name: "a",
				Provenance: &checker.RegistryProvenance{
					SourceRepository: "https://github.com/o/r", MatchesRepo: true,
				},
			}},
			outcomes: []finding.Outcome{finding.OutcomeTrue},
			reasons:  []string{""},
		},
		{
			name: "provenance from another repo",
			pkgs: []checker.RegistryPackage{{
				System: "npm", Name: "a",
				Provenance: &checker.RegistryProvenance{SourceRepository: "https://github.com/evil/r"},
			}},
			outcomes: []finding.Outcome{finding.OutcomeFalse},
			reasons:  []string{ReasonMismatch},
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
			for i := range findings {
				if got := findings[i].Values[ValueReason]; got != tt.reasons[i] {
					t.Errorf("finding %d: reason %q, want %q", i, got, tt.reasons[i])
				}
			}
		})
	}
}

func TestRun_nilRaw(t *testing.T) {
	t.Parallel()
	if _, _, err := Run(nil); err == nil {
		t.Error("expected an error")
	}
}
