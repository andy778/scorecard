// Copyright 2023 OpenSSF Scorecard Authors
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
package evaluation

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/ossf/scorecard/v5/checker"
	sce "github.com/ossf/scorecard/v5/errors"
	"github.com/ossf/scorecard/v5/finding"
	"github.com/ossf/scorecard/v5/probes/packageHasProvenanceFromRepo"
	"github.com/ossf/scorecard/v5/probes/packageKeepsProvenance"
	"github.com/ossf/scorecard/v5/probes/packagePublishedByRepoContributor"
	"github.com/ossf/scorecard/v5/probes/packagePublishedWithTrustedPublishing"
	"github.com/ossf/scorecard/v5/probes/packagedWithAutomatedWorkflow"
	"github.com/ossf/scorecard/v5/probes/utils/registrypkg"
	scut "github.com/ossf/scorecard/v5/utests"
)

// noRegistryPackages are the findings of the registry probes for a project
// that publishes no registry packages.
func noRegistryPackages() []finding.Finding {
	var fs []finding.Finding
	for _, p := range []string{
		packageHasProvenanceFromRepo.Probe,
		packageKeepsProvenance.Probe,
		packagePublishedByRepoContributor.Probe,
		packagePublishedWithTrustedPublishing.Probe,
	} {
		fs = append(fs, finding.Finding{Probe: p, Outcome: finding.OutcomeNotApplicable})
	}
	return fs
}

func workflow(o finding.Outcome) finding.Finding {
	return finding.Finding{Probe: packagedWithAutomatedWorkflow.Probe, Outcome: o}
}

// registryPackage describes the outcome of each registry probe for one npm package.
type registryPackage struct {
	name             string
	trusted          finding.Outcome
	provenance       finding.Outcome
	provenanceReason string
	contributor      finding.Outcome
	keepsProvenance  finding.Outcome
}

func (r *registryPackage) findings() []finding.Finding {
	values := func(extra ...string) map[string]string {
		v := map[string]string{
			registrypkg.ValueSystem:  "npm",
			registrypkg.ValuePackage: r.name,
			registrypkg.ValueVersion: "1.0.0",
		}
		for i := 0; i+1 < len(extra); i += 2 {
			v[extra[i]] = extra[i+1]
		}
		return v
	}
	return []finding.Finding{
		{Probe: packagePublishedWithTrustedPublishing.Probe, Outcome: r.trusted, Values: values()},
		{
			Probe: packageHasProvenanceFromRepo.Probe, Outcome: r.provenance,
			Values: values(packageHasProvenanceFromRepo.ValueReason, r.provenanceReason),
		},
		{Probe: packagePublishedByRepoContributor.Probe, Outcome: r.contributor, Values: values()},
		{Probe: packageKeepsProvenance.Probe, Outcome: r.keepsProvenance, Values: values()},
	}
}

func withPackages(base finding.Outcome, pkgs ...registryPackage) []finding.Finding {
	fs := []finding.Finding{workflow(base)}
	for i := range pkgs {
		fs = append(fs, pkgs[i].findings()...)
	}
	return fs
}

var (
	secureNPMPackage = registryPackage{
		name:            "secure",
		trusted:         finding.OutcomeTrue,
		provenance:      finding.OutcomeTrue,
		contributor:     finding.OutcomeTrue,
		keepsProvenance: finding.OutcomeTrue,
	}
	tokenNPMPackage = registryPackage{
		name:             "token",
		trusted:          finding.OutcomeFalse,
		provenance:       finding.OutcomeFalse,
		provenanceReason: packageHasProvenanceFromRepo.ReasonMissing,
		contributor:      finding.OutcomeTrue,
		keepsProvenance:  finding.OutcomeTrue,
	}
)

func TestPackaging(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		findings []finding.Finding
		result   scut.TestReturn
	}{
		{
			name:     "test true outcome",
			findings: append([]finding.Finding{workflow(finding.OutcomeTrue)}, noRegistryPackages()...),
			result: scut.TestReturn{
				Score:         checker.MaxResultScore,
				NumberOfInfo:  1,
				NumberOfDebug: 4,
			},
		},
		{
			name: "test true outcome with wrong probes",
			findings: []finding.Finding{
				{
					Probe:   "wrongProbe",
					Outcome: finding.OutcomeTrue,
				},
			},
			result: scut.TestReturn{
				Score: -1,
				Error: sce.ErrScorecardInternal,
			},
		},
		{
			name: "registry probes missing",
			findings: []finding.Finding{
				workflow(finding.OutcomeTrue),
			},
			result: scut.TestReturn{
				Score: -1,
				Error: sce.ErrScorecardInternal,
			},
		},
		{
			name:     "test inconclusive outcome",
			findings: append([]finding.Finding{workflow(finding.OutcomeFalse)}, noRegistryPackages()...),
			result: scut.TestReturn{
				Score:         checker.InconclusiveResultScore,
				NumberOfWarn:  1,
				NumberOfDebug: 4,
			},
		},
		{
			name: "test false outcome with wrong probes",
			findings: []finding.Finding{
				{
					Probe:   "wrongProbe",
					Outcome: finding.OutcomeFalse,
				},
			},
			result: scut.TestReturn{
				Score: -1,
				Error: sce.ErrScorecardInternal,
			},
		},
		{
			name:     "trusted publishing with provenance from repo",
			findings: withPackages(finding.OutcomeTrue, secureNPMPackage),
			result: scut.TestReturn{
				Score:        checker.MaxResultScore,
				NumberOfInfo: 5,
			},
		},
		{
			// Trusted publishing proves a CI publish even when Scorecard
			// doesn't recognize the workflow.
			name:     "trusted publishing with unrecognized workflow",
			findings: withPackages(finding.OutcomeFalse, secureNPMPackage),
			result: scut.TestReturn{
				Score:        checker.MaxResultScore,
				NumberOfInfo: 4,
				NumberOfWarn: 1,
			},
		},
		{
			name: "provenance with a token",
			findings: withPackages(finding.OutcomeTrue, registryPackage{
				name:            "provenance",
				trusted:         finding.OutcomeFalse,
				provenance:      finding.OutcomeTrue,
				contributor:     finding.OutcomeTrue,
				keepsProvenance: finding.OutcomeTrue,
			}),
			result: scut.TestReturn{
				Score:        8,
				NumberOfInfo: 4,
				NumberOfWarn: 1,
			},
		},
		{
			name:     "published from CI with a token",
			findings: withPackages(finding.OutcomeTrue, tokenNPMPackage),
			result: scut.TestReturn{
				Score:        5,
				NumberOfInfo: 3,
				NumberOfWarn: 2,
			},
		},
		{
			name:     "published by hand by a contributor",
			findings: withPackages(finding.OutcomeFalse, tokenNPMPackage),
			result: scut.TestReturn{
				Score:        2,
				NumberOfInfo: 2,
				NumberOfWarn: 3,
			},
		},
		{
			name: "published by hand by someone outside the project",
			findings: withPackages(finding.OutcomeFalse, registryPackage{
				name:             "outsider",
				trusted:          finding.OutcomeFalse,
				provenance:       finding.OutcomeFalse,
				provenanceReason: packageHasProvenanceFromRepo.ReasonMissing,
				contributor:      finding.OutcomeFalse,
				keepsProvenance:  finding.OutcomeTrue,
			}),
			result: scut.TestReturn{
				Score:        0,
				NumberOfInfo: 1,
				NumberOfWarn: 4,
			},
		},
		{
			name: "contributors unavailable is not penalized",
			findings: withPackages(finding.OutcomeTrue, registryPackage{
				name:             "unknown",
				trusted:          finding.OutcomeFalse,
				provenance:       finding.OutcomeFalse,
				provenanceReason: packageHasProvenanceFromRepo.ReasonMissing,
				contributor:      finding.OutcomeNotAvailable,
				keepsProvenance:  finding.OutcomeTrue,
			}),
			result: scut.TestReturn{
				Score:         5,
				NumberOfInfo:  2,
				NumberOfWarn:  2,
				NumberOfDebug: 1,
			},
		},
		{
			name: "provenance from a different repository",
			findings: withPackages(finding.OutcomeTrue, registryPackage{
				name:             "imposter",
				trusted:          finding.OutcomeTrue,
				provenance:       finding.OutcomeFalse,
				provenanceReason: packageHasProvenanceFromRepo.ReasonMismatch,
				contributor:      finding.OutcomeFalse,
				keepsProvenance:  finding.OutcomeTrue,
			}),
			result: scut.TestReturn{
				Score:        0,
				NumberOfInfo: 3,
				NumberOfWarn: 2,
			},
		},
		{
			name: "latest version dropped provenance",
			findings: withPackages(finding.OutcomeTrue, registryPackage{
				name:             "downgraded",
				trusted:          finding.OutcomeFalse,
				provenance:       finding.OutcomeFalse,
				provenanceReason: packageHasProvenanceFromRepo.ReasonMissing,
				contributor:      finding.OutcomeTrue,
				keepsProvenance:  finding.OutcomeFalse,
			}),
			result: scut.TestReturn{
				Score:        2,
				NumberOfInfo: 2,
				NumberOfWarn: 3,
			},
		},
		{
			name:     "weakest package sets the score",
			findings: withPackages(finding.OutcomeTrue, secureNPMPackage, tokenNPMPackage),
			result: scut.TestReturn{
				Score:        5,
				NumberOfInfo: 7,
				NumberOfWarn: 2,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dl := scut.TestDetailLogger{}
			got := Packaging(tt.name, tt.findings, &dl)
			scut.ValidateTestReturn(t, tt.name, &tt.result, &got, &dl)
		})
	}
}

func TestPackagingReason(t *testing.T) {
	t.Parallel()
	dl := scut.TestDetailLogger{}
	got := Packaging("Packaging",
		withPackages(finding.OutcomeTrue, secureNPMPackage, tokenNPMPackage), &dl)
	want := "2 registry package(s) checked; weakest is token: published with a long-lived token, no provenance"
	if diff := cmp.Diff(want, got.Reason); diff != "" {
		t.Errorf("reason mismatch (-want +got):\n%s", diff)
	}
}
