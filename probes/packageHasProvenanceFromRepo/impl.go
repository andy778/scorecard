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
	"embed"

	"github.com/ossf/scorecard/v5/checker"
	"github.com/ossf/scorecard/v5/finding"
	"github.com/ossf/scorecard/v5/internal/checknames"
	"github.com/ossf/scorecard/v5/internal/probes"
	"github.com/ossf/scorecard/v5/probes/utils/registrypkg"
)

func init() {
	probes.MustRegister(Probe, Run, []checknames.CheckName{checknames.Packaging})
}

//go:embed *.yml
var fs embed.FS

const (
	Probe = "packageHasProvenanceFromRepo"

	// ValueSourceRepository is the repository the provenance says the package was built from.
	ValueSourceRepository = "sourceRepository"
	ValueWorkflow         = "workflow"
	ValueCommit           = "commit"
	// ValueReason is "missing" or "mismatch" on OutcomeFalse.
	ValueReason    = "reason"
	ReasonMissing  = "missing"
	ReasonMismatch = "mismatch"
)

func Run(raw *checker.RawResults) ([]finding.Finding, string, error) {
	//nolint:wrapcheck
	return registrypkg.Run(raw, fs, Probe, func(p *checker.RegistryPackage) registrypkg.Result {
		prov := p.Provenance
		if prov == nil {
			return registrypkg.Result{
				Outcome: finding.OutcomeFalse,
				Text:    "no provenance attestation",
				Values:  map[string]string{ValueReason: ReasonMissing},
			}
		}
		values := map[string]string{
			ValueSourceRepository: prov.SourceRepository,
			ValueWorkflow:         prov.Workflow,
			ValueCommit:           prov.Commit,
		}
		if !prov.MatchesRepo {
			values[ValueReason] = ReasonMismatch
			return registrypkg.Result{
				Outcome: finding.OutcomeFalse,
				Text:    "provenance says it was built from a different repository: " + prov.SourceRepository,
				Values:  values,
			}
		}
		return registrypkg.Result{
			Outcome: finding.OutcomeTrue,
			Text:    "provenance shows it was built by " + prov.Workflow + " in this repository",
			Values:  values,
		}
	})
}
