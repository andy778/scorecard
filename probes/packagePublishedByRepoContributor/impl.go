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
	Probe          = "packagePublishedByRepoContributor"
	ValuePublisher = "publisher"
)

func Run(raw *checker.RawResults) ([]finding.Finding, string, error) {
	//nolint:wrapcheck
	return registrypkg.Run(raw, fs, Probe, func(p *checker.RegistryPackage) registrypkg.Result {
		values := map[string]string{ValuePublisher: p.Publisher}
		switch {
		case p.Provenance != nil && p.Provenance.MatchesRepo:
			return registrypkg.Result{
				Outcome: finding.OutcomeTrue,
				Text:    "published by this repository's CI",
				Values:  values,
			}
		case p.PublisherIsContributor == nil:
			return registrypkg.Result{
				Outcome: finding.OutcomeNotAvailable,
				Text:    "could not compare publisher " + p.Publisher + " with the repository's contributors",
				Values:  values,
			}
		case *p.PublisherIsContributor:
			return registrypkg.Result{
				Outcome: finding.OutcomeTrue,
				Text:    "published by " + p.Publisher + ", who contributes to this repository",
				Values:  values,
			}
		default:
			return registrypkg.Result{
				Outcome: finding.OutcomeFalse,
				Text:    "published by " + p.Publisher + ", who isn't a contributor to this repository",
				Values:  values,
			}
		}
	})
}
