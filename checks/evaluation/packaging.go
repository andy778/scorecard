// Copyright 2021 OpenSSF Scorecard Authors
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

package evaluation

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ossf/scorecard/v5/checker"
	sce "github.com/ossf/scorecard/v5/errors"
	"github.com/ossf/scorecard/v5/finding"
	"github.com/ossf/scorecard/v5/probes/packageHasProvenanceFromRepo"
	"github.com/ossf/scorecard/v5/probes/packageKeepsProvenance"
	"github.com/ossf/scorecard/v5/probes/packagePublishedByRepoContributor"
	"github.com/ossf/scorecard/v5/probes/packagePublishedWithTrustedPublishing"
	"github.com/ossf/scorecard/v5/probes/packagedWithAutomatedWorkflow"
	"github.com/ossf/scorecard/v5/probes/utils/registrypkg"
)

// Points a registry package earns for each way it was published securely.
// They add up to checker.MaxResultScore.
//
// Whether the publisher is a repository contributor is reported, but not
// scored: registry and forge accounts aren't linked, and in a survey of new
// npm packages almost every mismatch was the same person under a slightly
// different username.
const (
	pointsPublishedFromCI      = 4
	pointsTrustedPublishing    = 2
	pointsProvenanceFromRepo   = 4
	penaltyProvenanceDowngrade = 3
)

// registryPackageResult collects the registry probes' outcomes for one package.
type registryPackageResult struct {
	name               string
	trustedPublishing  bool
	provenanceFromRepo bool
	provenanceMismatch bool
	provenanceDropped  bool
}

// Packaging applies the score policy for the Packaging check.
//
// Without registry packages the check scores as before: the maximum score if a
// packaging workflow is detected, inconclusive otherwise.
//
// When the project publishes packages to a supported registry, each package's
// latest version is scored on how it was published (see the points above),
// and the check's score is that of the weakest package.
func Packaging(name string,
	findings []finding.Finding,
	dl checker.DetailLogger,
) checker.CheckResult {
	expectedProbes := []string{
		packagedWithAutomatedWorkflow.Probe,
		packageHasProvenanceFromRepo.Probe,
		packageKeepsProvenance.Probe,
		packagePublishedByRepoContributor.Probe,
		packagePublishedWithTrustedPublishing.Probe,
	}

	if !finding.UniqueProbesEqual(findings, expectedProbes) {
		e := sce.WithMessage(sce.ErrScorecardInternal, "invalid probe results")
		return checker.CreateRuntimeErrorResult(name, e)
	}

	workflowDetected := false
	packages := map[string]*registryPackageResult{}
	for i := range findings {
		f := &findings[i]
		var logLevel checker.DetailType
		switch {
		case f.Probe == packagePublishedByRepoContributor.Probe && f.Outcome == finding.OutcomeFalse:
			// Informational only, see above.
			logLevel = checker.DetailInfo
		case f.Outcome == finding.OutcomeFalse:
			logLevel = checker.DetailWarn
		case f.Outcome == finding.OutcomeTrue:
			logLevel = checker.DetailInfo
		default:
			logLevel = checker.DetailDebug
		}
		checker.LogFinding(dl, f, logLevel)

		if f.Probe == packagedWithAutomatedWorkflow.Probe {
			if f.Outcome == finding.OutcomeTrue {
				workflowDetected = true
			}
			continue
		}
		if f.Probe == packagePublishedByRepoContributor.Probe ||
			(f.Outcome != finding.OutcomeTrue && f.Outcome != finding.OutcomeFalse) {
			continue
		}

		key := f.Values[registrypkg.ValueSystem] + "/" + f.Values[registrypkg.ValuePackage]
		p, ok := packages[key]
		if !ok {
			p = &registryPackageResult{name: f.Values[registrypkg.ValuePackage]}
			packages[key] = p
		}
		isTrue := f.Outcome == finding.OutcomeTrue
		switch f.Probe {
		case packagePublishedWithTrustedPublishing.Probe:
			p.trustedPublishing = isTrue
		case packageHasProvenanceFromRepo.Probe:
			p.provenanceFromRepo = isTrue
			p.provenanceMismatch = f.Values[packageHasProvenanceFromRepo.ValueReason] ==
				packageHasProvenanceFromRepo.ReasonMismatch
		case packageKeepsProvenance.Probe:
			p.provenanceDropped = !isTrue
		}
	}

	if len(packages) == 0 {
		if workflowDetected {
			return checker.CreateMaxScoreResult(name, "packaging workflow detected")
		}
		return checker.CreateInconclusiveResult(name, "packaging workflow not detected")
	}

	// Sort for a deterministic reason when packages tie.
	keys := make([]string, 0, len(packages))
	for k := range packages {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var weakest *registryPackageResult
	weakestScore := checker.MaxResultScore + 1
	var weakestGaps []string
	for _, k := range keys {
		p := packages[k]
		score, gaps := scoreRegistryPackage(p, workflowDetected)
		if score < weakestScore {
			weakest, weakestScore, weakestGaps = p, score, gaps
		}
	}

	reason := fmt.Sprintf("%d registry package(s) checked; all are published securely", len(packages))
	if len(weakestGaps) > 0 {
		reason = fmt.Sprintf("%d registry package(s) checked; weakest is %s: %s",
			len(packages), weakest.name, strings.Join(weakestGaps, ", "))
	}
	return checker.CreateResultWithScore(name, reason, weakestScore)
}

// scoreRegistryPackage returns a package's score and what it is missing.
func scoreRegistryPackage(p *registryPackageResult, workflowDetected bool) (int, []string) {
	if p.provenanceMismatch {
		return checker.MinResultScore, []string{"provenance points at a different repository"}
	}

	score := 0
	var gaps []string
	// Trusted publishing and provenance from this repo both prove a CI publish,
	// even when the workflow isn't one Scorecard recognizes.
	if workflowDetected || p.trustedPublishing || p.provenanceFromRepo {
		score += pointsPublishedFromCI
	} else {
		gaps = append(gaps, "not published from CI")
	}
	if p.trustedPublishing {
		score += pointsTrustedPublishing
	} else {
		gaps = append(gaps, "published with a long-lived token")
	}
	if p.provenanceFromRepo {
		score += pointsProvenanceFromRepo
	} else {
		gaps = append(gaps, "no provenance")
	}
	if p.provenanceDropped {
		score -= penaltyProvenanceDowngrade
		gaps = append(gaps, "earlier versions had provenance")
	}
	return max(score, checker.MinResultScore), gaps
}
