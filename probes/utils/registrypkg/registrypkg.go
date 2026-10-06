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

// Package registrypkg holds code shared by the probes that inspect how
// packages were published to their registry.
package registrypkg

import (
	"embed"
	"fmt"

	"github.com/ossf/scorecard/v5/checker"
	"github.com/ossf/scorecard/v5/finding"
	"github.com/ossf/scorecard/v5/probes/internal/utils/uerror"
)

// Finding values set on every registry package finding.
const (
	ValueSystem  = "system"
	ValuePackage = "package"
	ValueVersion = "version"
)

// Result is a probe's verdict on one package.
type Result struct {
	Values  map[string]string
	Text    string
	Outcome finding.Outcome
}

// Run returns one finding per registry package, using eval to judge each
// package, or a single OutcomeNotApplicable finding if there are none.
func Run(raw *checker.RawResults, efs embed.FS, probe string,
	eval func(p *checker.RegistryPackage) Result,
) ([]finding.Finding, string, error) {
	if raw == nil {
		return nil, "", fmt.Errorf("%w: raw", uerror.ErrNil)
	}

	pkgs := raw.PackagingResults.RegistryPackages
	if len(pkgs) == 0 {
		f, err := finding.NewNotApplicable(efs, probe, "no packages published to a supported registry", nil)
		if err != nil {
			return nil, probe, fmt.Errorf("create finding: %w", err)
		}
		return []finding.Finding{*f}, probe, nil
	}

	findings := make([]finding.Finding, 0, len(pkgs))
	for i := range pkgs {
		p := &pkgs[i]
		r := eval(p)
		f, err := finding.NewWith(efs, probe,
			fmt.Sprintf("%s package %s@%s: %s", p.System, p.Name, p.Version, r.Text), nil, r.Outcome)
		if err != nil {
			return nil, probe, fmt.Errorf("create finding: %w", err)
		}
		f = f.WithValue(ValueSystem, p.System).
			WithValue(ValuePackage, p.Name).
			WithValue(ValueVersion, p.Version)
		for k, v := range r.Values {
			f = f.WithValue(k, v)
		}
		findings = append(findings, *f)
	}
	return findings, probe, nil
}
