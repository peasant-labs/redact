package redact

import (
	_ "embed"
	"fmt"
	"testing"

	"gopkg.in/yaml.v3"
)

//go:embed testdata/project_rules.yaml
var projectRuleFixtureData []byte

type projectRuleBoundaryCase struct {
	Name        string `yaml:"name"`
	Input       string `yaml:"input"`
	ShouldMatch bool   `yaml:"shouldMatch"`
}

type projectRuleFixture struct {
	RuleID string                    `yaml:"ruleId"`
	Cases  []projectRuleBoundaryCase `yaml:"cases"`
}

type projectResidueFixture struct {
	Name   string `yaml:"name"`
	RuleID string `yaml:"ruleId"`
	Input  string `yaml:"input"`
}

type projectRuleFixtures struct {
	Rules    []projectRuleFixture    `yaml:"rules"`
	Residues []projectResidueFixture `yaml:"residues"`
}

func loadProjectRuleFixtures() (projectRuleFixtures, error) {
	var fixtures projectRuleFixtures
	if err := yaml.Unmarshal(projectRuleFixtureData, &fixtures); err != nil {
		return projectRuleFixtures{}, fmt.Errorf("redact: could not parse testdata/project_rules.yaml while loading project-rule boundary and residue cases: %w; the project-rule corpus cannot run; fix the YAML syntax", err)
	}
	if len(fixtures.Rules) != len(projectRules) {
		return projectRuleFixtures{}, fmt.Errorf("redact: testdata/project_rules.yaml defines %d rule groups, want %d compiled project rules; boundary coverage is incomplete or duplicated; define exactly one group per compiled project rule", len(fixtures.Rules), len(projectRules))
	}
	if len(fixtures.Residues) != len(projectRules) {
		return projectRuleFixtures{}, fmt.Errorf("redact: testdata/project_rules.yaml defines %d residue cases, want %d compiled project rules; residue coverage is incomplete or duplicated; define exactly one residue case per compiled project rule", len(fixtures.Residues), len(projectRules))
	}

	compiled := make(map[string]struct{}, len(projectRules))
	for _, rule := range projectRules {
		if _, duplicate := compiled[rule.ID]; duplicate {
			return projectRuleFixtures{}, fmt.Errorf("redact: compiled project rule ID %q is duplicated; registry membership is ambiguous; keep each project rule ID unique", rule.ID)
		}
		compiled[rule.ID] = struct{}{}
	}

	seenRules := make(map[string]struct{}, len(fixtures.Rules))
	seenCaseNames := make(map[string]struct{})
	for i, rule := range fixtures.Rules {
		if rule.RuleID == "" || len(rule.Cases) == 0 {
			return projectRuleFixtures{}, fmt.Errorf("redact: rule group rules[%d] in testdata/project_rules.yaml is incomplete; ruleId and at least one case are required; the corpus cannot identify or exercise the rule; fill in the missing values", i)
		}
		if _, ok := compiled[rule.RuleID]; !ok {
			return projectRuleFixtures{}, fmt.Errorf("redact: fixture ruleId %q has no compiled project rule; the boundary corpus and production registry disagree; fix the fixture or restore the rule", rule.RuleID)
		}
		if _, duplicate := seenRules[rule.RuleID]; duplicate {
			return projectRuleFixtures{}, fmt.Errorf("redact: fixture ruleId %q appears more than once; exact registry membership cannot be proven; merge its cases into one rule group", rule.RuleID)
		}
		seenRules[rule.RuleID] = struct{}{}

		hasMatch := false
		hasNonMatch := false
		for j, c := range rule.Cases {
			if c.Name == "" || c.Input == "" {
				return projectRuleFixtures{}, fmt.Errorf("redact: rules[%d].cases[%d] for %q is incomplete; name and input are required; the boundary case cannot run; fill in the missing values", i, j, rule.RuleID)
			}
			qualifiedName := rule.RuleID + "/" + c.Name
			if _, duplicate := seenCaseNames[qualifiedName]; duplicate {
				return projectRuleFixtures{}, fmt.Errorf("redact: boundary case name %q is duplicated; subtest identity is ambiguous; give every case within a rule a unique name", qualifiedName)
			}
			seenCaseNames[qualifiedName] = struct{}{}
			hasMatch = hasMatch || c.ShouldMatch
			hasNonMatch = hasNonMatch || !c.ShouldMatch
		}
		if !hasMatch || !hasNonMatch {
			return projectRuleFixtures{}, fmt.Errorf("redact: fixture ruleId %q must include both matching and non-matching boundary cases; the corpus cannot prove both detection and restraint; add the missing case kind", rule.RuleID)
		}
	}

	seenResidues := make(map[string]struct{}, len(fixtures.Residues))
	seenResidueNames := make(map[string]struct{}, len(fixtures.Residues))
	for i, residue := range fixtures.Residues {
		if residue.Name == "" || residue.RuleID == "" || residue.Input == "" {
			return projectRuleFixtures{}, fmt.Errorf("redact: residues[%d] in testdata/project_rules.yaml is incomplete; name, ruleId, and input are required; the residue case cannot run; fill in the missing values", i)
		}
		if _, duplicate := seenResidueNames[residue.Name]; duplicate {
			return projectRuleFixtures{}, fmt.Errorf("redact: residue case name %q is duplicated; subtest identity is ambiguous; give every residue case a unique name", residue.Name)
		}
		seenResidueNames[residue.Name] = struct{}{}
		if _, duplicate := seenResidues[residue.RuleID]; duplicate {
			return projectRuleFixtures{}, fmt.Errorf("redact: residue ruleId %q appears more than once; exact residue membership cannot be proven; keep one load-bearing case per project residue rule", residue.RuleID)
		}
		seenResidues[residue.RuleID] = struct{}{}
	}
	for ruleID := range compiled {
		residueID := "residue_" + ruleID
		if _, ok := seenResidues[residueID]; !ok {
			return projectRuleFixtures{}, fmt.Errorf("redact: testdata/project_rules.yaml is missing residue case %q; project-rule residue coverage is incomplete; add one load-bearing case", residueID)
		}
	}

	return fixtures, nil
}

func TestProjectRuleBoundaries(t *testing.T) {
	fixtures, err := loadProjectRuleFixtures()
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range fixtures.Rules {
		rule := rule
		t.Run(rule.RuleID, func(t *testing.T) {
			for _, c := range rule.Cases {
				c := c
				t.Run(c.Name, func(t *testing.T) {
					if got := matchesRule(t, rule.RuleID, c.Input); got != c.ShouldMatch {
						t.Errorf("matchesRule(%q, %q) = %v, want %v", rule.RuleID, c.Input, got, c.ShouldMatch)
					}
				})
			}
		})
	}
}

func TestProjectResidueRules(t *testing.T) {
	fixtures, err := loadProjectRuleFixtures()
	if err != nil {
		t.Fatal(err)
	}
	detector := NewResidueDetector()
	for _, fixture := range fixtures.Residues {
		fixture := fixture
		t.Run(fixture.Name, func(t *testing.T) {
			warnings := detector.Scan(fixture.Input)
			for _, warning := range warnings {
				if warning.RuleID == fixture.RuleID {
					return
				}
			}
			t.Errorf("residue rule %q did not trigger on input %q; got warnings %v", fixture.RuleID, fixture.Input, warnings)
		})
	}
}

func TestVersion(t *testing.T) {
	if got := Version(); got != RuleSetVersion {
		t.Errorf("Version() = %q, want %q", got, RuleSetVersion)
	}
	if got := Version(); got != "3.1.1" {
		t.Errorf("Version() = %q, want %q", got, "3.1.1")
	}
}
