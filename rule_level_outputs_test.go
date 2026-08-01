package redact

import (
	_ "embed"
	"fmt"
	"testing"

	"gopkg.in/yaml.v3"
)

//go:embed testdata/rule_level_outputs.yaml
var ruleLevelOutputsData []byte

type ruleLevelExpectation struct {
	Active bool   `yaml:"active"`
	Output string `yaml:"output"`
}

type ruleLevelExpectations struct {
	Minimal  ruleLevelExpectation `yaml:"minimal"`
	Standard ruleLevelExpectation `yaml:"standard"`
	Maximum  ruleLevelExpectation `yaml:"maximum"`
}

type ruleLevelOutputFixture struct {
	Name                string                `yaml:"name"`
	RuleID              string                `yaml:"ruleId"`
	Control             ruleLevelControl      `yaml:"control"`
	Category            Category              `yaml:"category"`
	MinimumLevel        RedactionLevel        `yaml:"minimumLevel"`
	Input               string                `yaml:"input"`
	PanicFallbackOutput string                `yaml:"panicFallbackOutput"`
	Expectations        ruleLevelExpectations `yaml:"expectations"`
}

type ruleLevelControl string

const (
	ordinaryEmailControl           ruleLevelControl = "ordinary_email"
	gitEmailWithoutPathControl     ruleLevelControl = "git_email_without_remote_path"
	gitEmailFollowedByProseControl ruleLevelControl = "git_email_followed_by_prose"
	unsupportedSCPPrefixControl    ruleLevelControl = "unsupported_scp_remote_email_prefix"
)

func (c ruleLevelControl) isValid() bool {
	switch c {
	case ordinaryEmailControl, gitEmailWithoutPathControl, gitEmailFollowedByProseControl, unsupportedSCPPrefixControl:
		return true
	default:
		return false
	}
}

func TestRedactText_PanicRecoveryUsesMaximumRulePrecedence(t *testing.T) {
	fixtures, err := loadRuleLevelOutputFixtures()
	if err != nil {
		t.Fatal(err)
	}

	var recoveryFixture *ruleLevelOutputFixture
	for i := range fixtures {
		if fixtures[i].PanicFallbackOutput == "" {
			continue
		}
		if recoveryFixture != nil {
			t.Fatalf("testdata/rule_level_outputs.yaml defines more than one panicFallbackOutput; keep one load-bearing recovery case so the induced panic is unambiguous")
		}
		recoveryFixture = &fixtures[i]
	}
	if recoveryFixture == nil {
		t.Fatal("testdata/rule_level_outputs.yaml has no panicFallbackOutput; add one case that proves panic recovery applies Maximum-only rules before broader matches")
	}

	originalRules := Rules
	Rules = append([]Rule(nil), Rules...)
	t.Cleanup(func() { Rules = originalRules })

	emailRule := findRuleByID("email")
	if emailRule == nil {
		t.Fatal("compiled email rule is missing; restore it so the fixture can induce a panic in its post-match filter")
	}
	for i := range Rules {
		if Rules[i].ID == emailRule.ID {
			Rules[i].FilterFn = func(string, string, int) bool {
				panic("fixture-induced filter failure")
			}
			break
		}
	}

	r := mustNewRedactor(t, Standard, nil)
	if got := r.RedactText(recoveryFixture.Input); got != recoveryFixture.PanicFallbackOutput {
		t.Fatalf("RedactText panic recovery output = %q, want %q; the Maximum fallback must redact the full sensitive construct", got, recoveryFixture.PanicFallbackOutput)
	}
}

type ruleLevelOutputFixtures struct {
	Cases []ruleLevelOutputFixture `yaml:"cases"`
}

func loadRuleLevelOutputFixtures() ([]ruleLevelOutputFixture, error) {
	var fixtures ruleLevelOutputFixtures
	if err := yaml.Unmarshal(ruleLevelOutputsData, &fixtures); err != nil {
		return nil, fmt.Errorf("redact: failed to parse testdata/rule_level_outputs.yaml while loading rule-level output fixtures: %w; the activation and output tests cannot run; fix the YAML syntax", err)
	}
	expectedCount := len(projectRules) + 4
	if len(fixtures.Cases) != expectedCount {
		return nil, fmt.Errorf("redact: testdata/rule_level_outputs.yaml loaded %d cases, want %d; every compiled project rule and all four SSH/email overlap controls must remain covered exactly once", len(fixtures.Cases), expectedCount)
	}
	projectIDs := make(map[string]struct{}, len(projectRules))
	for _, rule := range projectRules {
		if _, duplicate := projectIDs[rule.ID]; duplicate {
			return nil, fmt.Errorf("redact: compiled project rule ID %q is duplicated; exact rule-level membership is ambiguous; keep every project rule ID unique", rule.ID)
		}
		projectIDs[rule.ID] = struct{}{}
	}
	seenNames := make(map[string]struct{}, len(fixtures.Cases))
	seenProjectRules := make(map[string]struct{}, len(projectRules))
	seenControls := make(map[ruleLevelControl]struct{}, 4)
	for i, fixture := range fixtures.Cases {
		if fixture.Name == "" || fixture.RuleID == "" || fixture.Input == "" {
			return nil, fmt.Errorf("redact: incomplete fixture at cases[%d] in testdata/rule_level_outputs.yaml while loading rule-level output fixtures: name, ruleId, and input must be non-empty; the activation and output tests cannot identify or exercise this case; fill in the missing field", i)
		}
		if !fixture.Category.IsValid() {
			return nil, fmt.Errorf("redact: invalid category %q in testdata/rule_level_outputs.yaml case %q while loading rule-level output fixtures: expected secrets, pii, paths, or project; the test cannot verify semantic classification; fix the fixture category", fixture.Category, fixture.Name)
		}
		if fixture.MinimumLevel != "" && !fixture.MinimumLevel.IsValid() {
			return nil, fmt.Errorf("redact: invalid minimumLevel %q in testdata/rule_level_outputs.yaml case %q while loading rule-level output fixtures: expected minimal, standard, maximum, or empty for the category default; the test cannot verify activation policy; fix the fixture minimumLevel", fixture.MinimumLevel, fixture.Name)
		}
		if _, duplicate := seenNames[fixture.Name]; duplicate {
			return nil, fmt.Errorf("redact: fixture name %q is duplicated in testdata/rule_level_outputs.yaml; subtest identity is ambiguous; give every case a unique name", fixture.Name)
		}
		seenNames[fixture.Name] = struct{}{}
		if _, isProjectRule := projectIDs[fixture.RuleID]; isProjectRule {
			if fixture.Name != fixture.RuleID || fixture.Control != "" {
				return nil, fmt.Errorf("redact: project-rule fixture %q must use the exact compiled rule ID as its name and leave control empty; exact registry membership cannot be proven; align the fixture identity", fixture.Name)
			}
			if _, duplicate := seenProjectRules[fixture.RuleID]; duplicate {
				return nil, fmt.Errorf("redact: project rule %q appears more than once in testdata/rule_level_outputs.yaml; exact registry membership is ambiguous; keep one level-output case per project rule", fixture.RuleID)
			}
			seenProjectRules[fixture.RuleID] = struct{}{}
			continue
		}
		if fixture.RuleID != "email" || !fixture.Control.isValid() || fixture.Name != string(fixture.Control) {
			return nil, fmt.Errorf("redact: non-project fixture %q must identify the email rule and one canonical overlap control with a matching name; the corpus contains an unexpected member; fix ruleId, control, or name", fixture.Name)
		}
		if _, duplicate := seenControls[fixture.Control]; duplicate {
			return nil, fmt.Errorf("redact: email overlap control %q appears more than once; exact control membership is ambiguous; keep one case per control", fixture.Control)
		}
		seenControls[fixture.Control] = struct{}{}
	}
	for ruleID := range projectIDs {
		if _, ok := seenProjectRules[ruleID]; !ok {
			return nil, fmt.Errorf("redact: testdata/rule_level_outputs.yaml is missing compiled project rule %q; exact rule-level membership is incomplete; add its activation and output case", ruleID)
		}
	}
	for _, control := range []ruleLevelControl{ordinaryEmailControl, gitEmailWithoutPathControl, gitEmailFollowedByProseControl, unsupportedSCPPrefixControl} {
		if _, ok := seenControls[control]; !ok {
			return nil, fmt.Errorf("redact: testdata/rule_level_outputs.yaml is missing email overlap control %q; exact control membership is incomplete; restore the case", control)
		}
	}
	return fixtures.Cases, nil
}

func TestRuleLevelOutputs(t *testing.T) {
	fixtures, err := loadRuleLevelOutputFixtures()
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range fixtures {
		fixture := fixture
		t.Run(fixture.Name, func(t *testing.T) {
			rule := findRuleByID(fixture.RuleID)
			if rule == nil {
				t.Fatalf("fixture ruleId %q does not identify a compiled rule; fix testdata/rule_level_outputs.yaml or restore the rule", fixture.RuleID)
			}
			if rule.Category != fixture.Category {
				t.Errorf("rule %q category = %q, want fixture category %q", fixture.RuleID, rule.Category, fixture.Category)
			}
			if rule.MinimumLevel != fixture.MinimumLevel {
				t.Errorf("rule %q MinimumLevel = %q, want fixture minimumLevel %q", fixture.RuleID, rule.MinimumLevel, fixture.MinimumLevel)
			}

			assertRuleLevelOutput(t, fixture, Minimal, fixture.Expectations.Minimal)
			assertRuleLevelOutput(t, fixture, Standard, fixture.Expectations.Standard)
			assertRuleLevelOutput(t, fixture, Maximum, fixture.Expectations.Maximum)
		})
	}
}

func assertRuleLevelOutput(t *testing.T, fixture ruleLevelOutputFixture, level RedactionLevel, expectation ruleLevelExpectation) {
	t.Helper()
	t.Run(level.String(), func(t *testing.T) {
		r := mustNewRedactor(t, level, nil)
		matches := r.Detect(fixture.Input)
		active := false
		for _, match := range matches {
			if match.Rule == fixture.RuleID {
				active = true
				break
			}
		}
		if active != expectation.Active {
			t.Errorf("rule %q active at %s = %v, want %v (matches: %+v)", fixture.RuleID, level, active, expectation.Active, matches)
		}
		if got := r.RedactText(fixture.Input); got != expectation.Output {
			t.Errorf("rule %q RedactText at %s = %q, want %q", fixture.RuleID, level, got, expectation.Output)
		}
	})
}
