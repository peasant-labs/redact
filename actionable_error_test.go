package redact

import (
	_ "embed"
	"errors"
	"fmt"
	"regexp"
	"testing"

	"gopkg.in/yaml.v3"
)

//go:embed testdata/actionable_errors.yaml
var actionableErrorFixtureData []byte

type actionableErrorCaseKind string

const (
	actionableErrorRenderKind              actionableErrorCaseKind = "render"
	actionableErrorInvalidLevelKind        actionableErrorCaseKind = "invalid_level"
	actionableErrorInvalidRuleCategoryKind actionableErrorCaseKind = "invalid_rule_category"
	actionableErrorInvalidRuleMinimumKind  actionableErrorCaseKind = "invalid_rule_minimum"
	actionableErrorWeakRuleMinimumKind     actionableErrorCaseKind = "weak_rule_minimum"
	actionableErrorEmptyPatternIDKind      actionableErrorCaseKind = "empty_pattern_id"
	actionableErrorInvalidPatternCatKind   actionableErrorCaseKind = "invalid_pattern_category"
	actionableErrorInvalidPatternRegexKind actionableErrorCaseKind = "invalid_pattern_regex"
	actionableErrorMaximumUnavailableKind  actionableErrorCaseKind = "maximum_unavailable"
	actionableErrorMalformedFixtureKind    actionableErrorCaseKind = "false_positive_malformed_yaml"
	actionableErrorInvalidFixtureLevelKind actionableErrorCaseKind = "false_positive_invalid_level"
)

func (k actionableErrorCaseKind) isValid() bool {
	switch k {
	case actionableErrorRenderKind,
		actionableErrorInvalidLevelKind,
		actionableErrorInvalidRuleCategoryKind,
		actionableErrorInvalidRuleMinimumKind,
		actionableErrorWeakRuleMinimumKind,
		actionableErrorEmptyPatternIDKind,
		actionableErrorInvalidPatternCatKind,
		actionableErrorInvalidPatternRegexKind,
		actionableErrorMaximumUnavailableKind,
		actionableErrorMalformedFixtureKind,
		actionableErrorInvalidFixtureLevelKind:
		return true
	default:
		return false
	}
}

type actionableErrorFieldsFixture struct {
	What  string `yaml:"what"`
	Why   string `yaml:"why"`
	Where string `yaml:"where"`
	When  string `yaml:"when"`
	Means string `yaml:"means"`
	Fix   string `yaml:"fix"`
}

type actionableErrorFixture struct {
	Name     string                       `yaml:"name"`
	Kind     actionableErrorCaseKind      `yaml:"kind"`
	Input    string                       `yaml:"input"`
	Expected actionableErrorFieldsFixture `yaml:"expected"`
	Rendered string                       `yaml:"rendered"`
	Cause    string                       `yaml:"cause"`
}

type actionableErrorFixtures struct {
	Cases []actionableErrorFixture `yaml:"cases"`
}

func loadActionableErrorFixtures() ([]actionableErrorFixture, error) {
	var fixtures actionableErrorFixtures
	if err := yaml.Unmarshal(actionableErrorFixtureData, &fixtures); err != nil {
		return nil, fmt.Errorf("redact: could not parse testdata/actionable_errors.yaml while loading constructor-error cases: %w; actionable-error coverage cannot run; fix the YAML syntax", err)
	}
	if len(fixtures.Cases) != 11 {
		return nil, fmt.Errorf("redact: testdata/actionable_errors.yaml defines %d cases, want 11 constructor, loader, and rendering branches; exact actionable-error coverage is incomplete or duplicated; restore one case per supported kind", len(fixtures.Cases))
	}
	seenNames := make(map[string]struct{}, len(fixtures.Cases))
	seenKinds := make(map[actionableErrorCaseKind]struct{}, len(fixtures.Cases))
	for i, fixture := range fixtures.Cases {
		if fixture.Name == "" || !fixture.Kind.isValid() || fixture.Expected.What == "" ||
			fixture.Expected.Why == "" || fixture.Expected.Where == "" || fixture.Expected.When == "" ||
			fixture.Expected.Means == "" || fixture.Expected.Fix == "" || fixture.Rendered == "" {
			return nil, fmt.Errorf("redact: actionable-error case cases[%d] is incomplete; name, valid kind, every expected field, and rendered are required; exact diagnostics cannot be verified; fill in the missing fixture values", i)
		}
		if (fixture.Kind == actionableErrorMalformedFixtureKind || fixture.Kind == actionableErrorInvalidFixtureLevelKind) && fixture.Input == "" {
			return nil, fmt.Errorf("redact: actionable-error case cases[%d] kind %q has no input; loader diagnostics cannot be exercised; provide the exact YAML bytes that must fail", i, fixture.Kind)
		}
		if _, duplicate := seenNames[fixture.Name]; duplicate {
			return nil, fmt.Errorf("redact: actionable-error case name %q is duplicated; subtest identity is ambiguous; give every case a unique name", fixture.Name)
		}
		seenNames[fixture.Name] = struct{}{}
		if _, duplicate := seenKinds[fixture.Kind]; duplicate {
			return nil, fmt.Errorf("redact: actionable-error kind %q is duplicated; exact branch membership is ambiguous; keep one load-bearing case per kind", fixture.Kind)
		}
		seenKinds[fixture.Kind] = struct{}{}
	}
	return fixtures.Cases, nil
}

func TestActionableErrors(t *testing.T) {
	fixtures, err := loadActionableErrorFixtures()
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range fixtures {
		fixture := fixture
		t.Run(fixture.Name, func(t *testing.T) {
			err := produceActionableError(fixture)
			if err == nil {
				t.Fatalf("%s produced nil error; the failure branch must remain fail-closed", fixture.Kind)
			}
			var actionable *actionableError
			if !errors.As(err, &actionable) {
				t.Fatalf("%s error type = %T, want *actionableError", fixture.Kind, err)
			}
			assertActionableErrorFields(t, actionable, fixture.Expected)
			if got := actionable.Error(); got != fixture.Rendered {
				t.Errorf("actionableError.Error() =\n%s\nwant\n%s", got, fixture.Rendered)
			}
			cause := errors.Unwrap(actionable)
			if fixture.Cause == "" {
				if cause != nil {
					t.Errorf("errors.Unwrap(actionableError) = %v, want nil", cause)
				}
			} else if cause == nil || cause.Error() != fixture.Cause {
				t.Errorf("errors.Unwrap(actionableError) = %v, want exact cause %q", cause, fixture.Cause)
			}
		})
	}
}

func produceActionableError(fixture actionableErrorFixture) error {
	switch fixture.Kind {
	case actionableErrorRenderKind:
		return &actionableError{
			what: fixture.Expected.What, why: fixture.Expected.Why, where: fixture.Expected.Where,
			when: fixture.Expected.When, means: fixture.Expected.Means, fix: fixture.Expected.Fix,
			cause: errors.New("fixture root cause"),
		}
	case actionableErrorInvalidLevelKind:
		_, err := NewRedactor(RedactionLevel("unsupported"), nil, XDGPaths{})
		return err
	case actionableErrorInvalidRuleCategoryKind:
		return validateRuleActivationMetadata([]Rule{{ID: "fixture_rule", Category: Category("unknown"), Pattern: regexp.MustCompile("fixture")}})
	case actionableErrorInvalidRuleMinimumKind:
		return validateRuleActivationMetadata([]Rule{{ID: "fixture_rule", Category: CategoryProject, MinimumLevel: RedactionLevel("unsupported"), Pattern: regexp.MustCompile("fixture")}})
	case actionableErrorWeakRuleMinimumKind:
		return validateRuleActivationMetadata([]Rule{{ID: "fixture_rule", Category: CategoryProject, MinimumLevel: Minimal, Pattern: regexp.MustCompile("fixture")}})
	case actionableErrorEmptyPatternIDKind:
		_, err := NewRedactor(Standard, []UserPattern{{Category: CategoryProject, Pattern: "fixture", Replacement: "<PROJECT>"}}, XDGPaths{})
		return err
	case actionableErrorInvalidPatternCatKind:
		_, err := NewRedactor(Standard, []UserPattern{{ID: "fixture_pattern", Category: Category("unknown"), Pattern: "fixture", Replacement: "<PROJECT>"}}, XDGPaths{})
		return err
	case actionableErrorInvalidPatternRegexKind:
		_, err := NewRedactor(Standard, []UserPattern{{ID: "fixture_pattern", Category: CategoryProject, Pattern: "[invalid", Replacement: "<PROJECT>"}}, XDGPaths{})
		return err
	case actionableErrorMaximumUnavailableKind:
		return validateMaximumAvailability(Maximum, false)
	case actionableErrorMalformedFixtureKind, actionableErrorInvalidFixtureLevelKind:
		_, err := loadFalsePositiveFixtures([]byte(fixture.Input))
		return err
	default:
		return fmt.Errorf("unsupported actionable-error fixture kind %q", fixture.Kind)
	}
}

func assertActionableErrorFields(t *testing.T, got *actionableError, expected actionableErrorFieldsFixture) {
	t.Helper()
	if got.what != expected.What || got.why != expected.Why || got.where != expected.Where ||
		got.when != expected.When || got.means != expected.Means || got.fix != expected.Fix {
		t.Errorf("actionableError fields = %+v, want %+v", got, expected)
	}
}
