package redact

import (
	_ "embed"
	"fmt"
	"testing"

	"gopkg.in/yaml.v3"
)

//go:embed testdata/user_pattern_activation.yaml
var userPatternActivationData []byte

type userPatternLevelOutputs struct {
	Minimal  string `yaml:"minimal"`
	Standard string `yaml:"standard"`
	Maximum  string `yaml:"maximum"`
}

type userPatternActivationFixture struct {
	Name         string                  `yaml:"name"`
	Pattern      UserPattern             `yaml:"pattern"`
	Input        string                  `yaml:"input"`
	Outputs      userPatternLevelOutputs `yaml:"outputs"`
	DefaultLevel RedactionLevel          `yaml:"defaultLevel"`
}

type userPatternActivationFixtures struct {
	Cases []userPatternActivationFixture `yaml:"cases"`
}

func loadUserPatternActivationFixtures() ([]userPatternActivationFixture, error) {
	var fixtures userPatternActivationFixtures
	if err := yaml.Unmarshal(userPatternActivationData, &fixtures); err != nil {
		return nil, fmt.Errorf("redact: could not parse pkg/redact/testdata/user_pattern_activation.yaml while loading user-pattern level cases: %w; activation coverage cannot run; fix the YAML syntax", err)
	}
	if len(fixtures.Cases) != 1 {
		return nil, fmt.Errorf("redact: pkg/redact/testdata/user_pattern_activation.yaml defines %d cases, want one load-bearing CategoryProject case; the Standard-default configuration limitation must remain explicit; restore exactly one case", len(fixtures.Cases))
	}
	fixture := fixtures.Cases[0]
	if fixture.Name == "" || fixture.Pattern.ID == "" || fixture.Pattern.Pattern == "" || fixture.Pattern.Replacement == "" || fixture.Input == "" ||
		fixture.Outputs.Minimal == "" || fixture.Outputs.Standard == "" || fixture.Outputs.Maximum == "" {
		return nil, fmt.Errorf("redact: CategoryProject user-pattern fixture is incomplete; name, all pattern fields, input, and all level outputs are required; exact activation cannot be verified; fill in the missing values")
	}
	if fixture.Pattern.Category != CategoryProject || fixture.DefaultLevel != Standard {
		return nil, fmt.Errorf("redact: CategoryProject user-pattern fixture has category %q and defaultLevel %q, want project and standard; the current configuration limitation is misstated; keep user patterns on the category default until the config exposes a per-pattern minimum", fixture.Pattern.Category, fixture.DefaultLevel)
	}
	return fixtures.Cases, nil
}

// TestUserPatternCategoryProjectActivation documents the current configuration
// boundary: user patterns can choose a semantic category, but cannot set their
// own MinimumLevel, so CategoryProject inherits Standard and cannot opt into a
// Maximum-only policy through config.
func TestUserPatternCategoryProjectActivation(t *testing.T) {
	fixtures, err := loadUserPatternActivationFixtures()
	if err != nil {
		t.Fatal(err)
	}
	fixture := fixtures[0]
	for _, level := range []RedactionLevel{Minimal, Standard, Maximum} {
		level := level
		t.Run(level.String(), func(t *testing.T) {
			r := mustNewRedactor(t, level, []UserPattern{fixture.Pattern})
			var want string
			switch level {
			case Minimal:
				want = fixture.Outputs.Minimal
			case Standard:
				want = fixture.Outputs.Standard
			case Maximum:
				want = fixture.Outputs.Maximum
			}
			if got := r.RedactText(fixture.Input); got != want {
				t.Errorf("CategoryProject user pattern at %s produced %q, want %q", level, got, want)
			}
		})
	}
}
