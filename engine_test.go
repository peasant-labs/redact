package redact

import (
	_ "embed"
	"errors"
	"regexp"
	"slices"
	"testing"

	"gopkg.in/yaml.v3"
)

//go:embed testdata/engine_configuration.yaml
var engineConfigurationData []byte

type engineNameFixture struct {
	Name  string     `yaml:"name"`
	Value string     `yaml:"value"`
	Want  engineName `yaml:"want"`
	Error bool       `yaml:"error"`
}

type engineConfigurationFixtures struct {
	Engines            []engineName        `yaml:"engines"`
	RequiredNames      []string            `yaml:"required_names"`
	Cases              []engineNameFixture `yaml:"cases"`
	ResidueOnlyPattern string              `yaml:"residue_only_pattern"`
}

func loadEngineConfigurationFixtures(t *testing.T) engineConfigurationFixtures {
	t.Helper()
	var fixtures engineConfigurationFixtures
	if err := yaml.Unmarshal(engineConfigurationData, &fixtures); err != nil {
		t.Fatal(err)
	}
	if err := requireFixtureNames("testdata/engine_configuration.yaml", "required_names", fixtures.RequiredNames, fixtureNames(fixtures.Cases, func(row engineNameFixture) string { return row.Name })); err != nil {
		t.Fatal(err)
	}
	if fixtures.ResidueOnlyPattern == "" {
		t.Fatal("restore residue_only_pattern in testdata/engine_configuration.yaml to exercise compiler isolation")
	}
	return fixtures
}

func TestEngineIdentityRegistry(t *testing.T) {
	fixtures := loadEngineConfigurationFixtures(t)
	if got := AllEngines(); !slices.Equal(got, fixtures.Engines) {
		t.Fatalf("AllEngines = %v, want ordered membership %v", got, fixtures.Engines)
	}
	names := AllEngines()
	names[0] = "modified"
	if !slices.Equal(AllEngines(), fixtures.Engines) {
		t.Fatal("mutating AllEngines result changed the identity registry")
	}
	for _, row := range fixtures.Cases {
		t.Run(row.Name, func(t *testing.T) {
			got, err := NewEngineName(row.Value)
			if (err != nil) != row.Error || got != row.Want {
				t.Fatalf("NewEngineName(%q) = %q, %v; want %q, error=%v", row.Value, got, err, row.Want, row.Error)
			}
		})
	}
}

func TestEngineDefaultRemainsStdlib(t *testing.T) {
	r, err := NewRedactor(Standard, nil, XDGPaths{})
	if err != nil {
		t.Fatal(err)
	}
	defaultRedactor := r.(*DefaultRedactor)
	if defaultRedactor.engineName != engineGoRegexp || defaultRedactor.patterns != nil {
		t.Fatal("NewRedactor must reuse the original stdlib patterns by default")
	}
	if selectEngine().Identity() != engineGoRegexp || engineGoRegexp != "go-regexp" || engineGoRE2 != "go-re2" {
		t.Fatal("engine identities or stdlib default changed")
	}
}

type rejectingEngine struct {
	goRegexpEngine
	err error
}

func (e rejectingEngine) Compile(string) (compiled, error) { return nil, e.err }

func TestEngineCompileFailureRefusesConstruction(t *testing.T) {
	cause := errors.New("engine compiler unavailable")
	e := rejectingEngine{err: cause}
	if r, err := newRedactorWithEngine(e, Standard, nil, XDGPaths{}); r != nil || !errors.Is(err, cause) {
		t.Fatalf("redactor = %v, %v; want no partial redactor and wrapped compiler error", r, err)
	}
	if p, err := newTitlePipelineWithEngine(e); p != nil || !errors.Is(err, cause) {
		t.Fatalf("title pipeline = %v, %v; want no partial pipeline and wrapped compiler error", p, err)
	}
}

type residueRejectingEngine struct {
	goRegexpEngine
	rejected string
	err      error
}

func (e residueRejectingEngine) Compile(pattern string) (compiled, error) {
	if pattern == e.rejected {
		return nil, e.err
	}
	return e.goRegexpEngine.Compile(pattern)
}

func TestEngineTitleCompilesOnlyTitleRules(t *testing.T) {
	fixtures := loadEngineConfigurationFixtures(t)
	pattern := regexp.MustCompile(fixtures.ResidueOnlyPattern)
	original := ResidueRules
	t.Cleanup(func() { ResidueRules = original })
	ResidueRules = append(slices.Clone(ResidueRules), ResidueRule{ID: "residue_construction_probe", Pattern: pattern})
	cause := errors.New("residue pattern refused")
	e := residueRejectingEngine{rejected: pattern.String(), err: cause}
	pipeline, err := newTitlePipelineWithEngine(e)
	if err != nil {
		t.Fatalf("title construction touched an unrelated residue pattern: %v", err)
	}
	if _, exists := pipeline.patterns[pattern]; exists {
		t.Fatal("title pattern set contains an unrelated residue pattern")
	}
	// Positive control: the redactor really does include advisory residue rules.
	if r, err := newRedactorWithEngine(e, Standard, nil, XDGPaths{}); r != nil || !errors.Is(err, cause) {
		t.Fatalf("redactor = %v, %v; want refusal from the residue compiler", r, err)
	}
}
