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
	Engines            []engineName          `yaml:"engines"`
	RequiredNames      []string              `yaml:"required_names"`
	Cases              []engineNameFixture   `yaml:"cases"`
	ResidueOnlyPattern string                `yaml:"residue_only_pattern"`
	Routing            engineRoutingFixtures `yaml:"routing"`
}

type engineRoutingFixtures struct {
	Patterns      []UserPattern       `yaml:"patterns"`
	XDGDataHome   string              `yaml:"xdg_data_home"`
	RequiredNames []string            `yaml:"required_names"`
	Cases         []engineRoutingCase `yaml:"cases"`
}

type engineRoutingCase struct {
	Name                string `yaml:"name"`
	Rule                string `yaml:"rule"`
	Input               string `yaml:"input"`
	Output              string `yaml:"output"`
	ReplacementOverride string `yaml:"replacement_override"`
	ExpectReplacement   bool   `yaml:"expect_replacement"`
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
	if err := requireFixtureNames("testdata/engine_configuration.yaml", "routing/required_names", fixtures.Routing.RequiredNames, fixtureNames(fixtures.Routing.Cases, func(row engineRoutingCase) string { return row.Name })); err != nil {
		t.Fatal(err)
	}
	if len(fixtures.Routing.Patterns) == 0 || fixtures.Routing.XDGDataHome == "" {
		t.Fatal("restore configured patterns and XDG data home to exercise both routing sources")
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
	if selectEngine().Identity() != engineGoRegexp || defaultRedactor.patterns != nil {
		t.Fatal("NewRedactor must reuse the original stdlib patterns by default")
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

// routingSpyEngine compiles real stdlib patterns and records calls per compiled
// entry, not per engine. Built-in scans cannot satisfy a configured/XDG check.
type routingSpyEngine struct{ goRegexpEngine }

func (e routingSpyEngine) Compile(pattern string) (compiled, error) {
	p, err := e.goRegexpEngine.Compile(pattern)
	if err != nil {
		return nil, err
	}
	return &routingSpyPattern{compiled: p}, nil
}

type routingSpyPattern struct {
	compiled
	scans, replacements                    int
	lastScan, lastReplace, lastReplacement string
}

func (p *routingSpyPattern) FindAllStringIndex(input string, n int) [][]int {
	p.scans++
	p.lastScan = input
	return p.compiled.FindAllStringIndex(input, n)
}

func (p *routingSpyPattern) ReplaceAllString(input, replacement string) string {
	p.replacements++
	p.lastReplace, p.lastReplacement = input, replacement
	return p.compiled.ReplaceAllString(input, replacement)
}

// Mutation checks: bypassing the compiled lookup in Detect fails each entry's
// scan assertion; bypassing it in back-reference replacement fails the rewrite
// assertions for both configured and generated rules, even with correct output.
// Ordinary XDG replacement is literal and deliberately invokes no engine rewrite.
func TestEngineConfiguredAndXDGRouting(t *testing.T) {
	fixtures := loadEngineConfigurationFixtures(t).Routing
	for _, row := range fixtures.Cases {
		t.Run(row.Name, func(t *testing.T) {
			redactor, err := newRedactorWithEngine(routingSpyEngine{}, Standard, fixtures.Patterns, XDGPaths{DataHome: fixtures.XDGDataHome})
			if err != nil {
				t.Fatal(err)
			}
			r := redactor.(*DefaultRedactor)
			var target *Rule
			for i := range r.userRules {
				if r.userRules[i].ID == row.Rule {
					target = &r.userRules[i]
					break
				}
			}
			if target == nil {
				t.Fatalf("rule %q was not constructed; restore the fixture's configured/XDG source", row.Rule)
			}
			if row.ReplacementOverride != "" {
				// Only this test's generated replacement changes. The generated
				// pattern and normal production back-reference branch are intact.
				target.Replacement = row.ReplacementOverride
			}
			spy, ok := r.patterns[target.Pattern].(*routingSpyPattern)
			if !ok {
				t.Fatalf("%s: no compiled spy entry; construction bypassed the injected engine", row.Rule)
			}
			matches := r.Detect(row.Input)
			if len(matches) != 1 || matches[0].Rule != row.Rule {
				t.Fatalf("Detect = %v; want exactly one %s match", matches, row.Rule)
			}
			if spy.scans != 1 || spy.lastScan != row.Input {
				t.Fatalf("%s: Detect scans=%d input=%q; want one spy scan of %q", row.Rule, spy.scans, spy.lastScan, row.Input)
			}
			if got := r.Redact(row.Input, matches); got != row.Output {
				t.Fatalf("Redact = %q, want %q", got, row.Output)
			}
			wantReplacements := 0
			if row.ExpectReplacement {
				wantReplacements = 1
			}
			if spy.scans != 1 || spy.replacements != wantReplacements {
				t.Fatalf("%s: Redact scans=%d replacements=%d; want no rescan and %d spy replacements", row.Rule, spy.scans, spy.replacements, wantReplacements)
			}
			if got := r.RedactText(row.Input); got != row.Output {
				t.Fatalf("RedactText = %q, want %q", got, row.Output)
			}
			if spy.scans != 2 || spy.lastScan != row.Input || spy.replacements != 2*wantReplacements {
				t.Fatalf("%s: RedactText scans=%d replacements=%d; want two total scans and %d spy replacements", row.Rule, spy.scans, spy.replacements, 2*wantReplacements)
			}
			if row.ExpectReplacement && (spy.lastReplace != matches[0].MatchedText || spy.lastReplacement != target.Replacement) {
				t.Fatalf("%s: spy rewrite input=%q replacement=%q; want matched text %q and rule replacement %q", row.Rule, spy.lastReplace, spy.lastReplacement, matches[0].MatchedText, target.Replacement)
			}
		})
	}
}
