package redact

import (
	_ "embed"
	"errors"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"

	"gopkg.in/yaml.v3"
)

//go:embed testdata/engine_lookup.yaml
var engineLookupData []byte

const engineLookupTestFixturePath = "testdata/engine_lookup.yaml"

type engineLookupCase struct {
	Name string `yaml:"name"`
}

type engineLookupFixtures struct {
	RequiredNames    []string           `yaml:"required_names"`
	ProbeRuleID      string             `yaml:"probe_rule_id"`
	ProbePattern     string             `yaml:"probe_pattern"`
	ProbeInput       string             `yaml:"probe_input"`
	ProbeReplacement string             `yaml:"probe_replacement"`
	Cases            []engineLookupCase `yaml:"cases"`
}

func loadEngineLookupFixtures(t *testing.T) engineLookupFixtures {
	t.Helper()
	var fixtures engineLookupFixtures
	if err := yaml.Unmarshal(engineLookupData, &fixtures); err != nil {
		t.Fatal(err)
	}
	if err := requireFixtureNames(engineLookupTestFixturePath, "required_names", fixtures.RequiredNames, fixtureNames(fixtures.Cases, func(row engineLookupCase) string { return row.Name })); err != nil {
		t.Fatal(err)
	}
	if fixtures.ProbeRuleID == "" || fixtures.ProbePattern == "" || fixtures.ProbeInput == "" || fixtures.ProbeReplacement == "" {
		t.Fatal("engine lookup fixture settings missing; restore probe rule id, pattern, input, and replacement")
	}
	if _, err := regexp.Compile(fixtures.ProbePattern); err != nil {
		t.Fatalf("engine lookup probe pattern is invalid: %v", err)
	}
	if !containsBackref(fixtures.ProbeReplacement) {
		t.Fatal("engine lookup probe replacement must carry a backreference to exercise the replacement lookup path")
	}
	return fixtures
}

// probeRule builds a rule whose pattern pointer never goes through
// compileRulePatterns, so resolving it through a non-nil set must panic.
func (fixtures engineLookupFixtures) probeRule(t *testing.T) Rule {
	t.Helper()
	pattern, err := regexp.Compile(fixtures.ProbePattern)
	if err != nil {
		t.Fatal(err)
	}
	return Rule{ID: fixtures.ProbeRuleID, Category: CategorySecrets, Pattern: pattern, Replacement: fixtures.ProbeReplacement}
}

func requireEngineLookupCase(t *testing.T, fixtures engineLookupFixtures, name string) {
	t.Helper()
	for _, row := range fixtures.Cases {
		if row.Name == name {
			return
		}
	}
	t.Fatalf("engine lookup case %q missing; restore the row or remove it from the required manifest in the same reviewed change", name)
}

// assertLookupPanics runs f and requires the actionable lookup panic: the
// message must name the lookup path and compileRulePatterns.
func assertLookupPanics(t *testing.T, what string, f func()) {
	t.Helper()
	defer func() {
		recovered := recover()
		if recovered == nil {
			t.Fatalf("%s did not panic on a rule pointer outside the compiled set", what)
		}
		message := strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(
			recoverMessage(t, recovered), "\r", ""), "\t", " "), "\n", " "))
		if !strings.Contains(message, "lookup") || !strings.Contains(message, "compileRulePatterns") {
			t.Fatalf("%s panic message %q does not name the lookup path", what, message)
		}
	}()
	f()
}

func recoverMessage(t *testing.T, recovered any) string {
	t.Helper()
	if err, ok := recovered.(error); ok {
		return err.Error()
	}
	t.Fatalf("lookup panic value is %T, want an actionable error", recovered)
	return ""
}

func TestEngineLookupNilSetUsesStdlib(t *testing.T) {
	fixtures := loadEngineLookupFixtures(t)
	requireEngineLookupCase(t, fixtures, "engine_lookup_nil_set_uses_stdlib")
	var set compiledPatterns
	for _, rule := range Rules {
		if rule.Pattern == nil {
			continue
		}
		stdlib, ok := set.lookup(rule.Pattern).(*regexp.Regexp)
		if !ok || stdlib != rule.Pattern {
			t.Fatalf("built-in rule %s missed the nil-set stdlib path", rule.ID)
		}
	}
	for _, rule := range ResidueRules {
		if rule.Pattern == nil {
			continue
		}
		stdlib, ok := set.lookup(rule.Pattern).(*regexp.Regexp)
		if !ok || stdlib != rule.Pattern {
			t.Fatalf("residue rule %s missed the nil-set stdlib path", rule.ID)
		}
	}
	if set.lookup(nil) != nil {
		t.Fatal("nil pattern through a nil set must resolve to nil")
	}
}

func TestEngineLookupMissPanics(t *testing.T) {
	fixtures := loadEngineLookupFixtures(t)
	requireEngineLookupCase(t, fixtures, "engine_lookup_miss_panics")
	probe := fixtures.probeRule(t)
	set, err := compileRulePatterns(routingSpyEngine{}, Rules, nil, ResidueRules)
	if err != nil {
		t.Fatal(err)
	}
	if set == nil {
		t.Fatal("a non-stdlib engine must produce a non-nil compiled set")
	}
	t.Run("detect", func(t *testing.T) {
		assertLookupPanics(t, "detection", func() {
			_ = detectWithRules(fixtures.ProbeInput, append(slices.Clone(Rules), probe), set)
		})
	})
	t.Run("replacement", func(t *testing.T) {
		assertLookupPanics(t, "replacement", func() {
			matches := []Match{{Rule: probe.ID, Offset: 0, Length: len(fixtures.ProbeInput), Category: probe.Category, MatchedText: fixtures.ProbeInput}}
			_, _ = redactWithRules(fixtures.ProbeInput, matches, append(slices.Clone(Rules), probe), set)
		})
	})
	t.Run("residue", func(t *testing.T) {
		original := ResidueRules
		t.Cleanup(func() { ResidueRules = original })
		ResidueRules = append(slices.Clone(ResidueRules), ResidueRule{ID: probe.ID, Pattern: probe.Pattern})
		assertLookupPanics(t, "residue scanning", func() {
			_ = (&DefaultResidueDetector{patterns: set}).Scan(fixtures.ProbeInput)
		})
	})
}

// lateTableEngine compiles with the inner engine and, on the first Compile,
// runs append so a live rule table can gain a pointer after the snapshot.
type lateTableEngine struct {
	inner  engine
	once   sync.Once
	append func()
}

func (e *lateTableEngine) Identity() engineName { return e.inner.Identity() }

func (e *lateTableEngine) Compile(pattern string) (compiled, error) {
	e.once.Do(e.append)
	return e.inner.Compile(pattern)
}

func TestEngineLookupMissingPatternRefuses(t *testing.T) {
	fixtures := loadEngineLookupFixtures(t)
	requireEngineLookupCase(t, fixtures, "lookup_missing_pattern_refuses")
	late := fixtures.probeRule(t)
	late.ID = "lookup_late_rule"

	assertRefused := func(t *testing.T, got any, err error) {
		t.Helper()
		if got != nil && !reflect.ValueOf(got).IsNil() {
			t.Fatal("constructor returned an object after a rule was added past the compile snapshot")
		}
		if !errors.Is(err, ErrPatternNotCompiled) {
			t.Fatalf("err=%v, want ErrPatternNotCompiled", err)
		}
		if !strings.Contains(err.Error(), late.ID) {
			t.Fatalf("error %q does not name rule %s", err.Error(), late.ID)
		}
	}

	t.Run("redactor", func(t *testing.T) {
		original := Rules
		t.Cleanup(func() { Rules = original })
		Rules = slices.Clone(Rules)
		e := &lateTableEngine{inner: routingSpyEngine{}, append: func() {
			Rules = append(Rules, late)
		}}
		r, err := newRedactorWithEngine(e, Standard, nil, XDGPaths{})
		assertRefused(t, r, err)
	})
	t.Run("title", func(t *testing.T) {
		original := Rules
		t.Cleanup(func() { Rules = original })
		Rules = slices.Clone(Rules)
		e := &lateTableEngine{inner: routingSpyEngine{}, append: func() {
			Rules = append(Rules, late)
		}}
		pipeline, err := newTitlePipelineWithEngine(e)
		assertRefused(t, pipeline, err)
	})
	t.Run("residue", func(t *testing.T) {
		original := ResidueRules
		t.Cleanup(func() { ResidueRules = original })
		ResidueRules = slices.Clone(ResidueRules)
		e := &lateTableEngine{inner: routingSpyEngine{}, append: func() {
			ResidueRules = append(ResidueRules, ResidueRule{ID: late.ID, Pattern: late.Pattern})
		}}
		d, err := newResidueDetector(e)
		assertRefused(t, d, err)
	})
	t.Run("nil_pattern", func(t *testing.T) {
		original := Rules
		t.Cleanup(func() { Rules = original })
		Rules = append(slices.Clone(Rules), Rule{ID: late.ID, Category: CategorySecrets})
		r, err := newRedactorWithEngine(routingSpyEngine{}, Standard, nil, XDGPaths{})
		assertRefused(t, r, err)
	})
}
