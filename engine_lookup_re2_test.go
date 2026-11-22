package redact

import (
	"regexp"
	"slices"
	"testing"

	re2 "github.com/wasilibs/go-re2"
)

func TestEngineLookupHitUsesSelectedEngine(t *testing.T) {
	fixtures := loadEngineLookupFixtures(t)
	requireEngineLookupCase(t, fixtures, "engine_lookup_hit_uses_selected_engine")
	set, err := compileRulePatterns(goRE2Engine{}, Rules, nil, ResidueRules)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range Rules {
		if rule.Pattern == nil {
			continue
		}
		resolved, ok := set.lookup(rule.Pattern).(*re2.Regexp)
		if !ok {
			t.Fatalf("built-in rule %s resolved to %T, want *re2.Regexp", rule.ID, set.lookup(rule.Pattern))
		}
		if resolved.String() != rule.Pattern.String() {
			t.Fatalf("built-in rule %s changed the pattern source", rule.ID)
		}
	}
	for _, rule := range ResidueRules {
		if rule.Pattern == nil {
			continue
		}
		if _, ok := set.lookup(rule.Pattern).(*re2.Regexp); !ok {
			t.Fatalf("residue rule %s resolved to %T, want *re2.Regexp", rule.ID, set.lookup(rule.Pattern))
		}
	}
}

func TestEngineParityRunsSelectedEngine(t *testing.T) {
	fixtures := loadEngineLookupFixtures(t)
	requireEngineLookupCase(t, fixtures, "engine_parity_runs_selected_engine")
	probe := fixtures.probeRule(t)
	set, err := compileRulePatterns(goRE2Engine{}, Rules, nil, ResidueRules)
	if err != nil {
		t.Fatal(err)
	}
	// Positive control: the compiled rules scan without complaint.
	_ = detectWithRules(fixtures.ProbeInput, Rules, set)
	// A probe rule absent from the set fails loudly instead of passing as
	// stdlib against stdlib.
	assertLookupPanics(t, "parity detection with a rule outside the set", func() {
		_ = detectWithRules(fixtures.ProbeInput, append(slices.Clone(Rules), probe), set)
	})
}

func TestEngineLookupNeverReturnsStdlib(t *testing.T) {
	fixtures := loadEngineLookupFixtures(t)
	requireEngineLookupCase(t, fixtures, "lookup_never_returns_stdlib")
	if EngineIdentity() != EngineGoRE2 {
		t.Fatalf("EngineIdentity()=%q, want %q on the go-re2 default build", EngineIdentity(), EngineGoRE2)
	}
	redactor, err := NewRedactor(Standard, []UserPattern{{
		ID:          "lookup_user",
		Category:    CategorySecrets,
		Pattern:     fixtures.ProbePattern,
		Replacement: fixtures.ProbeReplacement,
	}}, XDGPaths{})
	if err != nil {
		t.Fatal(err)
	}
	built := redactor.(*DefaultRedactor)
	assertGoRE2 := func(t *testing.T, id string, pattern *regexp.Regexp, set compiledPatterns) {
		t.Helper()
		got := set.lookup(pattern)
		if _, isStdlib := got.(*regexp.Regexp); isStdlib {
			t.Fatalf("rule %s lookup returned a stdlib *regexp.Regexp", id)
		}
		if _, ok := got.(*re2.Regexp); !ok {
			t.Fatalf("rule %s resolved to %T, want *re2.Regexp", id, got)
		}
	}
	for _, rule := range Rules {
		if rule.Pattern == nil {
			t.Fatalf("built-in rule %s has a nil pattern after a successful NewRedactor", rule.ID)
		}
		assertGoRE2(t, rule.ID, rule.Pattern, built.patterns)
	}
	for _, rule := range ResidueRules {
		if rule.Pattern == nil {
			t.Fatalf("residue rule %s has a nil pattern after a successful NewRedactor", rule.ID)
		}
		assertGoRE2(t, rule.ID, rule.Pattern, built.patterns)
	}
	for _, rule := range built.userRules {
		assertGoRE2(t, rule.ID, rule.Pattern, built.patterns)
	}
	pipeline, err := NewTitlePipeline()
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range pipeline.rules {
		assertGoRE2(t, rule.ID, rule.Pattern, pipeline.patterns)
	}
	detector, err := newResidueDetector(goRE2Engine{})
	if err != nil {
		t.Fatal(err)
	}
	residue := detector.(*DefaultResidueDetector)
	for _, rule := range ResidueRules {
		assertGoRE2(t, rule.ID, rule.Pattern, residue.patterns)
	}
}
