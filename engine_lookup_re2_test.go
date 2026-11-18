//go:build !no_re2

package redact

import (
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
