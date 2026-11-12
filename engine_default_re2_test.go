package redact

import (
	"testing"

	re2 "github.com/wasilibs/go-re2"
)

func TestEngineDefaultGoRE2(t *testing.T) {
	if _, ok := selectEngine().(goRE2Engine); !ok || selectEngine().Identity() != engineGoRE2 {
		t.Fatal("normal builds must select go-re2")
	}
	r, err := NewRedactor(Standard, nil, XDGPaths{})
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewTitlePipeline()
	if err != nil {
		t.Fatal(err)
	}
	assertDefaultRE2Patterns(t, r.(*DefaultRedactor).patterns, Rules, ResidueRules)
	assertDefaultRE2Patterns(t, p.patterns, p.rules, nil)
}

func assertDefaultRE2Patterns(t *testing.T, patterns compiledPatterns, rules []Rule, residues []ResidueRule) {
	t.Helper()
	if len(patterns) == 0 {
		t.Fatal("public constructor did not compile its rules with go-re2")
	}
	for _, rule := range rules {
		if _, ok := patterns[rule.Pattern].(*re2.Regexp); !ok {
			t.Fatalf("rule %s: public constructor must use a go-re2 pattern", rule.ID)
		}
	}
	for _, rule := range residues {
		if _, ok := patterns[rule.Pattern].(*re2.Regexp); !ok {
			t.Fatalf("residue rule %s: public constructor must use a go-re2 pattern", rule.ID)
		}
	}
}
