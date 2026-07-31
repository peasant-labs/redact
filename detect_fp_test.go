package redact

import (
	"testing"
)

// TestDetect_FalsePositives exercises the false-positive corpus in
// testdata/false_positives.yaml. For each case the test:
//
//  1. Calls r.Detect(input) at the specified level (default: Standard).
//  2. Checks whether the named rule fired.
//  3. Asserts the outcome matches the "expect" field ("match" or "no_match").
//
// Cases with expect="no_match" are guards against regressions where structural
// patterns (file paths, go.sum hashes, sequential strings) are mistakenly flagged.
// Cases with expect="match" are regression tests for true positives that must
// always be caught. Set level="maximum" for rules that only fire at Maximum.
func TestDetect_FalsePositives(t *testing.T) {
	cases, err := LoadFalsePositiveFixtures()
	if err != nil {
		t.Fatalf("LoadFalsePositiveFixtures: %v", err)
	}
	if len(cases) == 0 {
		t.Fatal("no fixture cases loaded")
	}

	// Build a validation set of known rule IDs from the compiled Rules table.
	// This runs before any subtests so a typo in a fixture rule field fails fast
	// in CI rather than silently passing as a no_match against a nonexistent rule.
	knownRuleIDs := make(map[string]struct{}, len(Rules))
	for _, r := range Rules {
		knownRuleIDs[r.ID] = struct{}{}
	}
	for _, tc := range cases {
		if _, ok := knownRuleIDs[tc.Rule]; !ok {
			t.Fatalf("fixture %q references unknown rule ID %q — check for typos or add the rule to rules.go", tc.Name, tc.Rule)
		}
	}

	for _, tc := range cases {
		tc := tc // capture for parallel subtests
		t.Run(tc.Name, func(t *testing.T) {
			level := tc.Level
			if level == "" {
				level = Standard
			}
			r := mustNewRedactor(t, level, nil)
			matches := r.Detect(tc.Input)

			ruleMatched := false
			for _, m := range matches {
				if m.Rule == tc.Rule {
					ruleMatched = true
					break
				}
			}

			switch tc.Expect {
			case "match":
				if !ruleMatched {
					t.Errorf("expected rule %q to match input %q: %s", tc.Rule, tc.Input, tc.Reason)
				}
			case "no_match":
				if ruleMatched {
					t.Errorf("expected rule %q NOT to match input %q (false positive): %s", tc.Rule, tc.Input, tc.Reason)
				}
			default:
				t.Fatalf("unknown expect value %q in fixture %q (must be 'match' or 'no_match')", tc.Expect, tc.Name)
			}
		})
	}
}
