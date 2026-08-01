package redact_test

import (
	"testing"

	"github.com/peasant-labs/redact"
	"github.com/peasant-labs/schema"
)

// TestRedactionFixtureConformance is the load-bearing no-drift gate for the
// session-detail redaction fixture that ships in the schema module. The fixture
// (testdata/session-detail/redactions.yaml, exported as schema.RedactionsYAML)
// STORES the engine-applied output verbatim; the engine itself lives ONLY here in
// redact package. This test runs the REAL engine over each case's OriginalText at the
// case's firing Level and asserts:
//
//  1. RedactText(OriginalText) == RedactedReplacement — binds the applied OUTPUT,
//     including back-reference forms (/Users/<USER>/…, postgresql://<BASIC_AUTH_URI>@…).
//  2. the firing rule's engine Category == the fixture's Category, and a match for
//     the fixture's RuleID is present — binds the category vocabulary + rule id.
//
// It FAILS the moment any redact package Pattern, Replacement, Category, or level
// behaviour drifts from the fixture, surfacing the drift as a reviewed change to
// the leaf data. This is the guarantee the leaf's shape-only freshness gate
// cannot provide (the leaf has no engine).
func TestRedactionFixtureConformance(t *testing.T) {
	cases, err := schema.LoadRedactionExamples()
	if err != nil {
		t.Fatalf("load redaction fixture (schema.RedactionsYAML): %v", err)
	}
	if len(cases) == 0 {
		t.Fatal("redaction fixture is empty — schema.RedactionsYAML did not unmarshal any cases")
	}

	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			level := redact.RedactionLevel(string(c.Level))
			if !level.IsValid() {
				t.Fatalf("case %q: fixture Level %q is not a valid redact.RedactionLevel "+
					"(want minimal/standard/maximum) — fix the Level in schema RedactionExamples",
					c.Name, c.Level)
			}
			if level == redact.Maximum && !redact.MaximumAvailable {
				t.Skipf("case %q requires Maximum redaction, which is unavailable in this CGO-disabled build; the CGO-enabled conformance run exercises the engine output, while package-level fixture tests still verify the rule's Maximum minimum", c.Name)
			}

			r, err := redact.NewRedactor(level, nil, redact.XDGPaths{})
			if err != nil {
				t.Fatalf("case %q: NewRedactor(%s): %v", c.Name, level, err)
			}

			// (1) Applied-output binding — the load-bearing assertion.
			got := r.RedactText(c.OriginalText)
			if got != c.RedactedReplacement {
				t.Errorf(
					"case %q: engine output drifted from the fixture.\n"+
						"  level:   %s\n"+
						"  in:      %q\n"+
						"  got:     %q  (real redact package output)\n"+
						"  want:    %q  (fixture redactedReplacement)\n"+
						"  fix:     the redact package changed its Pattern/Replacement/level for this case — update the\n"+
						"           case in schema RedactionExamples (run `go run ./cmd/schema-gen` in the schema repo),\n"+
						"           OR revert the unintended engine change.",
					c.Name, level, c.OriginalText, got, c.RedactedReplacement)
			}

			// (2) Category + rule-id binding — pin the vocabulary the fixture declares.
			matches := r.Detect(c.OriginalText)
			var fired *redact.Match
			for i := range matches {
				if matches[i].Rule == c.RuleID {
					fired = &matches[i]
					break
				}
			}
			if fired == nil {
				t.Errorf(
					"case %q: fixture RuleID %q did not fire on %q at level %s "+
						"(matched rules: %v). The fixture's ruleId no longer matches the engine — "+
						"reconcile the case in schema RedactionExamples.",
					c.Name, c.RuleID, c.OriginalText, level, matchRuleIDs(matches))
				return
			}
			if string(fired.Category) != c.Category {
				t.Errorf(
					"case %q: engine category %q for rule %q != fixture category %q — "+
						"the category vocabulary drifted; reconcile schema RedactionExamples.",
					c.Name, fired.Category, c.RuleID, c.Category)
			}
		})
	}
}

func matchRuleIDs(matches []redact.Match) []string {
	ids := make([]string, len(matches))
	for i, m := range matches {
		ids[i] = m.Rule
	}
	return ids
}
