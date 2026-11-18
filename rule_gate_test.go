package redact

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// vendorGateDeclarations is the reviewed contract for the vendor-token rules
// this change gates. RequiredLiterals is a disjunction: any one member may lead
// a match. MinMatchBytes is the shortest match the pattern can produce.
var vendorGateDeclarations = map[string]struct {
	literals []string
	minBytes int
}{
	"private_key_block":     {[]string{"PRIVATE KEY", "PuTTY-User-Key-File-2"}, 21},
	"slack_webhook_url":     {[]string{"hooks.slack.com/services/"}, 40},
	"slack_token":           {[]string{"xox"}, 8},
	"stripe_key":            {[]string{"_live_", "_test_"}, 32},
	"github_pat":            {[]string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"}, 40},
	"aws_access_key":        {[]string{"A3T", "ABIA", "ACCA", "AKIA", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA", "ASIA"}, 20},
	"gitlab_pat":            {[]string{"glpat-", "gldt-", "glft-", "glsoat-", "glrt-"}, 25},
	"artifactory_api_token": {[]string{"AKC"}, 13},
	"artifactory_password":  {[]string{"AP"}, 11},
}

// leadingLiteralPrefixes records the literal the engine can extract from each
// rewritten pattern. The three rewritten vendor rules lead with a literal;
// every other gated rule is listed in gatedRulesWithoutLeadingLiteral with the
// reason its pattern cannot lead with one.
var leadingLiteralPrefixes = map[string]string{
	"github_pat":     "gh",
	"aws_access_key": "A",
	"gitlab_pat":     "gl",
}

// gatedRulesWithoutLeadingLiteral documents why these patterns keep no leading
// literal. Each reason is a constraint, not a preference: relaxing it would
// change the match set or the redacted output.
var gatedRulesWithoutLeadingLiteral = map[string]string{
	"private_key_block":     "the PEM and PuTTY arms share no literal, so no common prefix exists",
	"slack_webhook_url":     "the scheme must stay in the match and (?i) suppresses prefix extraction",
	"slack_token":           "(?i) suppresses prefix extraction and the literal is already at the head",
	"stripe_key":            "the first byte is r or s, so no literal can lead the pattern",
	"artifactory_api_token": "the leading boundary group is part of the match span",
	"artifactory_password":  "the leading boundary group is part of the match span",
}

// gatedRuleIDs returns the declarations in a stable order for failure messages.
func gatedRuleIDs() []string {
	ids := make([]string, 0, len(vendorGateDeclarations))
	for id := range vendorGateDeclarations {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

func TestRuleGateMatchesDeclaredContract(t *testing.T) {
	for _, id := range gatedRuleIDs() {
		want := vendorGateDeclarations[id]
		rule := findRuleByID(id)
		if rule == nil {
			t.Fatalf("rule %q is missing from the rule table", id)
		}
		if !slices.Equal(rule.RequiredLiterals, want.literals) {
			t.Errorf("rule %q RequiredLiterals = %v, want %v", id, rule.RequiredLiterals, want.literals)
		}
		if rule.MinMatchBytes != want.minBytes {
			t.Errorf("rule %q MinMatchBytes = %d, want %d", id, rule.MinMatchBytes, want.minBytes)
		}
	}
}

// TestRuleGateAdmitsEveryFlaggedFixture is the mutation test: a gate that
// rejects a value the rule is supposed to flag fails here loudly.
func TestRuleGateAdmitsEveryFlaggedFixture(t *testing.T) {
	fixtures := mustLoadRuleFixtures(t)
	for _, family := range fixtures.Rules {
		if _, gated := vendorGateDeclarations[family.RuleID]; !gated {
			continue
		}
		rule := findRuleByID(family.RuleID)
		if rule == nil {
			t.Fatalf("rule %q is missing from the rule table", family.RuleID)
		}
		for _, fixture := range family.Cases {
			if !fixture.ShouldFlag {
				continue
			}
			if !admits(*rule, fixture.Input) {
				t.Errorf("admits(%q, %q) = false, but the fixture flags it", rule.ID, fixture.Input)
			}
		}
	}
}

// TestRuleGateAdmitsEveryDetectTruePositive covers the production Detect path:
// every true-positive fixture in the false-positive corpus must still be
// detected after the gate is applied.
func TestRuleGateAdmitsEveryDetectTruePositive(t *testing.T) {
	cases, err := LoadFalsePositiveFixtures()
	if err != nil {
		t.Fatalf("LoadFalsePositiveFixtures: %v", err)
	}
	for _, fixture := range cases {
		if _, gated := vendorGateDeclarations[fixture.Rule]; !gated || fixture.Expect != "match" {
			continue
		}
		rule := findRuleByID(fixture.Rule)
		if rule == nil {
			t.Fatalf("rule %q is missing from the rule table", fixture.Rule)
		}
		if !admits(*rule, fixture.Input) {
			t.Errorf("admits(%q, %q) = false, but the corpus expects a match", rule.ID, fixture.Input)
		}
	}
}

// TestRuleGateSkipsRegexForValueWithoutLiteral proves the gate runs before the
// pattern: the probe pattern would match, but the declared literal is absent.
func TestRuleGateSkipsRegexForValueWithoutLiteral(t *testing.T) {
	const payload = "xoxb-34532454-e039d02840a0b9379c"
	rule := Rule{
		ID:               "gate_probe",
		Category:         CategorySecrets,
		Pattern:          regexp.MustCompile(`(?i)xox[abopsr]-(?:\d+-)+[a-z0-9]+`),
		Replacement:      "<PROBE>",
		RequiredLiterals: []string{"absent-literal"},
	}
	if got := detectWithRules(payload, []Rule{rule}); len(got) != 0 {
		t.Fatalf("detectWithRules with an unsatisfied gate returned %v, want no matches", got)
	}

	rule.RequiredLiterals = []string{"xox"}
	if got := detectWithRules(payload, []Rule{rule}); len(got) != 1 {
		t.Fatalf("detectWithRules with a satisfied gate returned %d matches, want 1", len(got))
	}
}

// TestRuleGateMinMatchBytesBoundary pins the short-value skip to the exact
// shortest match: one byte under is refused, the floor itself is admitted.
func TestRuleGateMinMatchBytesBoundary(t *testing.T) {
	for _, id := range gatedRuleIDs() {
		rule := findRuleByID(id)
		want := vendorGateDeclarations[id]
		literal := want.literals[0]

		below := literal + strings.Repeat("a", want.minBytes-len(literal)-1)
		if len(below) != want.minBytes-1 {
			t.Fatalf("rule %q probe length = %d, want %d", id, len(below), want.minBytes-1)
		}
		if admits(*rule, below) {
			t.Errorf("admits(%q, %d-byte value) = true, want false", id, len(below))
		}

		atFloor := literal + strings.Repeat("a", want.minBytes-len(literal))
		if len(atFloor) != want.minBytes {
			t.Fatalf("rule %q probe length = %d, want %d", id, len(atFloor), want.minBytes)
		}
		if !admits(*rule, atFloor) {
			t.Errorf("admits(%q, %d-byte value) = false, want true", id, len(atFloor))
		}
	}
}

// TestRuleGateRejectsWhenEveryLiteralMissing is the other half of the contract:
// a value that holds none of the declared literals is skipped.
func TestRuleGateRejectsWhenEveryLiteralMissing(t *testing.T) {
	value := strings.Repeat("z", 64)
	for _, id := range gatedRuleIDs() {
		rule := findRuleByID(id)
		for _, literal := range rule.RequiredLiterals {
			if strings.Contains(value, literal) {
				t.Fatalf("probe value unexpectedly holds %q from rule %q", literal, id)
			}
		}
		if admits(*rule, value) {
			t.Errorf("admits(%q, value with no declared literal) = true, want false", id)
		}
	}
}

// TestRuleGateCaseInsensitiveLiterals proves the two case-insensitive rules
// admit uppercase inputs without allocating a lowercased copy of the value.
func TestRuleGateCaseInsensitiveLiterals(t *testing.T) {
	for _, id := range []string{"slack_token", "slack_webhook_url"} {
		rule := findRuleByID(id)
		if !ruleHasFoldCase(*rule) {
			t.Errorf("rule %q does not report fold-case; the gate would compare byte-exactly", id)
		}
	}

	slack := findRuleByID("slack_token")
	if !admits(*slack, "XOXB-34532454-e039d02840a0b9379c") {
		t.Error("uppercase XOX token was rejected by the case-insensitive gate")
	}

	webhook := findRuleByID("slack_webhook_url")
	if !admits(*webhook, "HTTPS://HOOKS.SLACK.COM/SERVICES/T1/B1/x") {
		t.Error("uppercase Slack webhook was rejected by the case-insensitive gate")
	}

	for _, id := range gatedRuleIDs() {
		if id == "slack_token" || id == "slack_webhook_url" {
			continue
		}
		if ruleHasFoldCase(*findRuleByID(id)) {
			t.Errorf("rule %q reported fold-case but its pattern is case-sensitive", id)
		}
	}
}

// TestRuleGateLeadingLiteral documents which vendor patterns lead with a
// literal, and why the rest do not.
func TestRuleGateLeadingLiteral(t *testing.T) {
	for _, id := range gatedRuleIDs() {
		rule := findRuleByID(id)
		prefix, _ := rule.Pattern.LiteralPrefix()
		want, rewritten := leadingLiteralPrefixes[id]
		if rewritten {
			if prefix != want {
				t.Errorf("rule %q LiteralPrefix = %q, want %q", id, prefix, want)
			}
			continue
		}
		reason, documented := gatedRulesWithoutLeadingLiteral[id]
		if !documented {
			t.Errorf("rule %q has no leading literal and no documented exception", id)
			continue
		}
		if prefix != "" {
			t.Errorf("rule %q now extracts prefix %q; update the reviewed exception %q", id, prefix, reason)
		}
	}
}

// TestRuleGateDeclaredLiteralsAppearInEveryMatch checks the safety property the
// gate depends on: at least one declared literal is present in every match the
// pattern produces.
func TestRuleGateDeclaredLiteralsAppearInEveryMatch(t *testing.T) {
	fixtures := mustLoadRuleFixtures(t)
	for _, family := range fixtures.Rules {
		rule := findRuleByID(family.RuleID)
		if rule == nil || len(rule.RequiredLiterals) == 0 {
			continue
		}
		for _, fixture := range family.Cases {
			if !fixture.ShouldFlag {
				continue
			}
			found := false
			for _, literal := range rule.RequiredLiterals {
				if containsLiteral(fixture.Input, literal, ruleHasFoldCase(*rule)) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("rule %q flags %q but holds none of its declared literals %v", rule.ID, fixture.Input, rule.RequiredLiterals)
			}
		}
	}
}

// TestRuleGatePatternRewriteIsSpanIdentical is the acceptance gate for the three
// pattern rewrites: the pre-rewrite pattern and the current pattern must produce
// identical spans over the whole fixture corpus.
func TestRuleGatePatternRewriteIsSpanIdentical(t *testing.T) {
	previous := map[string]string{
		"github_pat":     `(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}`,
		"aws_access_key": `(?:A3T[A-Z0-9]|ABIA|ACCA|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`,
		"gitlab_pat":     `(?:glpat|gldt|glft|glsoat|glrt)-[A-Za-z0-9_\-]{20,50}(?:[^A-Za-z0-9_]|$)`,
	}

	corpus := gateCorpus(t)
	for id, pattern := range previous {
		before := regexp.MustCompile(pattern)
		after := findRuleByID(id).Pattern
		for _, input := range corpus {
			beforeSpans := before.FindAllStringIndex(input, -1)
			afterSpans := after.FindAllStringIndex(input, -1)
			if !slices.EqualFunc(beforeSpans, afterSpans, func(a, b []int) bool {
				return a[0] == b[0] && a[1] == b[1]
			}) {
				t.Errorf("rule %q span set changed on %q: before=%v after=%v", id, input, beforeSpans, afterSpans)
			}
		}
	}
}

// TestRuleGateDoesNotChangeDetection is the whole-table parity proof: the same
// corpus produces identical matches with the gate declared and with the gate
// fields cleared.
func TestRuleGateDoesNotChangeDetection(t *testing.T) {
	corpus := gateCorpus(t)
	gated := append([]Rule(nil), Rules...)
	ungated := make([]Rule, len(gated))
	for i, rule := range gated {
		rule.RequiredLiterals = nil
		rule.MinMatchBytes = 0
		ungated[i] = rule
	}
	for _, input := range corpus {
		got := detectWithRules(input, gated)
		want := detectWithRules(input, ungated)
		if !slices.Equal(got, want) {
			t.Errorf("gate changed detection on %q: with gate=%v without gate=%v", input, got, want)
		}
	}
}

// gateCorpus collects every input the fixtures drive through the detector.
func gateCorpus(t *testing.T) []string {
	t.Helper()
	var corpus []string
	for _, family := range mustLoadRuleFixtures(t).Rules {
		for _, fixture := range family.Cases {
			corpus = append(corpus, fixture.Input)
		}
	}
	cases, err := LoadFalsePositiveFixtures()
	if err != nil {
		t.Fatalf("LoadFalsePositiveFixtures: %v", err)
	}
	for _, fixture := range cases {
		corpus = append(corpus, fixture.Input)
	}
	return corpus
}
