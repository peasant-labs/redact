package redact

import "testing"

func matchesRule(t *testing.T, ruleID, payload string) bool {
	t.Helper()
	for _, rule := range Rules {
		if rule.ID == ruleID {
			return rule.Pattern.MatchString(payload)
		}
	}
	t.Fatalf("matchesRule: rule %q not found in Rules table; restore the rule or correct the fixture ruleId", ruleID)
	return false
}

func TestRuleCases(t *testing.T) {
	fixtures := mustLoadRuleFixtures(t)
	for _, family := range fixtures.Rules {
		family := family
		t.Run(family.RuleID, func(t *testing.T) {
			for _, fixture := range family.Cases {
				fixture := fixture
				t.Run(fixture.Name, func(t *testing.T) {
					got := matchesRule(t, family.RuleID, fixture.Input)
					if got != fixture.ShouldFlag {
						t.Errorf("matchesRule(%q, %q) = %v, want %v", family.RuleID, fixture.Input, got, fixture.ShouldFlag)
					}
				})
			}
		})
	}
}

func TestRulesFixtureCoverage(t *testing.T) {
	fixtures := mustLoadRuleFixtures(t)
	compiled := make(map[string]bool, len(Rules))
	for _, rule := range Rules {
		compiled[rule.ID] = false
	}
	for _, id := range fixtures.CoveredRuleIDs {
		if _, ok := compiled[id]; !ok {
			t.Errorf("fixture coverage names unknown rule %q", id)
			continue
		}
		compiled[id] = true
	}
	for _, rule := range projectRules {
		compiled[rule.ID] = true
	}
	for id, covered := range compiled {
		if !covered {
			t.Errorf("rule %q has no declared test coverage", id)
		}
	}
}

func TestResidueRulesNewPositiveTriggers(t *testing.T) {
	fixtures := mustLoadRuleFixtures(t)
	detector := NewResidueDetector()
	for _, fixture := range fixtures.Residues {
		fixture := fixture
		t.Run(fixture.Name, func(t *testing.T) {
			for _, warning := range detector.Scan(fixture.Input) {
				if warning.RuleID == fixture.RuleID {
					return
				}
			}
			t.Errorf("residue rule %q did not trigger on %q", fixture.RuleID, fixture.Input)
		})
	}
}

func detectsAWSSecretKey(t *testing.T, input string) bool {
	t.Helper()
	redactor := mustNewRedactor(t, Minimal, nil)
	for _, match := range redactor.Detect(input) {
		if match.Rule == "aws_secret_key" {
			return true
		}
	}
	return false
}

func TestAWSSecretKeyFilter(t *testing.T) {
	for _, fixture := range mustLoadRuleFixtures(t).AWSFilters {
		fixture := fixture
		t.Run(fixture.Name, func(t *testing.T) {
			if got := detectsAWSSecretKey(t, fixture.Input); got != fixture.WantDetect {
				t.Errorf("detectsAWSSecretKey(%q) = %v, want %v", fixture.Input, got, fixture.WantDetect)
			}
		})
	}
}

func TestExtractBase64Body(t *testing.T) {
	for _, fixture := range mustLoadRuleFixtures(t).ExtractBase64 {
		fixture := fixture
		t.Run(fixture.Name, func(t *testing.T) {
			if got := extractBase64Body(fixture.Matched); got != fixture.Want {
				t.Errorf("extractBase64Body(%q) = %q, want %q", fixture.Matched, got, fixture.Want)
			}
		})
	}
}

func TestFindRuleByID(t *testing.T) {
	rule := findRuleByID("aws_access_key")
	if rule == nil || rule.ID != "aws_access_key" || rule.Pattern == nil {
		t.Fatalf("findRuleByID(aws_access_key) = %#v, want the compiled aws_access_key rule", rule)
	}
	if got := findRuleByID("nonexistent_rule_xyz"); got != nil {
		t.Errorf("findRuleByID(nonexistent_rule_xyz) = %v, want nil", got)
	}
}

func TestAWSSecretKeyRuleFilterFnWired(t *testing.T) {
	rule := findRuleByID("aws_secret_key")
	if rule == nil || rule.FilterFn == nil {
		t.Fatalf("aws_secret_key FilterFn is not wired; restore the rule initialization")
	}
}

func TestHomePathSingleSegmentFilters(t *testing.T) {
	for _, fixture := range mustLoadRuleFixtures(t).HomePaths {
		fixture := fixture
		t.Run(fixture.Name, func(t *testing.T) {
			got := unixHomeSingleSegmentFilter(fixture.Matched, fixture.Input, fixture.Offset)
			if got != fixture.Want {
				t.Errorf("unixHomeSingleSegmentFilter() = %v, want %v", got, fixture.Want)
			}
		})
	}
}

func TestRuleSetVersion(t *testing.T) {
	if RuleSetVersion != "3.1.0" || Version() != "3.1.0" {
		t.Errorf("rule set versions = (%q, %q), want (3.1.0, 3.1.0)", RuleSetVersion, Version())
	}
}
