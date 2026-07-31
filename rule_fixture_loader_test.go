package redact

import (
	_ "embed"
	"fmt"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

//go:embed testdata/rules.yaml
var ruleFixtureData []byte

type ruleFixtureCase struct {
	Name       string `yaml:"name"`
	Input      string `yaml:"input"`
	ShouldFlag bool   `yaml:"shouldFlag"`
}

type ruleFixtureFamily struct {
	RuleID string            `yaml:"ruleId"`
	Cases  []ruleFixtureCase `yaml:"cases"`
}

type residueFixture struct {
	Name   string `yaml:"name"`
	RuleID string `yaml:"ruleId"`
	Input  string `yaml:"input"`
}

type awsFilterFixture struct {
	Name       string `yaml:"name"`
	Input      string `yaml:"input"`
	WantDetect bool   `yaml:"wantDetect"`
}

type extractBase64Fixture struct {
	Name    string `yaml:"name"`
	Matched string `yaml:"matched"`
	Want    string `yaml:"want"`
}

type homePathFixture struct {
	Name    string `yaml:"name"`
	Input   string `yaml:"input"`
	Offset  int    `yaml:"offset"`
	Matched string `yaml:"matched"`
	Want    bool   `yaml:"want"`
}

type ruleFixtures struct {
	Rules          []ruleFixtureFamily    `yaml:"rules"`
	Residues       []residueFixture       `yaml:"residues"`
	AWSFilters     []awsFilterFixture     `yaml:"awsFilters"`
	ExtractBase64  []extractBase64Fixture `yaml:"extractBase64"`
	HomePaths      []homePathFixture      `yaml:"homePaths"`
	CoveredRuleIDs []string               `yaml:"coveredRuleIds"`
}

var expectedRuleFamilyCounts = map[string]int{
	"artifactory_api_token": 16, "artifactory_password": 12, "azure_storage_key": 5,
	"discord_bot_token": 12, "gitlab_pat": 13, "gitlab_runner_registration": 6,
	"gitlab_cicd": 7, "gitlab_incoming_mail": 6, "gitlab_trigger": 5,
	"gitlab_agent": 5, "gitlab_oauth_secret": 5, "mailchimp_api_key": 7,
	"npm_auth_token": 10, "pypi_api_token": 5, "pypi_test_token": 4,
	"square_oauth_secret": 6, "telegram_bot_token": 9, "access_code": 7,
}

func mustLoadRuleFixtures(t *testing.T) ruleFixtures {
	t.Helper()
	var fixtures ruleFixtures
	if err := yaml.Unmarshal(ruleFixtureData, &fixtures); err != nil {
		t.Fatalf("parse testdata/rules.yaml: %v; fix the YAML syntax", err)
	}
	if err := validateRuleFixtures(fixtures); err != nil {
		t.Fatal(err)
	}
	return fixtures
}

func validateRuleFixtures(fixtures ruleFixtures) error {
	if len(fixtures.Rules) != len(expectedRuleFamilyCounts) {
		return fmt.Errorf("testdata/rules.yaml loaded %d rule families, want %d; restore the missing or extra family", len(fixtures.Rules), len(expectedRuleFamilyCounts))
	}
	if len(fixtures.Residues) != 17 || len(fixtures.AWSFilters) != 8 || len(fixtures.ExtractBase64) != 6 || len(fixtures.HomePaths) != 2 || len(fixtures.CoveredRuleIDs) != 46 {
		return fmt.Errorf("testdata/rules.yaml family counts are residues=%d awsFilters=%d extractBase64=%d homePaths=%d coveredRuleIds=%d, want 17/8/6/2/46; restore the changed rows", len(fixtures.Residues), len(fixtures.AWSFilters), len(fixtures.ExtractBase64), len(fixtures.HomePaths), len(fixtures.CoveredRuleIDs))
	}
	seen := map[string]struct{}{}
	identity := func(id string) error {
		if strings.TrimSpace(id) == "" {
			return fmt.Errorf("testdata/rules.yaml contains an empty fixture identity; give every row a stable descriptive name")
		}
		if _, ok := seen[id]; ok {
			return fmt.Errorf("testdata/rules.yaml contains duplicate fixture identity %q; rename one row", id)
		}
		seen[id] = struct{}{}
		return nil
	}
	for _, family := range fixtures.Rules {
		want, ok := expectedRuleFamilyCounts[family.RuleID]
		if !ok || len(family.Cases) != want {
			return fmt.Errorf("testdata/rules.yaml rule family %q has %d rows, want %d; restore the family membership", family.RuleID, len(family.Cases), want)
		}
		if err := identity("rule/" + family.RuleID); err != nil {
			return err
		}
		for _, fixture := range family.Cases {
			if fixture.Input == "" {
				return fmt.Errorf("testdata/rules.yaml rule %q case %q has empty input; add the production detector input", family.RuleID, fixture.Name)
			}
			if err := identity("rule/" + family.RuleID + "/" + fixture.Name); err != nil {
				return err
			}
		}
	}
	for _, fixture := range fixtures.Residues {
		if fixture.RuleID == "" || fixture.Input == "" {
			return fmt.Errorf("testdata/rules.yaml residue %q is incomplete; ruleId and input are required", fixture.Name)
		}
		if err := identity("residue/" + fixture.Name); err != nil {
			return err
		}
	}
	for _, fixture := range fixtures.AWSFilters {
		if fixture.Input == "" {
			return fmt.Errorf("testdata/rules.yaml AWS filter %q has empty input", fixture.Name)
		}
		if err := identity("aws/" + fixture.Name); err != nil {
			return err
		}
	}
	for _, fixture := range fixtures.ExtractBase64 {
		if err := identity("base64/" + fixture.Name); err != nil {
			return err
		}
	}
	for _, fixture := range fixtures.HomePaths {
		if fixture.Offset < 0 || fixture.Offset+len(fixture.Matched) > len(fixture.Input) || fixture.Input[fixture.Offset:fixture.Offset+len(fixture.Matched)] != fixture.Matched {
			return fmt.Errorf("testdata/rules.yaml home path %q has invalid offset/matched coordinates", fixture.Name)
		}
		if err := identity("home/" + fixture.Name); err != nil {
			return err
		}
	}
	for _, id := range fixtures.CoveredRuleIDs {
		if err := identity("coverage/" + id); err != nil {
			return err
		}
	}
	return nil
}
