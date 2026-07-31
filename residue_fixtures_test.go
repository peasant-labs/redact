package redact

import (
	_ "embed"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	wantResiduePositiveTriggerRows = 18
	wantResidueReportWarningRows   = 3
)

//go:embed testdata/residue.yaml
var residueFixtureData []byte

type residueFixtures struct {
	PositiveTriggers []residuePositiveTriggerFixture `yaml:"positive_triggers"`
	ReportWarnings   []residueReportWarningFixture   `yaml:"report_warnings"`
}

type residuePositiveTriggerFixture struct {
	ID     string `yaml:"id"`
	RuleID string `yaml:"rule_id"`
	Input  string `yaml:"input"`
}

type residueReportWarningFixture struct {
	ID           string `yaml:"id"`
	Input        string `yaml:"input"`
	WantRuleHint string `yaml:"want_rule_hint"`
}

func loadResidueFixtures(t *testing.T) residueFixtures {
	t.Helper()

	var fixtures residueFixtures
	if err := yaml.Unmarshal(residueFixtureData, &fixtures); err != nil {
		t.Fatalf("decode testdata/residue.yaml while loading residue detector fixtures: %v", err)
	}

	checkResidueFixtureFamily(t, "positive_triggers", len(fixtures.PositiveTriggers), wantResiduePositiveTriggerRows, residuePositiveTriggerIDs(fixtures.PositiveTriggers))
	checkResidueFixtureFamily(t, "report_warnings", len(fixtures.ReportWarnings), wantResidueReportWarningRows, residueReportWarningIDs(fixtures.ReportWarnings))
	for _, row := range fixtures.PositiveTriggers {
		if row.RuleID == "" || row.Input == "" {
			t.Fatalf("residue positive trigger fixture %q must define rule_id and input", row.ID)
		}
	}
	for _, row := range fixtures.ReportWarnings {
		if row.Input == "" || row.WantRuleHint == "" {
			t.Fatalf("residue report warning fixture %q must define input and want_rule_hint", row.ID)
		}
	}
	return fixtures
}

func checkResidueFixtureFamily(t *testing.T, family string, got, want int, ids []string) {
	t.Helper()
	if got != want {
		t.Fatalf("residue fixture family %q has %d rows, want %d; update its exact row guard deliberately", family, got, want)
	}
	seen := make(map[string]struct{}, len(ids))
	for row, id := range ids {
		if id == "" {
			t.Fatalf("residue fixture family %q row %d has an empty ID", family, row)
		}
		if _, exists := seen[id]; exists {
			t.Fatalf("residue fixture family %q has duplicate ID %q", family, id)
		}
		seen[id] = struct{}{}
	}
}

func residuePositiveTriggerIDs(rows []residuePositiveTriggerFixture) []string {
	ids := make([]string, len(rows))
	for i, row := range rows {
		ids[i] = row.ID
	}
	return ids
}

func residueReportWarningIDs(rows []residueReportWarningFixture) []string {
	ids := make([]string, len(rows))
	for i, row := range rows {
		ids[i] = row.ID
	}
	return ids
}
