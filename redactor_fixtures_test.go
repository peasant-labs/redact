package redact

import (
	_ "embed"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	wantSecretsFixtureRows   = 16
	wantPIIFixtureRows       = 6
	wantPathFixtureRows      = 17
	wantCodeBlockFixtureRows = 4
	wantParityFixtureRows    = 5
)

//go:embed testdata/redactor_behavior.yaml
var redactorBehaviorFixtureData []byte

type redactorBehaviorFixtures struct {
	Secrets    []textRedactionFixture `yaml:"secrets"`
	PII        []textRedactionFixture `yaml:"pii"`
	Paths      []textRedactionFixture `yaml:"paths"`
	CodeBlocks []codeBlockFixture     `yaml:"code_blocks"`
	Parity     []parityFixture        `yaml:"parity"`
}

type textRedactionFixture struct {
	ID       string         `yaml:"id"`
	Level    RedactionLevel `yaml:"level"`
	Input    string         `yaml:"input"`
	Contains string         `yaml:"contains"`
	Absent   string         `yaml:"absent"`
}

type codeBlockFixture struct {
	ID    string `yaml:"id"`
	Input string `yaml:"input"`
	Want  string `yaml:"want"`
}
type parityFixture struct {
	ID    string         `yaml:"id"`
	Level RedactionLevel `yaml:"level"`
	Input string         `yaml:"input"`
	Want  string         `yaml:"want"`
}

func loadRedactorBehaviorFixtures(t *testing.T) redactorBehaviorFixtures {
	t.Helper()
	var fixtures redactorBehaviorFixtures
	if err := yaml.Unmarshal(redactorBehaviorFixtureData, &fixtures); err != nil {
		t.Fatalf("decode testdata/redactor_behavior.yaml while loading redactor behavior fixtures: %v", err)
	}
	checkFixtureFamily(t, "secrets", len(fixtures.Secrets), wantSecretsFixtureRows, textFixtureIDs(fixtures.Secrets))
	checkFixtureFamily(t, "pii", len(fixtures.PII), wantPIIFixtureRows, textFixtureIDs(fixtures.PII))
	checkFixtureFamily(t, "paths", len(fixtures.Paths), wantPathFixtureRows, textFixtureIDs(fixtures.Paths))
	checkFixtureFamily(t, "code_blocks", len(fixtures.CodeBlocks), wantCodeBlockFixtureRows, codeBlockFixtureIDs(fixtures.CodeBlocks))
	checkFixtureFamily(t, "parity", len(fixtures.Parity), wantParityFixtureRows, parityFixtureIDs(fixtures.Parity))
	for _, family := range [][]textRedactionFixture{fixtures.Secrets, fixtures.PII, fixtures.Paths} {
		for _, row := range family {
			checkFixtureLevel(t, row.ID, row.Level)
			if row.Contains == "" && row.Absent == "" {
				t.Fatalf("redactor behavior fixture %q has no expected outcome", row.ID)
			}
		}
	}
	for _, row := range fixtures.Parity {
		checkFixtureLevel(t, row.ID, row.Level)
	}
	return fixtures
}

func checkFixtureLevel(t *testing.T, id string, level RedactionLevel) {
	t.Helper()
	if level != Minimal && level != Standard && level != Maximum {
		t.Fatalf("redactor behavior fixture %q has unsupported level %q", id, level)
	}
}

func checkFixtureFamily(t *testing.T, family string, got, want int, ids []string) {
	t.Helper()
	if got != want {
		t.Fatalf("redactor behavior fixture family %q has %d rows, want %d; update its guard deliberately", family, got, want)
	}
	seen := make(map[string]struct{}, len(ids))
	for row, id := range ids {
		if id == "" {
			t.Fatalf("redactor behavior fixture family %q row %d has an empty identity", family, row)
		}
		if _, exists := seen[id]; exists {
			t.Fatalf("redactor behavior fixture family %q has duplicate identity %q", family, id)
		}
		seen[id] = struct{}{}
	}
}

func textFixtureIDs(rows []textRedactionFixture) []string {
	ids := make([]string, len(rows))
	for i, row := range rows {
		ids[i] = row.ID
	}
	return ids
}
func codeBlockFixtureIDs(rows []codeBlockFixture) []string {
	ids := make([]string, len(rows))
	for i, row := range rows {
		ids[i] = row.ID
	}
	return ids
}
func parityFixtureIDs(rows []parityFixture) []string {
	ids := make([]string, len(rows))
	for i, row := range rows {
		ids[i] = row.ID
	}
	return ids
}
