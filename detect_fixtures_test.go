package redact

import (
	_ "embed"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	wantDetectFixtureFamilies = 1
	wantDetectParityRows      = 7
	wantDetectParityIDs       = "anthropic_key_minimal,email_standard,key_and_email_standard,no_match_minimal,empty_string,github_pat_minimal,aws_access_key_minimal"
)

//go:embed testdata/detect.yaml
var detectFixtureData []byte

type detectFixtures struct {
	Parity []detectParityFixture `yaml:"parity"`
}

type detectParityFixture struct {
	ID    string         `yaml:"id"`
	Level RedactionLevel `yaml:"level"`
	Input string         `yaml:"input"`
}

func loadDetectFixtures(t *testing.T) detectFixtures {
	t.Helper()

	var families map[string]yaml.Node
	if err := yaml.Unmarshal(detectFixtureData, &families); err != nil {
		t.Fatalf("decode testdata/detect.yaml while checking detector fixture families: %v", err)
	}
	if len(families) != wantDetectFixtureFamilies {
		t.Fatalf("detector fixture corpus has %d families, want %d; update the family guard deliberately", len(families), wantDetectFixtureFamilies)
	}
	if _, ok := families["parity"]; !ok {
		t.Fatalf("detector fixture corpus is missing required family %q", "parity")
	}

	var fixtures detectFixtures
	if err := yaml.Unmarshal(detectFixtureData, &fixtures); err != nil {
		t.Fatalf("decode testdata/detect.yaml while loading detector fixtures: %v", err)
	}
	if len(fixtures.Parity) != wantDetectParityRows {
		t.Fatalf("detector fixture family %q has %d rows, want %d; update its row guard deliberately", "parity", len(fixtures.Parity), wantDetectParityRows)
	}

	ids := make([]string, len(fixtures.Parity))
	seen := make(map[string]struct{}, len(fixtures.Parity))
	for i, row := range fixtures.Parity {
		if row.ID == "" {
			t.Fatalf("detector fixture family %q row %d has an empty identity", "parity", i)
		}
		if _, exists := seen[row.ID]; exists {
			t.Fatalf("detector fixture family %q has duplicate identity %q", "parity", row.ID)
		}
		seen[row.ID] = struct{}{}
		ids[i] = row.ID
		if row.Level != Minimal && row.Level != Standard && row.Level != Maximum {
			t.Fatalf("detector fixture %q has unsupported level %q", row.ID, row.Level)
		}
	}
	if got := strings.Join(ids, ","); got != wantDetectParityIDs {
		t.Fatalf("detector fixture family %q identities = %q, want %q; update the identity guard deliberately", "parity", got, wantDetectParityIDs)
	}

	return fixtures
}
