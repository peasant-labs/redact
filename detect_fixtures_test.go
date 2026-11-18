package redact

import (
	_ "embed"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	wantDetectFixtureFamilies = 3
	wantDetectParityRows      = 7
	wantDetectParityIDs       = "anthropic_key_minimal,email_standard,key_and_email_standard,no_match_minimal,empty_string,github_pat_minimal,aws_access_key_minimal"
)

//go:embed testdata/detect.yaml
var detectFixtureData []byte

type detectFixtures struct {
	Parity               []detectParityFixture    `yaml:"parity"`
	RequiredValueSpanIDs []string                 `yaml:"required_value_span_ids"`
	ValueSpans           []detectValueSpanFixture `yaml:"value_spans"`
}

// detectValueSpanFixture is a text, the configured patterns for it, and every
// match Detect must return for it at standard, in order. It pins where a
// value rule's match starts and ends, after detection settled its overlaps.
type detectValueSpanFixture struct {
	ID       string              `yaml:"id"`
	Why      string              `yaml:"why"`
	Input    string              `yaml:"input"`
	Patterns []UserPattern       `yaml:"patterns"`
	Matches  []detectSpanFixture `yaml:"matches"`
}

type detectSpanFixture struct {
	Rule   string `yaml:"rule"`
	Offset int    `yaml:"offset"`
	Length int    `yaml:"length"`
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
	for _, family := range []string{"parity", "required_value_span_ids", "value_spans"} {
		if _, ok := families[family]; !ok {
			t.Fatalf("detector fixture corpus is missing required family %q", family)
		}
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
	checkFixtureFamily(t, "value_spans", fixtures.RequiredValueSpanIDs, fixtureNames(fixtures.ValueSpans, func(row detectValueSpanFixture) string { return row.ID }))
	for _, row := range fixtures.ValueSpans {
		if row.Why == "" || row.Input == "" || len(row.Matches) == 0 {
			t.Fatalf("detector value span fixture %q is incomplete; why, input and matches are required", row.ID)
		}
	}

	return fixtures
}

// TestDetect_ValueSpanFixtures pins every match Detect returns for each row:
// its rule, offset and length, in order, and that MatchedText is the input
// between them.
func TestDetect_ValueSpanFixtures(t *testing.T) {
	for _, row := range loadDetectFixtures(t).ValueSpans {
		t.Run(row.ID, func(t *testing.T) {
			matches := mustNewRedactor(t, Standard, row.Patterns).Detect(row.Input)
			got := make([]detectSpanFixture, len(matches))
			for i, match := range matches {
				got[i] = detectSpanFixture{Rule: match.Rule, Offset: match.Offset, Length: match.Length}
				if match.MatchedText != row.Input[match.Offset:match.Offset+match.Length] {
					t.Errorf("match %d MatchedText = %q, want the input at its span, %q", i, match.MatchedText, row.Input[match.Offset:match.Offset+match.Length])
				}
			}
			if !slices.Equal(got, row.Matches) {
				t.Errorf("Detect(%q) = %+v, want %+v: %s", row.Input, got, row.Matches, row.Why)
			}
		})
	}
}
