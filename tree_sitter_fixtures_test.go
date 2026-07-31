//go:build cgo

package redact

import (
	_ "embed"
	"testing"

	"gopkg.in/yaml.v3"
)

const wantTreeSitterAllLanguageRows = 5

//go:embed testdata/tree_sitter.yaml
var treeSitterFixtureData []byte

type treeSitterFixtures struct {
	AllLanguages []treeSitterLanguageFixture `yaml:"all_languages"`
}

type treeSitterLanguageFixture struct {
	ID          string   `yaml:"id"`
	Language    string   `yaml:"language"`
	Input       string   `yaml:"input"`
	MustAbsent  []string `yaml:"must_absent"`
	MustPresent []string `yaml:"must_present"`
}

func loadTreeSitterFixtures(t *testing.T) treeSitterFixtures {
	t.Helper()
	var fixtures treeSitterFixtures
	if err := yaml.Unmarshal(treeSitterFixtureData, &fixtures); err != nil {
		t.Fatalf("decode testdata/tree_sitter.yaml while loading tree-sitter fixtures: %v", err)
	}
	if got := len(fixtures.AllLanguages); got != wantTreeSitterAllLanguageRows {
		t.Fatalf("tree-sitter fixture family %q has %d rows, want %d; update its exact guard deliberately", "all_languages", got, wantTreeSitterAllLanguageRows)
	}

	wantLanguages := map[string]bool{
		"go":         false,
		"python":     false,
		"typescript": false,
		"javascript": false,
		"bash":       false,
	}
	seenIDs := make(map[string]struct{}, len(fixtures.AllLanguages))
	for rowNumber, row := range fixtures.AllLanguages {
		if row.ID == "" {
			t.Fatalf("tree-sitter fixture family %q row %d has an empty id; assign a stable identity", "all_languages", rowNumber)
		}
		if _, exists := seenIDs[row.ID]; exists {
			t.Fatalf("tree-sitter fixture family %q has duplicate id %q; use globally unique stable identities", "all_languages", row.ID)
		}
		seenIDs[row.ID] = struct{}{}
		seen, supported := wantLanguages[row.Language]
		if !supported {
			t.Fatalf("tree-sitter fixture %q has unsupported language %q", row.ID, row.Language)
		}
		if seen {
			t.Fatalf("tree-sitter fixture family %q has duplicate language %q; preserve exactly one row per language", "all_languages", row.Language)
		}
		wantLanguages[row.Language] = true
		if row.Input == "" || len(row.MustAbsent) == 0 || len(row.MustPresent) == 0 {
			t.Fatalf("tree-sitter fixture %q must define input, must_absent, and must_present expectations", row.ID)
		}
	}
	for language, seen := range wantLanguages {
		if !seen {
			t.Fatalf("tree-sitter fixture family %q is missing required language %q", "all_languages", language)
		}
	}
	return fixtures
}
