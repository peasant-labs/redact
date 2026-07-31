package redact

import (
	_ "embed"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	wantASTFixtureFamilies           = 3
	wantSupportedLanguageFixtureRows = 7
	wantLanguageHintFixtureRows      = 15
	wantWordExtractionFixtureRows    = 7
)

//go:embed testdata/ast.yaml
var astFixtureData []byte

type astFixtures struct {
	SupportedLanguages []supportedLanguageFixture `yaml:"supported_languages"`
	LanguageHints      []languageHintFixture      `yaml:"language_hints"`
	WordExtractions    []wordExtractionFixture    `yaml:"word_extractions"`
}

type supportedLanguageFixture struct {
	ID        string        `yaml:"id"`
	Lang      SupportedLang `yaml:"lang"`
	Supported bool          `yaml:"supported"`
}

type languageHintFixture struct {
	ID   string        `yaml:"id"`
	Hint string        `yaml:"hint"`
	Want SupportedLang `yaml:"want"`
}

type wordExtractionFixture struct {
	ID     string `yaml:"id"`
	S      string `yaml:"input"`
	Needle string `yaml:"needle"`
	Want   string `yaml:"want"`
}

type astFixtureFamilyGuard struct {
	name string
	got  int
	want int
	ids  []string
}

func loadASTFixtures(t *testing.T) astFixtures {
	t.Helper()
	var fixtures astFixtures
	if err := yaml.Unmarshal(astFixtureData, &fixtures); err != nil {
		t.Fatalf("decode testdata/ast.yaml while loading AST fixtures: %v", err)
	}
	var fixtureFamilies map[string]yaml.Node
	if err := yaml.Unmarshal(astFixtureData, &fixtureFamilies); err != nil {
		t.Fatalf("decode testdata/ast.yaml family index while loading AST fixtures: %v", err)
	}
	if len(fixtureFamilies) != wantASTFixtureFamilies {
		t.Fatalf("AST fixture document has %d families, want %d; update the family guard deliberately", len(fixtureFamilies), wantASTFixtureFamilies)
	}

	families := []astFixtureFamilyGuard{
		{"supported_languages", len(fixtures.SupportedLanguages), wantSupportedLanguageFixtureRows, supportedLanguageFixtureIDs(fixtures.SupportedLanguages)},
		{"language_hints", len(fixtures.LanguageHints), wantLanguageHintFixtureRows, languageHintFixtureIDs(fixtures.LanguageHints)},
		{"word_extractions", len(fixtures.WordExtractions), wantWordExtractionFixtureRows, wordExtractionFixtureIDs(fixtures.WordExtractions)},
	}
	seen := make(map[string]string)
	for _, family := range families {
		if family.got != family.want {
			t.Fatalf("AST fixture family %q has %d rows, want %d; update its row guard deliberately", family.name, family.got, family.want)
		}
		for row, id := range family.ids {
			if id == "" {
				t.Fatalf("AST fixture family %q row %d has an empty identity", family.name, row)
			}
			if priorFamily, exists := seen[id]; exists {
				t.Fatalf("AST fixture identity %q in family %q duplicates an identity in family %q", id, family.name, priorFamily)
			}
			seen[id] = family.name
		}
	}
	return fixtures
}

func supportedLanguageFixtureIDs(rows []supportedLanguageFixture) []string {
	ids := make([]string, len(rows))
	for i, row := range rows {
		ids[i] = row.ID
	}
	return ids
}

func languageHintFixtureIDs(rows []languageHintFixture) []string {
	ids := make([]string, len(rows))
	for i, row := range rows {
		ids[i] = row.ID
	}
	return ids
}

func wordExtractionFixtureIDs(rows []wordExtractionFixture) []string {
	ids := make([]string, len(rows))
	for i, row := range rows {
		ids[i] = row.ID
	}
	return ids
}
