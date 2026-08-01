package redact

import (
	_ "embed"
	"errors"
	"fmt"
	"testing"

	"gopkg.in/yaml.v3"
)

//go:embed testdata/category_strings.yaml
var categoryStringData []byte

type categoryStringFixture struct {
	Category       Category       `yaml:"category"`
	CategoryString CategoryString `yaml:"categoryString"`
}

type categoryStringFixtures struct {
	Mappings     []categoryStringFixture `yaml:"mappings"`
	Unknown      Category                `yaml:"unknown"`
	UnknownError string                  `yaml:"unknownError"`
}

func loadCategoryStringFixtures() (categoryStringFixtures, error) {
	var fixtures categoryStringFixtures
	if err := yaml.Unmarshal(categoryStringData, &fixtures); err != nil {
		return categoryStringFixtures{}, fmt.Errorf("redact: could not parse testdata/category_strings.yaml while loading canonical category renderings: %w; exact rendering coverage cannot run; fix the YAML syntax", err)
	}
	canonical := AllCategories()
	if len(fixtures.Mappings) != len(canonical) || fixtures.Unknown == "" || fixtures.UnknownError == "" {
		return categoryStringFixtures{}, fmt.Errorf("redact: category-string fixture is incomplete; want %d canonical mappings plus unknown and unknownError, got %d mappings; exact totality and failure coverage cannot run; restore the missing fixture values", len(canonical), len(fixtures.Mappings))
	}
	seenCategories := make(map[Category]struct{}, len(fixtures.Mappings))
	seenStrings := make(map[CategoryString]struct{}, len(fixtures.Mappings))
	for i, fixture := range fixtures.Mappings {
		if !fixture.Category.IsValid() || fixture.CategoryString == "" {
			return categoryStringFixtures{}, fmt.Errorf("redact: mappings[%d] is invalid; category must be canonical and categoryString must be non-empty; exact rendering coverage cannot run; fix the fixture", i)
		}
		if _, duplicate := seenCategories[fixture.Category]; duplicate {
			return categoryStringFixtures{}, fmt.Errorf("redact: category %q is duplicated in the category-string fixture; rendering is ambiguous; keep one mapping per category", fixture.Category)
		}
		if _, duplicate := seenStrings[fixture.CategoryString]; duplicate {
			return categoryStringFixtures{}, fmt.Errorf("redact: category string %q is duplicated in the category-string fixture; canonical labels must be distinct; keep one label per category", fixture.CategoryString)
		}
		seenCategories[fixture.Category] = struct{}{}
		seenStrings[fixture.CategoryString] = struct{}{}
	}
	for _, category := range canonical {
		if _, ok := seenCategories[category]; !ok {
			return categoryStringFixtures{}, fmt.Errorf("redact: category-string fixture is missing canonical category %q; exact totality cannot be proven; add its CategoryString rendering", category)
		}
	}
	return fixtures, nil
}

func TestCategoryString(t *testing.T) {
	fixtures, err := loadCategoryStringFixtures()
	if err != nil {
		t.Fatal(err)
	}
	byCategory := make(map[Category]CategoryString, len(fixtures.Mappings))
	for _, fixture := range fixtures.Mappings {
		byCategory[fixture.Category] = fixture.CategoryString
	}
	for _, category := range AllCategories() {
		category := category
		t.Run(string(category), func(t *testing.T) {
			if err := category.Validate(); err != nil {
				t.Fatalf("Category(%q).Validate(): %v", category, err)
			}
			got := category.String()
			if got != byCategory[category] {
				t.Errorf("Category(%q).String() = %q, want fixture rendering %q", category, got, byCategory[category])
			}
		})
	}

	err = fixtures.Unknown.Validate()
	if err == nil {
		t.Fatalf("Category(%q).Validate() returned nil error; unknown categories must fail closed", fixtures.Unknown)
	}
	var actionable *actionableError
	if !errors.As(err, &actionable) {
		t.Fatalf("Category(%q).Validate() error type = %T, want *actionableError", fixtures.Unknown, err)
	}
	if got := err.Error(); got != fixtures.UnknownError {
		t.Errorf("Category(%q).Validate() error =\n%s\nwant\n%s", fixtures.Unknown, got, fixtures.UnknownError)
	}
	if got := fixtures.Unknown.String(); got != "" {
		t.Errorf("Category(%q).String() = %q, want zero value rather than a valid fallback", fixtures.Unknown, got)
	}
}
