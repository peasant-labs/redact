package redact

import (
	_ "embed"
	"fmt"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

//go:embed testdata/category_validation.yaml
var categoryValidationFixtureData []byte

type invalidCategoryCaseKind string

const (
	invalidCategoryEmptyKind       invalidCategoryCaseKind = "empty"
	invalidCategoryUnknownKind     invalidCategoryCaseKind = "unknown"
	invalidCategoryCapitalizedKind invalidCategoryCaseKind = "capitalized"
)

var allInvalidCategoryCaseKinds = [...]invalidCategoryCaseKind{
	invalidCategoryEmptyKind,
	invalidCategoryUnknownKind,
	invalidCategoryCapitalizedKind,
}

func (k invalidCategoryCaseKind) isValid() bool {
	switch k {
	case invalidCategoryEmptyKind, invalidCategoryUnknownKind, invalidCategoryCapitalizedKind:
		return true
	default:
		return false
	}
}

type invalidCategoryFixture struct {
	Name     string                  `yaml:"name"`
	Kind     invalidCategoryCaseKind `yaml:"kind"`
	Category Category                `yaml:"category"`
}

type categoryValidationFixtures struct {
	Invalid []invalidCategoryFixture `yaml:"invalid"`
}

func loadCategoryValidationFixtures() ([]invalidCategoryFixture, error) {
	var fixtures categoryValidationFixtures
	if err := yaml.Unmarshal(categoryValidationFixtureData, &fixtures); err != nil {
		return nil, fmt.Errorf("redact: could not parse pkg/redact/testdata/category_validation.yaml while loading invalid-category cases: %w; category validation coverage cannot run; fix the YAML syntax", err)
	}
	if len(fixtures.Invalid) != len(allInvalidCategoryCaseKinds) {
		return nil, fmt.Errorf("redact: pkg/redact/testdata/category_validation.yaml defines %d invalid-category cases, want %d; exact empty, unknown, and capitalized coverage is incomplete or duplicated; restore one case per supported kind", len(fixtures.Invalid), len(allInvalidCategoryCaseKinds))
	}

	seenNames := make(map[string]struct{}, len(fixtures.Invalid))
	seenKinds := make(map[invalidCategoryCaseKind]struct{}, len(fixtures.Invalid))
	seenCategories := make(map[Category]struct{}, len(fixtures.Invalid))
	for i, fixture := range fixtures.Invalid {
		if fixture.Name == "" || !fixture.Kind.isValid() {
			return nil, fmt.Errorf("redact: invalid category case invalid[%d] is incomplete; name and a supported kind are required; exact invalid-category coverage cannot run; fill in the missing fixture value", i)
		}
		if fixture.Category.IsValid() {
			return nil, fmt.Errorf("redact: invalid category case %q uses canonical category %q; the negative case would be vacuous; set an invalid category value", fixture.Name, fixture.Category)
		}
		if _, duplicate := seenNames[fixture.Name]; duplicate {
			return nil, fmt.Errorf("redact: invalid category case name %q is duplicated; subtest identity is ambiguous; give every case a unique name", fixture.Name)
		}
		seenNames[fixture.Name] = struct{}{}
		if _, duplicate := seenKinds[fixture.Kind]; duplicate {
			return nil, fmt.Errorf("redact: invalid category kind %q is duplicated; exact branch membership is ambiguous; keep one case per kind", fixture.Kind)
		}
		seenKinds[fixture.Kind] = struct{}{}
		if _, duplicate := seenCategories[fixture.Category]; duplicate {
			return nil, fmt.Errorf("redact: invalid category value %q is duplicated; distinct failure modes would exercise the same input; give every kind a distinct value", fixture.Category)
		}
		seenCategories[fixture.Category] = struct{}{}

		switch fixture.Kind {
		case invalidCategoryEmptyKind:
			if fixture.Category != "" {
				return nil, fmt.Errorf("redact: invalid category case %q has kind empty but value %q; the empty-value branch is not covered; set category to the empty string", fixture.Name, fixture.Category)
			}
		case invalidCategoryUnknownKind:
			if fixture.Category == "" || fixture.Category != Category(strings.ToLower(string(fixture.Category))) {
				return nil, fmt.Errorf("redact: invalid category case %q has kind unknown but value %q; the lower-case unknown-value branch is not covered; use a non-empty lower-case value", fixture.Name, fixture.Category)
			}
		case invalidCategoryCapitalizedKind:
			if !isCapitalizedCanonicalCategory(fixture.Category) {
				return nil, fmt.Errorf("redact: invalid category case %q has kind capitalized but value %q; the case-sensitive canonical-name branch is not covered; capitalize a canonical category", fixture.Name, fixture.Category)
			}
		}
	}
	for _, kind := range allInvalidCategoryCaseKinds {
		if _, ok := seenKinds[kind]; !ok {
			return nil, fmt.Errorf("redact: category validation fixture is missing invalid kind %q; exact membership cannot be proven; add its typed case", kind)
		}
	}
	return fixtures.Invalid, nil
}

func isCapitalizedCanonicalCategory(category Category) bool {
	for _, canonical := range AllCategories() {
		if category != canonical && strings.EqualFold(string(category), string(canonical)) {
			return true
		}
	}
	return false
}

func TestCategory_IsValid(t *testing.T) {
	canonical := AllCategories()
	if len(canonical) == 0 {
		t.Fatal("AllCategories returned an empty canonical enumeration")
	}
	seenCanonical := make(map[Category]struct{}, len(canonical))
	for _, category := range canonical {
		if _, duplicate := seenCanonical[category]; duplicate {
			t.Fatalf("AllCategories returned duplicate canonical category %q; exact membership is ambiguous", category)
		}
		seenCanonical[category] = struct{}{}
		if !category.IsValid() {
			t.Errorf("canonical Category(%q).IsValid() = false, want true", category)
		}
	}

	fixtures, err := loadCategoryValidationFixtures()
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range fixtures {
		fixture := fixture
		t.Run(fixture.Name, func(t *testing.T) {
			if fixture.Category.IsValid() {
				t.Errorf("Category(%q).IsValid() = true, want false", fixture.Category)
			}
		})
	}
}

func TestAllCategoriesReturnsCopy(t *testing.T) {
	first := AllCategories()
	if len(first) == 0 {
		t.Fatal("AllCategories returned an empty canonical enumeration")
	}
	original := first[0]
	first[0] = Category("mutated-by-caller")
	second := AllCategories()
	if second[0] != original {
		t.Fatalf("AllCategories shared mutable state: second[0] = %q, want %q", second[0], original)
	}
}
