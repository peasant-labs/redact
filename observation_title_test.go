package redact

import (
	"regexp"
	"slices"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestObservationTitleParity(t *testing.T) {
	data, err := observationFixtures.ReadFile("testdata/observation_disabled_calls.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Required []string             `yaml:"requiredTitleNames"`
		Cases    []observationFixture `yaml:"titleCases"`
	}
	if err := yaml.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	names := fixtureNames(file.Cases, func(row observationFixture) string { return row.Name })
	seen := make(map[string]bool)
	for _, name := range names {
		if seen[name] {
			t.Fatal("duplicate title observation fixture")
		}
		seen[name] = true
	}
	if err := requireFixtureNames("observation_disabled_calls.yaml", "title", file.Required, names); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"title_overlap_parity", "title_backreference_parity", "title_sensitive_category_parity"} {
		if !slices.Contains(names, name) {
			t.Fatalf("missing pinned title fixture %s", name)
		}
	}
	for _, row := range file.Cases {
		t.Run(row.Name, func(t *testing.T) {
			old := Rules
			t.Cleanup(func() { Rules = old })
			Rules = nil
			for _, spec := range row.Builtins {
				Rules = append(Rules, Rule{ID: spec.ID, Category: spec.Category, Pattern: regexp.MustCompile(spec.Pattern), Replacement: spec.Replacement})
			}
			pipeline, err := NewTitlePipeline()
			if err != nil {
				t.Fatal(err)
			}
			result, err := pipeline.Sanitize(row.Input, TitleContext{})
			if err != nil {
				t.Fatal(err)
			}
			if result.Text != row.Output || !slices.Equal(result.Categories, row.TitleCategories) {
				t.Fatalf("title result %#v want %q/%v", result, row.Output, row.TitleCategories)
			}
		})
	}
}
