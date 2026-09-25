package redact

import (
	"embed"
	"fmt"
)

//go:embed testdata/observation_disabled_calls.yaml
var observationLegacyFixtures embed.FS

type observationAllocationFixture struct {
	Name       string `yaml:"name"`
	Allocation bool   `yaml:"allocation"`
	Operation  string `yaml:"operation"`
	Input      string `yaml:"input"`
	Number     string `yaml:"number"`
}

func loadObservationAllocationFixtures() ([]observationAllocationFixture, error) {
	const file = "testdata/observation_disabled_calls.yaml"
	data, err := observationLegacyFixtures.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var fixtures observationDocument
	if err := decodeObservationYAML(data, &fixtures); err != nil {
		return nil, fmt.Errorf("decode strict observation allocation fixtures: %w", err)
	}
	required := map[string]string{"alloc_detect": "Detect", "alloc_redact": "Redact", "alloc_redact_text": "RedactText", "alloc_redact_json": "RedactJSON", "alloc_redact_metadata": "RedactMetadata"}
	names := make([]string, 0, len(fixtures.Cases))
	seen := make(map[string]bool)
	for _, row := range fixtures.AllocationCases {
		if seen[row.Name] || !row.Allocation || required[row.Name] != row.Operation || row.Operation == "" {
			return nil, fmt.Errorf("redact: allocation fixture %q in %s has duplicate name or wrong operation membership; restore the five public-operation fixtures before measuring", row.Name, file)
		}
		seen[row.Name] = true
		names = append(names, row.Name)
	}
	for name := range required {
		if !seen[name] {
			return nil, fmt.Errorf("redact: missing allocation fixture %q in %s; restore it before measuring all public operations", name, file)
		}
	}
	if err := requireFixtureNames(file, "allocations", fixtures.RequiredAllocationNames, names); err != nil {
		return nil, err
	}
	return fixtures.AllocationCases, nil
}
