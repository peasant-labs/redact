package redact

import (
	_ "embed"
	"fmt"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	wantLevelOrdFixtureRows   = 5
	wantLevelMaxFixtureRows   = 8
	wantLevelValidFixtureRows = 6
)

//go:embed testdata/levels.yaml
var levelFixtureYAML []byte

type levelOrdFixture struct {
	ID         string         `yaml:"id"`
	Level      RedactionLevel `yaml:"level"`
	Want       int            `yaml:"want"`
	WantString string         `yaml:"want_string"`
}

func TestValidateLevelFixturesRejectsEmptyID(t *testing.T) {
	fixtures, err := loadLevelFixtures()
	if err != nil {
		t.Fatal(err)
	}
	fixtures.Ord[0].ID = ""
	if err := validateLevelFixtures(fixtures); err == nil {
		t.Fatal("validateLevelFixtures() accepted an empty fixture identity")
	}
}

func TestValidateLevelFixturesRejectsDuplicateID(t *testing.T) {
	fixtures, err := loadLevelFixtures()
	if err != nil {
		t.Fatal(err)
	}
	fixtures.Valid[0].ID = fixtures.Max[0].ID
	if err := validateLevelFixtures(fixtures); err == nil {
		t.Fatal("validateLevelFixtures() accepted a duplicate fixture identity")
	}
}

type levelMaxFixture struct {
	ID   string         `yaml:"id"`
	A    RedactionLevel `yaml:"a"`
	B    RedactionLevel `yaml:"b"`
	Want RedactionLevel `yaml:"want"`
}

type levelValidFixture struct {
	ID    string         `yaml:"id"`
	Level RedactionLevel `yaml:"level"`
	Want  bool           `yaml:"want"`
}

type levelFixtures struct {
	Ord   []levelOrdFixture   `yaml:"ord"`
	Max   []levelMaxFixture   `yaml:"max"`
	Valid []levelValidFixture `yaml:"valid"`
}

func loadLevelFixtures() (levelFixtures, error) {
	var fixtures levelFixtures
	if err := yaml.Unmarshal(levelFixtureYAML, &fixtures); err != nil {
		return levelFixtures{}, fmt.Errorf("load level fixtures: decode testdata/levels.yaml: %w", err)
	}
	if err := validateLevelFixtures(fixtures); err != nil {
		return levelFixtures{}, err
	}
	return fixtures, nil
}

func validateLevelFixtures(fixtures levelFixtures) error {
	if len(fixtures.Ord) != wantLevelOrdFixtureRows || len(fixtures.Max) != wantLevelMaxFixtureRows || len(fixtures.Valid) != wantLevelValidFixtureRows {
		return fmt.Errorf("validate level fixtures: unexpected family row counts ord=%d max=%d valid=%d; want ord=%d max=%d valid=%d; update guards deliberately when changing testdata/levels.yaml", len(fixtures.Ord), len(fixtures.Max), len(fixtures.Valid), wantLevelOrdFixtureRows, wantLevelMaxFixtureRows, wantLevelValidFixtureRows)
	}

	seen := make(map[string]string, wantLevelOrdFixtureRows+wantLevelMaxFixtureRows+wantLevelValidFixtureRows)
	checkID := func(family, id string) error {
		if id == "" {
			return fmt.Errorf("validate level fixtures: family %q contains an empty id; assign every row a stable identity in testdata/levels.yaml", family)
		}
		if prior, exists := seen[id]; exists {
			return fmt.Errorf("validate level fixtures: duplicate id %q in family %q (already used in %q); use globally unique stable identities", id, family, prior)
		}
		seen[id] = family
		return nil
	}
	for _, row := range fixtures.Ord {
		if err := checkID("ord", row.ID); err != nil {
			return err
		}
	}
	for _, row := range fixtures.Max {
		if err := checkID("max", row.ID); err != nil {
			return err
		}
	}
	for _, row := range fixtures.Valid {
		if err := checkID("valid", row.ID); err != nil {
			return err
		}
	}
	return nil
}
