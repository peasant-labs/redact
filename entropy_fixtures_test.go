package redact

import (
	_ "embed"
	"fmt"

	"gopkg.in/yaml.v3"
)

//go:embed testdata/entropy.yaml
var entropyFixtureYAML []byte

type entropyFixtureFamily string

const (
	entropyFamilyUUID         entropyFixtureFamily = "uuid"
	entropyFamilySequential   entropyFixtureFamily = "sequential"
	entropyFamilyDollarPrefix entropyFixtureFamily = "dollar_prefix"
	entropyFamilyBase64       entropyFixtureFamily = "base64"
	entropyFamilyHex          entropyFixtureFamily = "hex"
)

type entropyThresholdRelation string

const (
	entropyThresholdBelow entropyThresholdRelation = "below"
	entropyThresholdAbove entropyThresholdRelation = "above"
)

type entropyBehaviorFixture struct {
	ID       string         `yaml:"id"`
	Level    RedactionLevel `yaml:"level"`
	Input    string         `yaml:"input"`
	Redacted bool           `yaml:"redacted"`
}

type entropyPrefilterFixture struct {
	ID              string               `yaml:"id"`
	Family          entropyFixtureFamily `yaml:"family"`
	Input           string               `yaml:"input"`
	Matched         bool                 `yaml:"matched"`
	DetectUnchanged bool                 `yaml:"detect_unchanged"`
}

type charsetEntropyFixture struct {
	ID                string                   `yaml:"id"`
	Family            entropyFixtureFamily     `yaml:"family"`
	Input             string                   `yaml:"input"`
	ThresholdRelation entropyThresholdRelation `yaml:"threshold_relation"`
	DetectRedacted    bool                     `yaml:"detect_redacted"`
}

type entropyPathFixture struct {
	ID   string `yaml:"id"`
	Path string `yaml:"path"`
}

type entropyFixtures struct {
	Behavior       []entropyBehaviorFixture  `yaml:"behavior"`
	Prefilters     []entropyPrefilterFixture `yaml:"prefilters"`
	CharsetEntropy []charsetEntropyFixture   `yaml:"charset_entropy"`
	Paths          []entropyPathFixture      `yaml:"paths"`
}

func loadEntropyFixtures() (entropyFixtures, error) {
	var fixtures entropyFixtures
	if err := yaml.Unmarshal(entropyFixtureYAML, &fixtures); err != nil {
		return entropyFixtures{}, fmt.Errorf("load entropy fixtures: decode testdata/entropy.yaml: %w", err)
	}
	if err := validateEntropyFixtures(fixtures); err != nil {
		return entropyFixtures{}, err
	}
	return fixtures, nil
}

func validateEntropyFixtures(fixtures entropyFixtures) error {
	if len(fixtures.Behavior) != 4 || len(fixtures.Prefilters) != 8 || len(fixtures.CharsetEntropy) != 4 || len(fixtures.Paths) != 7 {
		return fmt.Errorf("validate entropy fixtures: unexpected row counts behavior=%d prefilters=%d charset_entropy=%d paths=%d; update guards when intentionally changing testdata/entropy.yaml", len(fixtures.Behavior), len(fixtures.Prefilters), len(fixtures.CharsetEntropy), len(fixtures.Paths))
	}
	seen := make(map[string]string)
	checkID := func(section, id string) error {
		if id == "" {
			return fmt.Errorf("validate entropy fixtures: %s contains an empty id; assign every row a stable identity in testdata/entropy.yaml", section)
		}
		if prior, ok := seen[id]; ok {
			return fmt.Errorf("validate entropy fixtures: duplicate id %q in %s (already used in %s); use globally unique stable identities", id, section, prior)
		}
		seen[id] = section
		return nil
	}
	for _, row := range fixtures.Behavior {
		if err := checkID("behavior", row.ID); err != nil {
			return err
		}
		if row.Level != Maximum && row.Level != Standard {
			return fmt.Errorf("validate entropy fixtures: behavior %q has unsupported level %q; use maximum or standard", row.ID, row.Level)
		}
	}
	prefilterFamilies := map[entropyFixtureFamily]int{}
	for _, row := range fixtures.Prefilters {
		if err := checkID("prefilters", row.ID); err != nil {
			return err
		}
		switch row.Family {
		case entropyFamilyUUID, entropyFamilySequential, entropyFamilyDollarPrefix:
			prefilterFamilies[row.Family]++
		default:
			return fmt.Errorf("validate entropy fixtures: prefilter %q has unsupported family %q", row.ID, row.Family)
		}
	}
	if prefilterFamilies[entropyFamilyUUID] != 3 || prefilterFamilies[entropyFamilySequential] != 4 || prefilterFamilies[entropyFamilyDollarPrefix] != 1 {
		return fmt.Errorf("validate entropy fixtures: prefilter family counts uuid=%d sequential=%d dollar_prefix=%d; preserve every behavioral branch", prefilterFamilies[entropyFamilyUUID], prefilterFamilies[entropyFamilySequential], prefilterFamilies[entropyFamilyDollarPrefix])
	}
	charsetFamilies := map[entropyFixtureFamily]int{}
	relations := map[entropyThresholdRelation]int{}
	for _, row := range fixtures.CharsetEntropy {
		if err := checkID("charset_entropy", row.ID); err != nil {
			return err
		}
		if row.Family != entropyFamilyBase64 && row.Family != entropyFamilyHex {
			return fmt.Errorf("validate entropy fixtures: charset entropy %q has unsupported family %q", row.ID, row.Family)
		}
		if row.ThresholdRelation != entropyThresholdBelow && row.ThresholdRelation != entropyThresholdAbove {
			return fmt.Errorf("validate entropy fixtures: charset entropy %q has unsupported threshold relation %q", row.ID, row.ThresholdRelation)
		}
		charsetFamilies[row.Family]++
		relations[row.ThresholdRelation]++
	}
	if charsetFamilies[entropyFamilyBase64] != 2 || charsetFamilies[entropyFamilyHex] != 2 || relations[entropyThresholdBelow] != 2 || relations[entropyThresholdAbove] != 2 {
		return fmt.Errorf("validate entropy fixtures: charset family/relation guards failed base64=%d hex=%d below=%d above=%d", charsetFamilies[entropyFamilyBase64], charsetFamilies[entropyFamilyHex], relations[entropyThresholdBelow], relations[entropyThresholdAbove])
	}
	for _, row := range fixtures.Paths {
		if err := checkID("paths", row.ID); err != nil {
			return err
		}
	}
	return nil
}
