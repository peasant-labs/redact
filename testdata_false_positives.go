package redact

import (
	_ "embed"
	"fmt"

	"gopkg.in/yaml.v3"
)

//go:embed testdata/false_positives.yaml
var falsePositiveFixtureData []byte

// FalsePositiveCase is a single fixture entry in testdata/false_positives.yaml.
// Each case specifies an input string, the rule under test, the expected outcome
// ("match" or "no_match"), a human-readable reason, and the provenance of the case.
type FalsePositiveCase struct {
	// Name is a unique slug used as the t.Run subtest name.
	Name string `yaml:"name"`
	// Input is the text passed to Detect.
	Input string `yaml:"input"`
	// Rule is the rule ID to look for in the returned matches (e.g. "aws_secret_key").
	Rule string `yaml:"rule"`
	// Expect is either "match" or "no_match".
	//   "match"    — the rule must fire on the input (true positive).
	//   "no_match" — the rule must NOT fire on the input (false positive guard).
	Expect string `yaml:"expect"`
	// Level is the redaction level at which to run Detect. Empty means Standard.
	Level RedactionLevel `yaml:"level"`
	// Reason documents why the case behaves as expected.
	Reason string `yaml:"reason"`
	// Source records where the pattern was observed:
	//   "real_transcript" — from an actual agent session
	//   "detect_secrets"  — from the detect-secrets reference implementation
	//   "synthetic"       — hand-crafted for coverage
	Source string `yaml:"source"`
}

type falsePositiveFixtures struct {
	Cases []FalsePositiveCase `yaml:"cases"`
}

// LoadFalsePositiveFixtures parses the embedded YAML fixture file and returns
// all test cases. Returns an error if the YAML is malformed.
func LoadFalsePositiveFixtures() ([]FalsePositiveCase, error) {
	return loadFalsePositiveFixtures(falsePositiveFixtureData)
}

// loadFalsePositiveFixtures keeps the embedded public loader small while
// allowing malformed and semantically invalid fixture bytes to exercise the
// same production parsing path in tests.
func loadFalsePositiveFixtures(data []byte) ([]FalsePositiveCase, error) {
	var f falsePositiveFixtures
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, &actionableError{
			what:  "the false-positive fixture YAML could not be parsed",
			why:   err.Error(),
			where: "pkg/redact/testdata/false_positives.yaml via LoadFalsePositiveFixtures",
			when:  "loading embedded redaction fixtures before running the false-positive corpus",
			means: "the corpus cannot run, so rule false-positive coverage is unavailable",
			fix:   "fix the YAML syntax in pkg/redact/testdata/false_positives.yaml",
			cause: err,
		}
	}
	for i, fixture := range f.Cases {
		if fixture.Level != "" && !fixture.Level.IsValid() {
			return nil, &actionableError{
				what:  fmt.Sprintf("fixture case %q at cases[%d] has invalid redaction level %q", fixture.Name, i, fixture.Level),
				why:   "fixture levels must be minimal, standard, maximum, or empty for the Standard default",
				where: "pkg/redact/testdata/false_positives.yaml via LoadFalsePositiveFixtures",
				when:  "validating embedded fixtures before selecting a redactor level",
				means: "the test cannot safely choose a level and the false-positive corpus cannot run",
				fix:   "set the fixture level to minimal, standard, maximum, or remove it to use Standard",
			}
		}
	}
	return f.Cases, nil
}
