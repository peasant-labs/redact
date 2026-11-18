//go:build !no_re2

package redact

import (
	_ "embed"
	"encoding/hex"
	"regexp"
	"testing"

	"gopkg.in/yaml.v3"
)

//go:embed testdata/engine_invalid_utf8.yaml
var engineInvalidUTF8Data []byte

const engineInvalidUTF8FixturePath = "testdata/engine_invalid_utf8.yaml"

type engineInvalidUTF8Case struct {
	Name            string `yaml:"name"`
	InputHex        string `yaml:"input_hex"`
	Pattern         string `yaml:"pattern"`
	Replacement     string `yaml:"replacement"`
	StdlibOutputHex string `yaml:"stdlib_output_hex"`
	RE2OutputHex    string `yaml:"re2_output_hex"`
	StdlibSpans     int    `yaml:"stdlib_spans"`
	RE2Spans        int    `yaml:"re2_spans"`
	Why             string `yaml:"why"`
}

type engineInvalidUTF8Fixtures struct {
	RequiredNames []string                `yaml:"required_names"`
	Cases         []engineInvalidUTF8Case `yaml:"cases"`
}

func loadEngineInvalidUTF8Fixtures(t *testing.T) engineInvalidUTF8Fixtures {
	t.Helper()
	var fixtures engineInvalidUTF8Fixtures
	if err := yaml.Unmarshal(engineInvalidUTF8Data, &fixtures); err != nil {
		t.Fatal(err)
	}
	if err := requireFixtureNames(engineInvalidUTF8FixturePath, "required_names", fixtures.RequiredNames, fixtureNames(fixtures.Cases, func(row engineInvalidUTF8Case) string { return row.Name })); err != nil {
		t.Fatal(err)
	}
	for _, row := range fixtures.Cases {
		if row.Why == "" {
			t.Fatalf("%s: add a why sentence; this fixture is a reviewed contract pin", row.Name)
		}
		if _, err := hex.DecodeString(row.InputHex); err != nil {
			t.Fatalf("%s: input_hex is not hex: %v", row.Name, err)
		}
		if _, err := hex.DecodeString(row.StdlibOutputHex); err != nil {
			t.Fatalf("%s: stdlib_output_hex is not hex: %v", row.Name, err)
		}
		if _, err := hex.DecodeString(row.RE2OutputHex); err != nil {
			t.Fatalf("%s: re2_output_hex is not hex: %v", row.Name, err)
		}
		if _, err := regexp.Compile(row.Pattern); err != nil {
			t.Fatalf("%s: probe pattern is invalid: %v", row.Name, err)
		}
		if row.StdlibOutputHex == row.RE2OutputHex {
			t.Fatalf("%s: outputs are equal; the fixture no longer pins a divergence", row.Name)
		}
		if row.RE2Spans > row.StdlibSpans {
			t.Fatalf("%s: go-re2 reports more spans than stdlib; review the engine change before accepting it", row.Name)
		}
	}
	return fixtures
}

// TestEngineInvalidUTF8Divergence is a contract pin, not a parity requirement.
// The public input contract is valid UTF-8. This test records what happens when
// that contract is violated, so a change in go-re2's handling is reviewed.
func TestEngineInvalidUTF8Divergence(t *testing.T) {
	for _, row := range loadEngineInvalidUTF8Fixtures(t).Cases {
		t.Run(row.Name, func(t *testing.T) {
			inputBytes, err := hex.DecodeString(row.InputHex)
			if err != nil {
				t.Fatal(err)
			}
			input := string(inputBytes)
			pattern := UserPattern{
				ID:          "invalid-utf8-probe",
				Category:    CategorySecrets,
				Pattern:     row.Pattern,
				Replacement: row.Replacement,
			}
			stdlib, err := newRedactorWithEngine(goRegexpEngine{}, Standard, []UserPattern{pattern}, XDGPaths{})
			if err != nil {
				t.Fatal(err)
			}
			re2, err := newRedactorWithEngine(goRE2Engine{}, Standard, []UserPattern{pattern}, XDGPaths{})
			if err != nil {
				t.Fatal(err)
			}

			if got := hex.EncodeToString([]byte(stdlib.RedactText(input))); got != row.StdlibOutputHex {
				t.Fatalf("stdlib output = %s, want %s", got, row.StdlibOutputHex)
			}
			if got := hex.EncodeToString([]byte(re2.RedactText(input))); got != row.RE2OutputHex {
				t.Fatalf("go-re2 output = %s, want %s", got, row.RE2OutputHex)
			}
			if got, want := len(stdlib.Detect(input)), row.StdlibSpans; got != want {
				t.Fatalf("stdlib spans = %d, want %d", got, want)
			}
			if got, want := len(re2.Detect(input)), row.RE2Spans; got != want {
				t.Fatalf("go-re2 spans = %d, want %d", got, want)
			}
		})
	}
}
