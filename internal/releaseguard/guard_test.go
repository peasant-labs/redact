package releaseguard

import (
	_ "embed"
	"testing"

	"gopkg.in/yaml.v3"
)

//go:embed testdata/release_guard.yaml
var guardFixtureYAML []byte

type guardFixture struct {
	Name      string `yaml:"name"`
	Operation string `yaml:"operation"`
	Input     string `yaml:"input"`
	Want      string `yaml:"want"`
	WantError bool   `yaml:"want_error"`
}

func TestGuardFixtures(t *testing.T) {
	var fixtures []guardFixture
	if err := yaml.Unmarshal(guardFixtureYAML, &fixtures); err != nil {
		t.Fatal(err)
	}
	if len(fixtures) != 10 {
		t.Fatalf("fixture count = %d, want 10", len(fixtures))
	}
	seen := map[string]bool{}
	for _, fixture := range fixtures {
		if fixture.Name == "" || seen[fixture.Name] {
			t.Fatalf("empty or duplicate fixture name %q", fixture.Name)
		}
		seen[fixture.Name] = true
		t.Run(fixture.Name, func(t *testing.T) {
			var got string
			var err error
			switch fixture.Operation {
			case "title":
				got, err = VersionFromTitle(fixture.Input)
			case "tag":
				var kind Kind
				var base string
				kind, base, err = ClassifyTag(fixture.Input)
				got = string(kind) + " " + base
			default:
				t.Fatalf("unknown fixture operation %q", fixture.Operation)
			}
			if (err != nil) != fixture.WantError {
				t.Fatalf("error = %v, want_error = %v", err, fixture.WantError)
			}
			if err == nil && got != fixture.Want {
				t.Fatalf("got %q, want %q", got, fixture.Want)
			}
		})
	}
}
