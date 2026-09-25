package redact_test

import (
	"bytes"
	"embed"
	"errors"
	"io"
	"reflect"
	"testing"

	"github.com/peasant-labs/redact"
	"github.com/peasant-labs/schema"
	"gopkg.in/yaml.v3"
)

//go:embed testdata/observation_disabled_calls.yaml
var externalObservationFixtures embed.FS

type externalObservationEngine struct {
	calls          int
	level, version string
}

var _ redact.Redactor = (*externalObservationEngine)(nil)

func (e *externalObservationEngine) Detect(string) []redact.Match { e.calls++; return nil }
func (e *externalObservationEngine) Redact(input string, _ []redact.Match) string {
	e.calls++
	return input
}
func (e *externalObservationEngine) RedactText(input string) string { e.calls++; return input }
func (e *externalObservationEngine) RedactJSON(value any) any       { e.calls++; return value }
func (e *externalObservationEngine) RedactMetadata(meta *schema.UnifiedMetadata) *schema.UnifiedMetadata {
	e.calls++
	return meta
}
func (e *externalObservationEngine) Report() redact.RedactionReport {
	return redact.RedactionReport{TotalRedactions: e.calls}
}
func (e *externalObservationEngine) Level() string          { return e.level }
func (e *externalObservationEngine) RuleSetVersion() string { return e.version }

type externalObservationFixture struct {
	Name     string          `yaml:"name"`
	Input    string          `yaml:"input"`
	Output   string          `yaml:"output"`
	Level    string          `yaml:"level"`
	Version  string          `yaml:"version"`
	Error    string          `yaml:"error"`
	ID       string          `yaml:"id"`
	Category redact.Category `yaml:"category"`
	Offset   int             `yaml:"offset"`
	Length   int             `yaml:"length"`
}

func decodeExternalObservationYAML(data []byte, out any) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return err
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("external observation fixture must contain exactly one YAML document")
		}
		return err
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return errors.New("external observation fixture must contain one YAML mapping document")
	}
	allowed := map[string]bool{
		"requiredAllocationNames": true, "allocationCases": true, "requiredNames": true, "cases": true,
		"requiredExternalNames": true, "externalCases": true, "requiredTitleNames": true, "titleCases": true,
		"requiredCoverageNames": true, "detect": true, "text": true, "parent": true, "coverageCases": true,
		"requiredConstructorNames": true, "nilError": true, "constructorCases": true,
	}
	var externalCases, requiredNames yaml.Node
	for i := 0; i < len(document.Content[0].Content); i += 2 {
		key, value := document.Content[0].Content[i].Value, document.Content[0].Content[i+1]
		if !allowed[key] {
			return errors.New("external observation fixture contains an unknown top-level key")
		}
		switch key {
		case "externalCases":
			externalCases = *value
		case "requiredExternalNames":
			requiredNames = *value
		}
	}
	file, ok := out.(*struct {
		Required []string                     `yaml:"requiredExternalNames"`
		Cases    []externalObservationFixture `yaml:"externalCases"`
	})
	if !ok {
		return errors.New("external observation decoder target has an unexpected shape")
	}
	requiredBytes, err := yaml.Marshal(&requiredNames)
	if err != nil {
		return err
	}
	requiredDecoder := yaml.NewDecoder(bytes.NewReader(requiredBytes))
	requiredDecoder.KnownFields(true)
	if err := requiredDecoder.Decode(&file.Required); err != nil {
		return err
	}
	if externalCases.Kind == 0 {
		return nil
	}
	caseBytes, err := yaml.Marshal(&externalCases)
	if err != nil {
		return err
	}
	caseDecoder := yaml.NewDecoder(bytes.NewReader(caseBytes))
	caseDecoder.KnownFields(true)
	if err := caseDecoder.Decode(&file.Cases); err != nil {
		return err
	}
	return nil
}

func TestObservationExternalCompatibility(t *testing.T) {
	data, err := externalObservationFixtures.ReadFile("testdata/observation_disabled_calls.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Required []string                     `yaml:"requiredExternalNames"`
		Cases    []externalObservationFixture `yaml:"externalCases"`
	}
	if err := decodeExternalObservationYAML(data, &file); err != nil {
		t.Fatal(err)
	}
	pinned := map[string]bool{"legacy_interface_implementation": false, "disabled_external_forwarding": false, "enabled_external_rejected": false, "public_unkeyed_rule_match": false}
	manifest := map[string]bool{}
	for _, name := range file.Required {
		if manifest[name] {
			t.Fatal("duplicate external fixture manifest name")
		}
		manifest[name] = true
	}
	seen := map[string]bool{}
	for _, row := range file.Cases {
		if seen[row.Name] || !manifest[row.Name] {
			t.Fatal("duplicate or unreviewed external fixture")
		}
		seen[row.Name] = true
		if _, ok := pinned[row.Name]; ok {
			pinned[row.Name] = true
		}
		t.Run(row.Name, func(t *testing.T) {
			engine := &externalObservationEngine{level: row.Level, version: row.Version}
			if row.Name == "enabled_external_rejected" {
				run, err := redact.NewRun(engine, "PRIVATE_RUN_ID", func(redact.Observation) error { t.Fatal("rejected constructor invoked callback"); return nil })
				if run != nil || err == nil || err.Error() != row.Error || engine.calls != 0 {
					t.Fatalf("unsupported enabled binding was not safely rejected: %v", err)
				}
				return
			}
			if row.Name == "public_unkeyed_rule_match" {
				rule := redact.Rule{row.ID, row.Category, "", nil, row.Output, nil}
				match := redact.Match{row.ID, row.Offset, row.Length, row.Category, row.Input}
				if rule.ID != row.ID || rule.Category != row.Category || match.MatchedText != row.Input || match.Length != row.Length {
					t.Fatal("public layout changed")
				}
				return
			}
			var legacy redact.Redactor = engine
			if legacy.Level() != row.Level || legacy.RuleSetVersion() != row.Version {
				t.Fatal("legacy interface methods changed")
			}
			if row.Name == "legacy_interface_implementation" {
				if legacy.Detect(row.Input) != nil || legacy.Redact(row.Input, nil) != row.Output || legacy.RedactText(row.Input) != row.Output || legacy.RedactJSON(row.Input) != row.Output || legacy.RedactMetadata(nil) != nil {
					t.Fatal("external implementation changed")
				}
			} else {
				run, err := redact.NewRun(legacy, "run", nil)
				if err != nil {
					t.Fatal(err)
				}
				matches, status := run.Detect("call", row.Input)
				if matches != nil || status != redact.DeliveryDisabled {
					t.Fatal("Detect not forwarded")
				}
				output, status := run.Redact("call", row.Input, nil)
				if output != row.Output || status != redact.DeliveryDisabled {
					t.Fatal("Redact not forwarded")
				}
				output, status = run.RedactText("call", row.Input)
				if output != row.Output || status != redact.DeliveryDisabled {
					t.Fatal("text not forwarded")
				}
				value, status := run.RedactJSON("call", row.Input)
				if value != row.Output || status != redact.DeliveryDisabled {
					t.Fatal("JSON not forwarded")
				}
				meta := &schema.UnifiedMetadata{}
				meta.CWD = row.Input
				result, status := run.RedactMetadata("call", meta)
				if result != meta || status != redact.DeliveryDisabled {
					t.Fatal("metadata not forwarded unchanged")
				}
			}
			if engine.Report().TotalRedactions != 5 {
				t.Fatal("each original public operation must be called exactly once")
			}
		})
	}
	if !reflect.DeepEqual(seen, manifest) {
		t.Fatal("external fixture manifest differs from rows")
	}
	for name, present := range pinned {
		if !present {
			t.Fatalf("missing pinned external fixture %s", name)
		}
	}
}
