package redact

import (
	"embed"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/peasant-labs/schema"
	"gopkg.in/yaml.v3"
)

//go:embed testdata/observation_*.yaml
var observationFixtures embed.FS

type observationFixture struct {
	Name             string                   `yaml:"name"`
	Operation        string                   `yaml:"operation"`
	Input            string                   `yaml:"input"`
	JSON             string                   `yaml:"json"`
	Metadata         string                   `yaml:"metadata"`
	Output           string                   `yaml:"output"`
	Detected         int                      `yaml:"detected"`
	Total            int                      `yaml:"total"`
	Status           DeliveryStatus           `yaml:"status"`
	Failure          string                   `yaml:"failure"`
	Events           []Observation            `yaml:"events"`
	Prior            string                   `yaml:"prior"`
	Other            string                   `yaml:"other"`
	OtherOutput      string                   `yaml:"otherOutput"`
	SameRun          bool                     `yaml:"sameRun"`
	Patterns         []UserPattern            `yaml:"patterns"`
	XDG              XDGPaths                 `yaml:"xdg"`
	Builtins         []observationRuleFixture `yaml:"builtins"`
	Level            RedactionLevel           `yaml:"level"`
	Forbidden        []string                 `yaml:"forbidden"`
	Authorized       []string                 `yaml:"authorized"`
	RunID            string                   `yaml:"runID"`
	CorrelationID    string                   `yaml:"correlationID"`
	FilterCalls      int                      `yaml:"filterCalls"`
	ReportCounts     map[string]int           `yaml:"reportCounts"`
	ReportCategories []string                 `yaml:"reportCategories"`
	TitleCategories  []CategoryString         `yaml:"titleCategories"`
}

type observationRuleFixture struct {
	ID          string         `yaml:"id"`
	Category    Category       `yaml:"category"`
	Pattern     string         `yaml:"pattern"`
	Replacement string         `yaml:"replacement"`
	Minimum     RedactionLevel `yaml:"minimum"`
	Filter      string         `yaml:"filter"`
}

func loadObservationFixtures(t testing.TB, family string, pinned ...string) []observationFixture {
	t.Helper()
	path := "testdata/observation_" + family + ".yaml"
	data, err := observationFixtures.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Required []string             `yaml:"requiredNames"`
		Cases    []observationFixture `yaml:"cases"`
	}
	if err := yaml.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(file.Cases))
	seen := make(map[string]bool)
	for _, row := range file.Cases {
		if seen[row.Name] {
			t.Fatalf("duplicate observation fixture %s in %s; use unique names", row.Name, path)
		}
		seen[row.Name] = true
		names = append(names, row.Name)
		if row.Status > DeliveryObserverErrorAndPanic {
			t.Fatalf("invalid delivery enum in %s", row.Name)
		}
		for _, event := range row.Events {
			validateObservationEnums(t, event)
		}
	}
	if err := requireFixtureNames(path, "observations", file.Required, names); err != nil {
		t.Fatal(err)
	}
	for _, name := range pinned {
		if !seen[name] {
			t.Fatalf("missing required observation fixture %s in %s; restore its coverage", name, path)
		}
	}
	return file.Cases
}

func validateObservationEnums(t testing.TB, event Observation) {
	t.Helper()
	if event.Operation < OperationDetect || event.Operation > OperationRedactMetadata || event.Diagnostic > DiagnosticEnginePanicked {
		t.Fatal("observation has an unknown operation or diagnostic")
	}
	check := func(count ObservedCount) {
		if count.Coverage > CoverageNotApplicable || count.Diagnostic > DiagnosticEnginePanicked || count.Value < 0 {
			t.Fatal("observation has an invalid count")
		}
		if count.Coverage == CoverageUnavailable {
			if count.Value != 0 || count.Diagnostic == DiagnosticNone {
				t.Fatal("unavailable count must have a reason and zero value")
			}
		} else if count.Diagnostic != DiagnosticNone || (count.Coverage == CoverageNotApplicable && count.Value != 0) {
			t.Fatal("measured/not-applicable count has invalid value or reason")
		}
	}
	check(event.RegexDetected)
	check(event.RegexApplied)
	check(event.ContextualReplacements)
	for _, rule := range event.Rules {
		if !rule.Category.IsValid() || rule.Rule.Origin < RuleOriginBuiltin || rule.Rule.Origin > RuleOriginRuntimeXDG || rule.Rule.Index < 0 || rule.Count <= 0 {
			t.Fatal("observation has an invalid rule fact")
		}
	}
}

func observationEngine(t testing.TB) Redactor {
	t.Helper()
	engine, err := NewRedactor(Standard, []UserPattern{{ID: "fixture", Category: CategoryPII, Pattern: "PRIVATE", Replacement: "<SAFE>"}}, XDGPaths{})
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func observationValue(t testing.TB, row observationFixture) (any, *schema.UnifiedMetadata) {
	t.Helper()
	var value any
	if row.JSON != "" {
		decoder := json.NewDecoder(strings.NewReader(row.JSON))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil {
			t.Fatal(err)
		}
	}
	var meta *schema.UnifiedMetadata
	if row.Metadata != "" {
		if err := json.Unmarshal([]byte(row.Metadata), &meta); err != nil {
			t.Fatal(err)
		}
	}
	return value, meta
}

func observationOutput(t testing.TB, value any) string {
	t.Helper()
	if s, ok := value.(string); ok {
		return s
	}
	var data strings.Builder
	encoder := json.NewEncoder(&data)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		t.Fatal(err)
	}
	return strings.TrimSuffix(data.String(), "\n")
}

func callObservation(t testing.TB, run *Run, engine Redactor, row observationFixture, correlation string) (any, DeliveryStatus) {
	t.Helper()
	value, meta := observationValue(t, row)
	switch row.Operation {
	case "Detect":
		if run != nil {
			return run.Detect(correlation, row.Input)
		}
		return engine.Detect(row.Input), DeliveryDisabled
	case "Redact":
		matches := observationEngine(t).Detect(row.Input)
		if run != nil {
			return run.Redact(correlation, row.Input, matches)
		}
		return engine.Redact(row.Input, matches), DeliveryDisabled
	case "RedactText":
		if run != nil {
			return run.RedactText(correlation, row.Input)
		}
		return engine.RedactText(row.Input), DeliveryDisabled
	case "RedactJSON":
		if run != nil {
			return run.RedactJSON(correlation, value)
		}
		return engine.RedactJSON(value), DeliveryDisabled
	case "RedactMetadata":
		if run != nil {
			return run.RedactMetadata(correlation, meta)
		}
		return engine.RedactMetadata(meta), DeliveryDisabled
	default:
		t.Fatal(fmt.Sprintf("unknown public operation %q in fixture %s", row.Operation, row.Name))
	}
	return nil, DeliveryDisabled
}
