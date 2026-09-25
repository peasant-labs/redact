package redact

import (
	"encoding/json"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
)

type observationPreviewResidue struct{}

func (observationPreviewResidue) Scan(string) []ResidueWarning {
	return []ResidueWarning{{RuleID: "advisory", Location: 7, Preview: "PRIVATE_RESIDUE_PREVIEW"}}
}

func TestObservationPrivacy(t *testing.T) {
	for _, row := range loadObservationFixtures(t, "privacy_sentinel", "builtin_configured_collision", "configured_collision", "configured_runtime_collision", "filtered_inactive_rules", "text_single_scan", "forbidden_payloads", "forged_match") {
		t.Run(row.Name, func(t *testing.T) {
			old := Rules
			t.Cleanup(func() { Rules = old })
			Rules = nil
			calls := 0
			for _, spec := range row.Builtins {
				rule := Rule{ID: spec.ID, Category: spec.Category, MinimumLevel: spec.Minimum, Pattern: regexp.MustCompile(spec.Pattern), Replacement: spec.Replacement}
				if spec.Filter != "" {
					keep := spec.Filter == "accept"
					rule.FilterFn = func(string, string, int) bool { calls++; return keep }
				}
				Rules = append(Rules, rule)
			}
			engine, err := NewRedactor(Standard, row.Patterns, row.XDG)
			if err != nil {
				t.Fatal(err)
			}
			engine.(*DefaultRedactor).residueDetector = observationPreviewResidue{}
			var events []Observation
			run, err := NewRun(engine, row.RunID, func(event Observation) error {
				events = append(events, event)
				if row.Failure == "error" {
					return hostileObservationError{}
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			var output string
			var status DeliveryStatus
			switch row.Operation {
			case "Detect":
				matches, s := run.Detect(row.CorrelationID, row.Input)
				status = s
				if len(matches) != 1 {
					t.Fatal("accepted detection count changed")
				}
			case "Redact":
				output, status = run.Redact(row.CorrelationID, row.Input, row.Matches)
			case "RedactText":
				output, status = run.RedactText(row.CorrelationID, row.Input)
			default:
				t.Fatal("privacy fixture has unsupported operation")
			}
			wantStatus := row.Status
			if wantStatus == DeliveryDisabled {
				wantStatus = DeliveryOK
			}
			if output != row.Output || status != wantStatus {
				t.Fatalf("collision output/status %q/%v want %q/%v", output, status, row.Output, wantStatus)
			}
			if calls != row.FilterCalls {
				t.Fatalf("canonical filter invoked %d times, want %d; detection may have rescanned", calls, row.FilterCalls)
			}
			requireObservationEvents(t, events, row.Events)
			report := engine.Report()
			if row.Operation == "RedactText" && (len(report.Warnings) != 1 || !strings.Contains(report.Warnings[0], "PRIVATE_RESIDUE_PREVIEW")) {
				t.Fatal("privacy fixture did not exercise a real private residue preview")
			}
			slices.Sort(report.Categories)
			slices.Sort(row.ReportCategories)
			if report.TotalRedactions != row.Total || !reflect.DeepEqual(report.Counts, row.ReportCounts) || !slices.Equal(report.Categories, row.ReportCategories) {
				t.Fatalf("legacy collision/report precedence changed: %#v", report)
			}
			serialized, err := json.Marshal(events)
			if err != nil {
				t.Fatal(err)
			}
			for _, sentinel := range row.Forbidden {
				if strings.Contains(string(serialized), sentinel) {
					t.Fatalf("forbidden payload %q reached serialized observation", sentinel)
				}
				assertObservationNoString(t, reflect.ValueOf(events), sentinel)
			}
			for _, authorized := range row.Authorized {
				if !strings.Contains(string(serialized), authorized) {
					t.Fatalf("authorized ID %q was removed", authorized)
				}
			}
		})
	}
}

func assertObservationNoString(t *testing.T, value reflect.Value, sentinel string) {
	t.Helper()
	switch value.Kind() {
	case reflect.String:
		if strings.Contains(value.String(), sentinel) {
			t.Fatalf("private sentinel %q in retained record", sentinel)
		}
	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			assertObservationNoString(t, value.Field(i), sentinel)
		}
	case reflect.Slice:
		for i := 0; i < value.Len(); i++ {
			assertObservationNoString(t, value.Index(i), sentinel)
		}
	}
}

func TestObservationClosedSchema(t *testing.T) {
	data, err := observationFixtures.ReadFile("testdata/observation_privacy_sentinel.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var fixture observationDocument
	if err := decodeObservationYAML(data, &fixture); err != nil {
		t.Fatal(err)
	}
	// These are type/enum membership manifests, not inline scenario cases.
	types := map[string]reflect.Type{"Observation": reflect.TypeFor[Observation](), "ObservedCount": reflect.TypeFor[ObservedCount](), "RuleDetection": reflect.TypeFor[RuleDetection](), "RuleIdentity": reflect.TypeFor[RuleIdentity]()}
	if len(types) != len(fixture.Schema) {
		t.Fatal("closed observation schema type membership changed")
	}
	for name, typ := range types {
		var fields []string
		for i := 0; i < typ.NumField(); i++ {
			fields = append(fields, typ.Field(i).Name)
		}
		if !slices.Equal(fields, fixture.Schema[name]) {
			t.Fatalf("observation schema %s changed fields: %v", name, fields)
		}
	}
	enums := map[string][]int{
		"Operation":      {int(OperationDetect), int(OperationRedact), int(OperationRedactText), int(OperationRedactJSON), int(OperationRedactMetadata)},
		"Coverage":       {int(CoverageUnavailable), int(CoverageComplete), int(CoverageNotApplicable)},
		"DiagnosticCode": {int(DiagnosticNone), int(DiagnosticNotMeasured), int(DiagnosticEngineRecovered), int(DiagnosticEnginePanicked)},
		"DeliveryStatus": {int(DeliveryDisabled), int(DeliveryOK), int(DeliveryObserverError), int(DeliveryObserverPanic), int(DeliveryObserverErrorAndPanic)},
		"RuleOrigin":     {int(RuleOriginBuiltin), int(RuleOriginConfigured), int(RuleOriginRuntimeXDG)},
	}
	if !reflect.DeepEqual(enums, fixture.Enums) {
		t.Fatal("closed observation enum membership changed")
	}
}
