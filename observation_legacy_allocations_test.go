package redact

import (
	"encoding/json"
	"github.com/peasant-labs/schema"
	"testing"
)

var observationMatchesSink []Match
var observationStringSink string
var observationJSONSink any
var observationMetadataSink *schema.UnifiedMetadata

func TestObservationLegacyAllocations(t *testing.T) {
	fixtures, err := loadObservationAllocationFixtures()
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range fixtures {
		t.Run(row.Name, func(t *testing.T) {
			legacy, err := NewRedactor(Standard, nil, XDGPaths{})
			if err != nil {
				t.Fatal(err)
			}
			setup, err := NewRedactor(Standard, nil, XDGPaths{})
			if err != nil {
				t.Fatal(err)
			}
			matches := setup.Detect(row.Input)
			var value any = []any{row.Input, json.Number(row.Number)}
			meta := &schema.UnifiedMetadata{}
			meta.CWD = row.Input
			var measure func()
			switch row.Operation {
			case "Detect":
				measure = func() { observationMatchesSink = legacy.Detect(row.Input) }
			case "Redact":
				measure = func() { observationStringSink = legacy.Redact(row.Input, matches) }
			case "RedactText":
				measure = func() { observationStringSink = legacy.RedactText(row.Input) }
			case "RedactJSON":
				measure = func() { observationJSONSink = legacy.RedactJSON(value) }
			case "RedactMetadata":
				measure = func() { observationMetadataSink = legacy.RedactMetadata(meta) }
			default:
				t.Fatalf("unhandled allocation operation %q; add its public method closure", row.Operation)
			}
			measure()
			allocations := testing.AllocsPerRun(100, measure)
			if warnings := legacy.Report().Warnings; len(warnings) != 0 {
				t.Fatalf("allocation fixture grows residue history: %v; use a stable input", warnings)
			}
			t.Logf("legacy_allocs fixture=%s operation=%s value=%g", row.Name, row.Operation, allocations)
		})
	}
}
