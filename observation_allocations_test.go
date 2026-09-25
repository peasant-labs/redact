//go:build !race

package redact

import (
	"encoding/json"
	"testing"

	"github.com/peasant-labs/schema"
)

var observationDeliverySink DeliveryStatus

// Exact heap comparisons run without race instrumentation: the race build
// randomly drops sync.Pool entries used by regexp. Functional gates still race.
func TestObservationDisabledAllocations(t *testing.T) {
	rows, err := loadObservationAllocationFixtures()
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		t.Run(row.Name, func(t *testing.T) {
			legacy, err := NewRedactor(Standard, nil, XDGPaths{})
			if err != nil {
				t.Fatal(err)
			}
			engine, err := NewRedactor(Standard, nil, XDGPaths{})
			if err != nil {
				t.Fatal(err)
			}
			disabled, err := NewRun(engine, "allocation", nil)
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
			var direct, forward func()
			switch row.Operation {
			case "Detect":
				direct = func() { observationMatchesSink = legacy.Detect(row.Input) }
				forward = func() { observationMatchesSink, observationDeliverySink = disabled.Detect("allocation", row.Input) }
			case "Redact":
				direct = func() { observationStringSink = legacy.Redact(row.Input, matches) }
				forward = func() {
					observationStringSink, observationDeliverySink = disabled.Redact("allocation", row.Input, matches)
				}
			case "RedactText":
				direct = func() { observationStringSink = legacy.RedactText(row.Input) }
				forward = func() { observationStringSink, observationDeliverySink = disabled.RedactText("allocation", row.Input) }
			case "RedactJSON":
				direct = func() { observationJSONSink = legacy.RedactJSON(value) }
				forward = func() { observationJSONSink, observationDeliverySink = disabled.RedactJSON("allocation", value) }
			case "RedactMetadata":
				direct = func() { observationMetadataSink = legacy.RedactMetadata(meta) }
				forward = func() { observationMetadataSink, observationDeliverySink = disabled.RedactMetadata("allocation", meta) }
			default:
				t.Fatal("missing allocation public-method closure")
			}
			direct()
			forward()
			directAllocs := testing.AllocsPerRun(100, direct)
			disabledAllocs := testing.AllocsPerRun(100, forward)
			t.Logf("disabled_allocs fixture=%s operation=%s legacy=%g disabled=%g delta=%g", row.Name, row.Operation, directAllocs, disabledAllocs, disabledAllocs-directAllocs)
			if directAllocs != disabledAllocs {
				t.Fatalf("%s/%s allocation sampling in TestObservationDisabledAllocations: direct=%g disabled=%g; disabled callers incur extra work; remove disabled instrumentation rather than relax this assertion", row.Name, row.Operation, directAllocs, disabledAllocs)
			}
			if observationDeliverySink != DeliveryDisabled || disabled.counter.Load() != 0 {
				t.Fatal("disabled measurement allocated call IDs or changed delivery status")
			}
		})
	}
}
