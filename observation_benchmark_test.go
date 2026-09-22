package redact

import (
	"encoding/json"
	"github.com/peasant-labs/schema"
	"testing"
)

func BenchmarkObservation(b *testing.B) {
	rows, err := loadObservationAllocationFixtures()
	if err != nil {
		b.Fatal(err)
	}
	for _, row := range rows {
		b.Run(row.Name, func(b *testing.B) {
			// Setup and fixture decoding are outside the measured loop.
			var value any = []any{row.Input, json.Number(row.Number)}
			meta := &schema.UnifiedMetadata{}
			meta.CWD = row.Input
			setup, err := NewRedactor(Standard, nil, XDGPaths{})
			if err != nil {
				b.Fatal(err)
			}
			matches := setup.Detect(row.Input)
			bench := func(b *testing.B, observer Observer, legacyOnly bool) {
				engine, err := NewRedactor(Standard, nil, XDGPaths{})
				if err != nil {
					b.Fatal(err)
				}
				run, err := NewRun(engine, "benchmark", observer)
				if err != nil {
					b.Fatal(err)
				}
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					switch row.Operation {
					case "Detect":
						if legacyOnly {
							observationMatchesSink = engine.Detect(row.Input)
						} else {
							observationMatchesSink, _ = run.Detect("call", row.Input)
						}
					case "Redact":
						if legacyOnly {
							observationStringSink = engine.Redact(row.Input, matches)
						} else {
							observationStringSink, _ = run.Redact("call", row.Input, matches)
						}
					case "RedactText":
						if legacyOnly {
							observationStringSink = engine.RedactText(row.Input)
						} else {
							observationStringSink, _ = run.RedactText("call", row.Input)
						}
					case "RedactJSON":
						if legacyOnly {
							observationJSONSink = engine.RedactJSON(value)
						} else {
							observationJSONSink, _ = run.RedactJSON("call", value)
						}
					case "RedactMetadata":
						if legacyOnly {
							observationMetadataSink = engine.RedactMetadata(meta)
						} else {
							observationMetadataSink, _ = run.RedactMetadata("call", meta)
						}
					}
				}
			}
			b.Run("legacy", func(b *testing.B) { bench(b, nil, true) })
			b.Run("disabled", func(b *testing.B) { bench(b, nil, false) })
			b.Run("enabled", func(b *testing.B) { bench(b, func(Observation) error { return nil }, false) })
		})
	}
}
