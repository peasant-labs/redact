package redact

import (
	"reflect"
	"regexp"
	"testing"
)

type observationPanicResidue struct{ value any }

func (r observationPanicResidue) Scan(string) []ResidueWarning { panic(r.value) }

func observationCatch(f func()) (value any) { defer func() { value = recover() }(); f(); return nil }

func TestObservationRecovery(t *testing.T) {
	for _, row := range loadObservationFixtures(t, "recovery", "filter_fallback", "residue_fallback", "direct_detect_panic", "direct_application_panic", "fallback_propagates_panic", "json_child_recovered", "json_child_panicked", "observer_failure_after_recovery") {
		t.Run(row.Name, func(t *testing.T) {
			marker := &struct{ private string }{"PRIVATE_ENGINE_PANIC"}
			oldRules, oldCodeBlocks := Rules, codeBlockPattern
			t.Cleanup(func() { Rules = oldRules; codeBlockPattern = oldCodeBlocks })
			if row.Failure == "filter" || row.Failure == "detect" || row.Failure == "filter_observer" {
				Rules = []Rule{{ID: "builtin-fixture", Category: CategoryPII, Pattern: regexp.MustCompile("PRIVATE"), Replacement: "<SAFE>", FilterFn: func(string, string, int) bool { panic(marker) }}}
			}
			engine, legacy := observationEngine(t), observationEngine(t)
			if row.Failure == "residue" || row.Failure == "fallback" {
				engine.(*DefaultRedactor).residueDetector = observationPanicResidue{marker}
				legacy.(*DefaultRedactor).residueDetector = observationPanicResidue{marker}
			}
			if row.Failure == "fallback" {
				codeBlockPattern = nil
			}
			var events []Observation
			run, err := NewRun(engine, "run", func(event Observation) error {
				events = append(events, event)
				if row.Failure == "filter_observer" {
					panic("PRIVATE_CALLBACK_PANIC")
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			var got, want any
			var status DeliveryStatus
			invoke := func(observed bool) {
				if row.Failure == "application" {
					matches := []Match{{Rule: "PRIVATE_FORGED_RULE", Offset: 0, Length: -1, Category: Category("PRIVATE_CATEGORY"), MatchedText: "PRIVATE_CONTENT"}}
					if observed {
						got, status = run.Redact("call", row.Input, matches)
					} else {
						want = legacy.Redact(row.Input, matches)
					}
				} else if observed {
					got, status = callObservation(t, run, nil, row, "call")
				} else {
					want, _ = callObservation(t, nil, legacy, row, "call")
				}
			}
			legacyPanic := observationCatch(func() { invoke(false) })
			observedPanic := observationCatch(func() { invoke(true) })
			if !reflect.DeepEqual(observedPanic, legacyPanic) {
				t.Fatal("observed boundary replaced the legacy panic value")
			}
			if row.Failure == "detect" && observedPanic != marker {
				t.Fatal("direct Detect did not re-panic original object")
			}
			if row.Failure == "application" || row.Failure == "fallback" {
				if observedPanic == nil {
					t.Fatal("fixture did not reach a propagating panic")
				}
			}
			if legacyPanic == nil {
				if status != row.Status || !reflect.DeepEqual(got, want) || observationOutput(t, got) != row.Output {
					t.Fatalf("fallback output/status differs: %#v %#v %v", got, want, status)
				}
			}
			requireObservationEvents(t, events, row.Events)
			requireObservationReport(t, engine.Report(), legacy.Report())
			if engine.Report().TotalRedactions != row.Total {
				t.Fatal("fallback changed legacy detected-count report")
			}
		})
	}
}
