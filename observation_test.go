package redact

import (
	"reflect"
	"slices"
	"testing"
)

func requireObservationEvents(t *testing.T, got, want []Observation) {
	t.Helper()
	// Nil and empty rule slices both mean no rule facts; compare their contents.
	for i := range got {
		validateObservationEnums(t, got[i])
		if len(got[i].Rules) == 0 {
			got[i].Rules = nil
		}
	}
	for i := range want {
		if len(want[i].Rules) == 0 {
			want[i].Rules = nil
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("completion records differ\ngot: %#v\nwant: %#v", got, want)
	}
}

func requireObservationReport(t *testing.T, got, want RedactionReport) {
	t.Helper()
	slices.Sort(got.Categories)
	slices.Sort(want.Categories)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("legacy report changed\ngot: %#v\nwant: %#v", got, want)
	}
}

func TestObservationDisabled(t *testing.T) {
	for _, row := range loadObservationFixtures(t, "disabled_calls", "detect_nonempty", "detect_empty_preserves_matches", "redact_nonempty", "redact_empty", "text_nonempty", "text_empty", "json_array", "json_scalar", "metadata_nonempty", "metadata_nil") {
		t.Run(row.Name, func(t *testing.T) {
			legacy, engine := observationEngine(t), observationEngine(t)
			if row.Prior != "" {
				legacy.RedactText(row.Prior)
				engine.RedactText(row.Prior)
			}
			run, err := NewRun(engine, "run", nil)
			if err != nil {
				t.Fatal(err)
			}
			got, status := callObservation(t, run, nil, row, "call")
			want, _ := callObservation(t, nil, legacy, row, "call")
			if !reflect.DeepEqual(got, want) || status != DeliveryDisabled || run.counter.Load() != 0 {
				t.Fatalf("disabled forwarding changed output/status/counter: %#v %#v %v %d", got, want, status, run.counter.Load())
			}
			if row.Operation == "Detect" {
				if len(got.([]Match)) != row.Detected {
					t.Fatal("wrong accepted matches")
				}
			} else if row.Operation != "RedactMetadata" || row.Metadata == "null" {
				if observationOutput(t, got) != row.Output {
					t.Fatalf("output %q want %q", observationOutput(t, got), row.Output)
				}
			}
			requireObservationReport(t, engine.Report(), legacy.Report())
			if engine.Report().TotalRedactions != row.Total {
				t.Fatal("wrong report total")
			}
			if row.Prior != "" && len(engine.Report().Matches) != 1 {
				t.Fatal("empty Detect cleared prior last matches")
			}
		})
	}
}

func TestObservationConstructor(t *testing.T) {
	// Both nil forms must be rejected before any operation or callback.
	var typedNil *DefaultRedactor
	if run, err := NewRun(nil, "private", nil); run != nil || err == nil {
		t.Fatal("nil engine accepted")
	}
	if run, err := NewRun(typedNil, "private", func(Observation) error { t.Fatal("callback during construction"); return nil }); run != nil || err == nil {
		t.Fatal("typed nil engine accepted")
	}
}

func TestObservationNested(t *testing.T) {
	for _, row := range loadObservationFixtures(t, "nested_calls", "json_string", "json_nested", "json_number", "metadata_nil", "metadata_fields") {
		t.Run(row.Name, func(t *testing.T) {
			engine, legacy := observationEngine(t), observationEngine(t)
			var events []Observation
			run, err := NewRun(engine, "run", func(event Observation) error { events = append(events, event); return nil })
			if err != nil {
				t.Fatal(err)
			}
			got, status := callObservation(t, run, nil, row, "call")
			want, _ := callObservation(t, nil, legacy, row, "call")
			if status != row.Status || !reflect.DeepEqual(got, want) {
				t.Fatalf("nested result/status mismatch: %v %#v %#v", status, got, want)
			}
			if row.Operation != "RedactMetadata" || row.Metadata == "null" {
				if observationOutput(t, got) != row.Output {
					t.Fatalf("output %q want %q", observationOutput(t, got), row.Output)
				}
			}
			requireObservationEvents(t, events, row.Events)
			requireObservationReport(t, engine.Report(), legacy.Report())
			if engine.Report().TotalRedactions != row.Total {
				t.Fatalf("total %d want %d", engine.Report().TotalRedactions, row.Total)
			}
			if row.Name == "metadata_fields" {
				_, original := observationValue(t, row)
				before := observationOutput(t, original)
				copy, _ := run.RedactMetadata("immutability", original)
				if observationOutput(t, original) != before || original.Git.Remote == copy.Git.Remote || &original.Diagnostics.Warnings[0] == &copy.Diagnostics.Warnings[0] {
					t.Fatal("metadata input changed or copy aliases pointers/slices")
				}
				if copy.CWD != "<SAFE>" || *copy.Git.Remote != "<SAFE>" || *copy.Git.Branch != "<SAFE>" || *copy.Git.Worktree != "<SAFE>" || *copy.Git.Tracking != "<SAFE>" || copy.Diagnostics.Warnings[0].Message != "<SAFE>" || copy.Diagnostics.Warnings[0].Location != "<SAFE>" {
					t.Fatal("metadata fields not redacted")
				}
			}
		})
	}
}

type hostileObservationError struct{}

func (hostileObservationError) Error() string { panic("PRIVATE_ERROR_PAYLOAD") }

func TestObservationObserverFailure(t *testing.T) {
	for _, row := range loadObservationFixtures(t, "observer_failure", "success", "hostile_error", "private_panic", "child_error_parent_panic", "retained_mutated_snapshot") {
		t.Run(row.Name, func(t *testing.T) {
			engine, legacy := observationEngine(t), observationEngine(t)
			var events []Observation
			run, err := NewRun(engine, "run", func(event Observation) error {
				snapshot := event
				snapshot.Rules = slices.Clone(event.Rules)
				events = append(events, snapshot)
				switch row.Failure {
				case "error":
					return hostileObservationError{}
				case "panic":
					panic("PRIVATE_PANIC_PAYLOAD")
				case "combined":
					if event.ParentCallID != 0 {
						return hostileObservationError{}
					}
					panic("PRIVATE_PANIC_PAYLOAD")
				case "mutate":
					if len(event.Rules) > 0 {
						event.Rules[0].Count = 999
						event.Rules[0].Rule.ID = "mutated"
					}
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			got, status := callObservation(t, run, nil, row, "call")
			want, _ := callObservation(t, nil, legacy, row, "call")
			if status != row.Status || !reflect.DeepEqual(got, want) || observationOutput(t, got) != row.Output {
				t.Fatalf("observer changed output/status: %v %v", got, status)
			}
			requireObservationEvents(t, events, row.Events)
			requireObservationReport(t, engine.Report(), legacy.Report())
			if row.Failure == "mutate" {
				first := events[0]
				run.RedactText("later", row.Input)
				if !reflect.DeepEqual(first, events[0]) || events[1].Rules[0].Count != 1 || events[1].Rules[0].Rule.ID != "fixture" {
					t.Fatal("callback slice mutation affected retained/future snapshot")
				}
			}
		})
	}
}
