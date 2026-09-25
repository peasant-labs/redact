package redact

import (
	"reflect"
	"slices"
	"testing"
	"time"
)

func TestObservationEmptyCoverage(t *testing.T) {
	data, err := observationFixtures.ReadFile("testdata/observation_disabled_calls.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var file observationDocument
	if err := decodeObservationYAML(data, &file); err != nil {
		t.Fatal(err)
	}
	names := fixtureNames(file.CoverageCases, func(row observationFixture) string { return row.Name })
	seen := make(map[string]bool)
	for _, name := range names {
		if seen[name] {
			t.Fatal("duplicate coverage observation fixture")
		}
		seen[name] = true
	}
	if err := requireFixtureNames("observation_disabled_calls.yaml", "coverage", file.RequiredCoverageNames, names); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"empty_detect", "no_match_detect", "empty_redact", "empty_text", "no_match_text", "empty_json_array", "empty_json_map", "empty_metadata", "empty_ids"} {
		if !slices.Contains(names, name) {
			t.Fatalf("missing pinned coverage fixture %s", name)
		}
	}
	for _, row := range file.CoverageCases {
		t.Run(row.Name, func(t *testing.T) {
			engine, legacy := observationEngine(t), observationEngine(t)
			var events []Observation
			runID, correlation := "run", "call"
			if row.Name == "empty_ids" {
				runID, correlation = "", ""
			}
			run, err := NewRun(engine, runID, func(event Observation) error { events = append(events, event); return nil })
			if err != nil {
				t.Fatal(err)
			}
			got, status := callObservation(t, run, nil, row, correlation)
			want, _ := callObservation(t, nil, legacy, row, correlation)
			if status != DeliveryOK || !reflect.DeepEqual(got, want) {
				t.Fatal("empty/no-match result changed")
			}
			if row.Operation != "Detect" && row.Operation != "RedactMetadata" && observationOutput(t, got) != row.Output {
				t.Fatal("empty/no-match output not exact")
			}
			requireObservationEvents(t, events, row.Events)
			requireObservationReport(t, engine.Report(), legacy.Report())
		})
	}
}

func requireObservationEvents(t *testing.T, got, want []Observation) {
	t.Helper()
	// Nil and empty rule slices both mean no rule facts; compare their contents.
	// Duration is measured at runtime, so fixture records intentionally leave it
	// at zero. Validate it above, then compare the stable public facts only.
	normalized := slices.Clone(got)
	for i := range normalized {
		validateObservationEnums(t, normalized[i])
		normalized[i].Duration = 0
		if len(normalized[i].Rules) == 0 {
			normalized[i].Rules = nil
		}
	}
	for i := range want {
		if len(want[i].Rules) == 0 {
			want[i].Rules = nil
		}
	}
	if !reflect.DeepEqual(normalized, want) {
		t.Fatalf("completion records differ\ngot: %#v\nwant: %#v", normalized, want)
	}
}

func requireDurationPolicy(t *testing.T, events []Observation, policy string) {
	t.Helper()
	switch policy {
	case "parent":
		if len(events) != 1 || events[0].ParentCallID != 0 {
			t.Fatalf("duration policy %q requires one root observation: %#v", policy, events)
		}
	case "parent_and_children":
		if len(events) < 2 {
			t.Fatalf("duration policy %q requires a parent and child observations: %#v", policy, events)
		}
		parent := events[len(events)-1]
		if parent.ParentCallID != 0 {
			t.Fatalf("duration policy %q requires the final event to be the root: %#v", policy, events)
		}
		for _, event := range events[:len(events)-1] {
			if event.ParentCallID != parent.CallID {
				t.Fatalf("duration policy %q has an unrelated child: %#v", policy, event)
			}
		}
	default:
		t.Fatalf("unknown observation duration policy %q", policy)
	}
	for _, event := range events {
		if event.Duration < 0 {
			t.Fatalf("duration policy %q has a negative duration: %#v", policy, event)
		}
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
			if row.MetadataOutput != "" {
				_, golden := observationValue(t, observationFixture{Metadata: row.MetadataOutput})
				if !reflect.DeepEqual(got, golden) {
					t.Fatal("metadata differs from exact golden output")
				}
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
	data, err := observationFixtures.ReadFile("testdata/observation_disabled_calls.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var file observationDocument
	if err := decodeObservationYAML(data, &file); err != nil {
		t.Fatal(err)
	}
	var names []string
	seen := map[string]bool{}
	for _, row := range file.ConstructorCases {
		if seen[row.Name] {
			t.Fatal("duplicate constructor fixture")
		}
		seen[row.Name] = true
		names = append(names, row.Name)
		t.Run(row.Name, func(t *testing.T) {
			var engine Redactor
			if row.Typed {
				var typedNil *DefaultRedactor
				engine = typedNil
			}
			var observer Observer
			if row.Enabled {
				observer = func(Observation) error { t.Fatal("constructor invoked callback"); return nil }
			}
			run, err := NewRun(engine, "PRIVATE_RUN_ID", observer)
			if run != nil || err == nil || err.Error() != row.Error {
				t.Fatalf("nil constructor result differs from fixed safe fixture: %v", err)
			}
		})
	}
	if err := requireFixtureNames("observation_disabled_calls.yaml", "constructors", file.RequiredConstructorNames, names); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"nil_interface_disabled", "nil_interface_enabled", "typed_nil_disabled", "typed_nil_enabled"} {
		if !seen[name] {
			t.Fatalf("missing required constructor fixture %s", name)
		}
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
			if row.MetadataOutput != "" {
				_, golden := observationValue(t, observationFixture{Metadata: row.MetadataOutput})
				if !reflect.DeepEqual(got, golden) {
					t.Fatal("nested metadata differs from exact golden output")
				}
			}
			if row.Operation != "RedactMetadata" || row.Metadata == "null" {
				if observationOutput(t, got) != row.Output {
					t.Fatalf("output %q want %q", observationOutput(t, got), row.Output)
				}
			}
			requireObservationEvents(t, events, row.Events)
			requireDurationPolicy(t, events, row.DurationPolicy)
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

func TestObservationDuration(t *testing.T) {
	rows := loadObservationFixtures(t, "nested_calls", "json_string")
	var row observationFixture
	for _, candidate := range rows {
		if candidate.Name == "json_string" {
			row = candidate
			break
		}
	}
	if row.Name == "" {
		t.Fatal("missing json_string duration fixture")
	}

	engine := observationEngine(t).(*DefaultRedactor)
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	engine.userRules[0].FilterFn = func(string, string, int) bool {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		return true
	}

	var events []Observation
	run, err := NewRun(engine, "run", func(event Observation) error {
		events = append(events, event)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	value, _ := observationValue(t, row)
	result := make(chan struct {
		output any
		status DeliveryStatus
	}, 1)
	go func() {
		output, status := run.RedactJSON("call", value)
		result <- struct {
			output any
			status DeliveryStatus
		}{output: output, status: status}
	}()

	enteredTimer := time.NewTimer(time.Second)
	select {
	case <-entered:
		if !enteredTimer.Stop() {
			<-enteredTimer.C
		}
	case <-enteredTimer.C:
		close(release)
		t.Fatal("JSON redaction did not reach the fixture filter")
	}
	close(release)

	resultTimer := time.NewTimer(time.Second)
	var got struct {
		output any
		status DeliveryStatus
	}
	select {
	case got = <-result:
		if !resultTimer.Stop() {
			<-resultTimer.C
		}
	case <-resultTimer.C:
		t.Fatal("JSON redaction did not complete after releasing the fixture filter")
	}
	if got.status != row.Status || observationOutput(t, got.output) != row.Output {
		t.Fatalf("duration test changed JSON result/status: %#v %v", got.output, got.status)
	}
	requireObservationEvents(t, events, row.Events)
	requireDurationPolicy(t, events, row.DurationPolicy)
	for _, event := range events {
		if event.Duration <= 0 {
			t.Fatalf("enabled operation did not record a positive duration: %#v", event)
		}
	}
}

type hostileObservationError struct{}

func (hostileObservationError) Error() string { panic("PRIVATE_ERROR_PAYLOAD") }

func TestObservationObserverFailure(t *testing.T) {
	for _, row := range loadObservationFixtures(t, "observer_failure", "success", "hostile_error", "private_panic", "child_error_parent_panic", "retained_mutated_snapshot") {
		t.Run(row.Name, func(t *testing.T) {
			engine, legacy := observationEngine(t), observationEngine(t)
			var events []Observation
			var retained []Observation
			run, err := NewRun(engine, "run", func(event Observation) error {
				snapshot := event
				snapshot.Rules = slices.Clone(event.Rules)
				events = append(events, snapshot)
				retained = append(retained, event)
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
			} else {
				before := slices.Clone(events)
				_, nextStatus := callObservation(t, run, nil, row, "later")
				if nextStatus != row.Status || len(events) != 2*len(before) {
					t.Fatal("observer failure changed future callback delivery")
				}
				if !reflect.DeepEqual(retained[:len(before)], before) {
					t.Fatal("a later call changed an unmodified retained snapshot")
				}
			}
		})
	}
}
