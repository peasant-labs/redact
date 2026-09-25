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
	for _, row := range loadObservationDurationFixtures(t) {
		t.Run(row.Name, func(t *testing.T) {
			filterEntered := make(chan struct{}, len(row.Events))
			var events []Observation
			// Latch the first matching child: later queued callbacks must not
			// overwrite the result observed by that callback.
			firstPositiveCallback := false
			immediateDelivery := false
			output, status := runObservationDurationCall(t, row, filterEntered, func(event Observation) error {
				events = append(events, event)
				if event.ParentCallID != 0 && event.RegexDetected.Value > 0 && !firstPositiveCallback {
					firstPositiveCallback = true
					select {
					case <-filterEntered:
					default:
					}
					immediateDelivery = len(filterEntered) == 0
				}
				return nil
			})
			requireObservationDurationResult(t, row, output, status)
			requireObservationEvents(t, events, row.Events)
			requireDurationPolicy(t, events, row.DurationPolicy)
			if !immediateDelivery {
				t.Fatalf("automatic child delivery was deferred until parent traversal ended: %#v", events)
			}
			parent, childTotal := requireObservationDurationBounds(t, events)
			if parent.Duration < childTotal {
				t.Fatalf("parent duration %v omitted sequential child traversal totaling %v", parent.Duration, childTotal)
			}
		})
	}
}

func TestObservationDurationExcludesChildCallback(t *testing.T) {
	for _, row := range loadObservationDurationFixtures(t) {
		t.Run(row.Name, func(t *testing.T) {
			requireObservationDurationCallbackExclusion(t, row, DeliveryOK, func() error { return nil })
		})
	}
}

func TestObservationDurationExcludesChildCallbackError(t *testing.T) {
	for _, row := range loadObservationDurationFixtures(t) {
		t.Run(row.Name, func(t *testing.T) {
			requireObservationDurationCallbackExclusion(t, row, DeliveryObserverError, func() error {
				return hostileObservationError{}
			})
		})
	}
}

func TestObservationDurationExcludesChildCallbackPanic(t *testing.T) {
	for _, row := range loadObservationDurationFixtures(t) {
		t.Run(row.Name, func(t *testing.T) {
			requireObservationDurationCallbackExclusion(t, row, DeliveryObserverPanic, func() error {
				panic("PRIVATE_CALLBACK_PANIC_PAYLOAD")
			})
		})
	}
}

type observationDurationCallbackController struct {
	entered chan struct{}
	release chan struct{}
	stop    chan struct{}
}

func newObservationDurationCallbackController(hold time.Duration) *observationDurationCallbackController {
	controller := &observationDurationCallbackController{
		entered: make(chan struct{}),
		release: make(chan struct{}),
		stop:    make(chan struct{}),
	}
	go func() {
		select {
		case <-controller.entered:
		case <-controller.stop:
			return
		}
		timer := time.NewTimer(hold)
		defer timer.Stop()
		select {
		case <-timer.C:
			close(controller.release)
		case <-controller.stop:
		}
	}()
	return controller
}

func (c *observationDurationCallbackController) Hold() time.Duration {
	close(c.entered)
	started := time.Now()
	select {
	case <-c.release:
		return time.Since(started)
	case <-c.stop:
		return 0
	}
}

func (c *observationDurationCallbackController) Stop() {
	close(c.stop)
}

func requireObservationDurationCallbackExclusion(t *testing.T, row observationFixture, wantStatus DeliveryStatus, callbackAction func() error) {
	t.Helper()
	var baselineEvents []Observation
	baselineOutput, baselineStatus := runObservationDurationCall(t, row, make(chan struct{}, len(row.Events)), func(event Observation) error {
		baselineEvents = append(baselineEvents, event)
		return nil
	})
	requireObservationDurationResult(t, row, baselineOutput, baselineStatus)
	requireObservationEvents(t, baselineEvents, row.Events)
	baselineParent, baselineChildTotal := requireObservationDurationBounds(t, baselineEvents)
	// Make the measured hold dominate this fixture's relative work budget; this
	// keeps unrelated scheduler pauses from deciding the callback boundary.
	hold := 8 * (baselineParent.Duration + baselineChildTotal)
	controller := newObservationDurationCallbackController(hold)
	t.Cleanup(controller.Stop)

	var events []Observation
	var child Observation
	var callbackHold time.Duration
	childCallbacks, parentCallbacks := 0, 0
	output, status := runObservationDurationCall(t, row, make(chan struct{}, len(row.Events)), func(event Observation) error {
		events = append(events, event)
		if event.ParentCallID == 0 {
			parentCallbacks++
			return nil
		}
		childCallbacks++
		if event.RegexDetected.Value == 0 || child.CallID != 0 {
			return nil
		}
		child = event
		callbackHold = controller.Hold()
		return callbackAction()
	})
	requireObservationDurationOutput(t, row, output)
	requireObservationEvents(t, events, row.Events)
	requireDurationPolicy(t, events, row.DurationPolicy)
	if child.CallID == 0 || childCallbacks == 0 {
		t.Fatalf("duration fixture did not deliver automatic child callbacks: %#v", events)
	}
	if parentCallbacks != 1 {
		t.Fatalf("duration fixture delivered %d parent callbacks, want one: %#v", parentCallbacks, events)
	}
	if status != wantStatus {
		t.Fatalf("duration callback status %v, want %v", status, wantStatus)
	}
	parent, _ := requireObservationDurationBounds(t, events)
	parentCallbackIndependentBound := baselineParent.Duration + callbackHold
	if parent.Duration >= parentCallbackIndependentBound {
		t.Fatalf("parent duration %v included automatic child callback hold %v against paired baseline %v (baseline children %v, hold budget %v)", parent.Duration, callbackHold, baselineParent.Duration, baselineChildTotal, hold)
	}
}

func loadObservationDurationFixtures(t testing.TB) []observationFixture {
	t.Helper()
	rows := loadObservationFixtures(t, "nested_calls", "json_nested", "metadata_fields")
	return slices.DeleteFunc(rows, func(row observationFixture) bool { return row.Name != "json_nested" && row.Name != "metadata_fields" })
}

func runObservationDurationCall(t testing.TB, row observationFixture, filterEntered chan struct{}, observer Observer) (any, DeliveryStatus) {
	t.Helper()
	engine := observationEngine(t).(*DefaultRedactor)
	filterReached := make(chan struct{}, 1)
	filterRelease := make(chan struct{})
	go func() {
		<-filterReached
		close(filterRelease)
	}()
	engine.userRules[0].FilterFn = func(string, string, int) bool {
		select {
		case filterReached <- struct{}{}:
		default:
		}
		filterEntered <- struct{}{}
		<-filterRelease
		return true
	}

	run, err := NewRun(engine, "run", observer)
	if err != nil {
		t.Fatal(err)
	}
	value, meta := observationValue(t, row)
	switch row.Operation {
	case "RedactJSON":
		return run.RedactJSON("call", value)
	case "RedactMetadata":
		return run.RedactMetadata("call", meta)
	default:
		t.Fatalf("duration fixture %s has unsupported operation %q", row.Name, row.Operation)
		return nil, DeliveryDisabled
	}
}

func requireObservationDurationResult(t testing.TB, row observationFixture, output any, status DeliveryStatus) {
	t.Helper()
	if status != row.Status {
		t.Fatalf("duration fixture %s returned status %v, want %v", row.Name, status, row.Status)
	}
	requireObservationDurationOutput(t, row, output)
}

func requireObservationDurationOutput(t testing.TB, row observationFixture, output any) {
	t.Helper()
	if row.MetadataOutput != "" {
		_, golden := observationValue(t, observationFixture{Metadata: row.MetadataOutput})
		if !reflect.DeepEqual(output, golden) {
			t.Fatalf("duration fixture %s changed metadata output", row.Name)
		}
	} else if observationOutput(t, output) != row.Output {
		t.Fatalf("duration fixture %s returned %q, want %q", row.Name, observationOutput(t, output), row.Output)
	}
}

func requireObservationDurationBounds(t testing.TB, events []Observation) (Observation, time.Duration) {
	t.Helper()
	if len(events) < 2 {
		t.Fatalf("duration fixture requires a parent and automatic child: %#v", events)
	}
	var childTotal time.Duration
	for _, event := range events {
		if event.Duration <= 0 {
			t.Fatalf("duration fixture did not measure positive engine time: %#v", event)
		}
		if event.ParentCallID != 0 {
			childTotal += event.Duration
		}
	}
	parent := events[len(events)-1]
	if parent.ParentCallID != 0 {
		t.Fatalf("duration fixture parent was not delivered last: %#v", events)
	}
	return parent, childTotal
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
