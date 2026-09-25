package redact

import (
	"context"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

type observationResult struct {
	output string
	status DeliveryStatus
}

func awaitObservation[T any](t *testing.T, ctx context.Context, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-ctx.Done():
		t.Fatal("observation barrier timed out; inspect callback lock/reentry boundaries")
	}
	var zero T
	return zero
}

func TestObservationConcurrentRuns(t *testing.T) {
	rows := loadObservationFixtures(t, "independent_overlapping_runs", "independent_runs", "same_run_roots")
	rows = append(rows, loadObservationFixtures(t, "concurrent_barriers", "callbacks_release_report_lock")...)
	for _, row := range rows {
		t.Run(row.Name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			release := make(chan struct{})
			entered := make(chan Observation, 2)
			var doneChannels []<-chan struct{}
			t.Cleanup(func() {
				cancel()
				deadline := time.NewTimer(5 * time.Second)
				defer deadline.Stop()
				for _, done := range doneChannels {
					select {
					case <-done:
					case <-deadline.C:
						t.Error("callback cleanup did not terminate after cancellation")
						return
					}
				}
			})
			engine := observationEngine(t)
			observer := func(event Observation) error {
				select {
				case entered <- event:
				case <-ctx.Done():
					return nil
				}
				select {
				case <-release:
				case <-ctx.Done():
				}
				return nil
			}
			first, err := NewRun(engine, "first", observer)
			if err != nil {
				t.Fatal(err)
			}
			second := first
			if !row.SameRun {
				second, err = NewRun(engine, "second", observer)
				if err != nil {
					t.Fatal(err)
				}
			}
			start := func(run *Run, correlation, input string) <-chan observationResult {
				result := make(chan observationResult, 1)
				done := make(chan struct{})
				doneChannels = append(doneChannels, done)
				go func() {
					defer close(done)
					output, status := run.RedactText(correlation, input)
					result <- observationResult{output, status}
				}()
				return result
			}
			one := start(first, "first-call", row.Input)
			eventOne := awaitObservation(t, ctx, entered)
			two := start(second, "second-call", row.Other)
			eventTwo := awaitObservation(t, ctx, entered)
			// Both callbacks are blocked. A third goroutine must read the report and
			// complete unobserved redaction before either callback is released.
			probe := make(chan observationResult, 1)
			probeDone := make(chan struct{})
			doneChannels = append(doneChannels, probeDone)
			go func() {
				defer close(probeDone)
				engine.Report()
				probe <- observationResult{output: engine.RedactText(row.Input)}
			}()
			if result := awaitObservation(t, ctx, probe); result.output != row.Output {
				t.Fatal("unobserved probe changed output")
			}
			close(release)
			resultOne, resultTwo := awaitObservation(t, ctx, one), awaitObservation(t, ctx, two)
			if resultOne.output != row.Output || resultTwo.output != row.OtherOutput || resultOne.status != DeliveryOK || resultTwo.status != DeliveryOK {
				t.Fatal("concurrent output/delivery differs from fixture")
			}
			requireObservationEvents(t, []Observation{eventOne, eventTwo}, row.Events)
			engine.Detect(row.Input) // Deliberate deterministic last-call winner.
			report := engine.Report()
			if report.TotalRedactions != row.Total || report.Counts["fixture"] != row.Total || !reflect.DeepEqual(report.Categories, []string{"pii"}) || len(report.Warnings) != 0 || len(report.Matches) != 1 {
				t.Fatalf("concurrent report differs: %#v", report)
			}
			if row.SameRun && first.counter.Load() != 2 {
				t.Fatal("same-run roots must have distinct IDs; unobserved work must not acquire one")
			}
		})
	}
}

func TestObservationPriorHistory(t *testing.T) {
	for _, row := range loadObservationFixtures(t, "prior_history", "exclude_prior_detected_history") {
		t.Run(row.Name, func(t *testing.T) {
			engine := observationEngine(t)
			engine.RedactText(row.Prior)
			var events []Observation
			run, err := NewRun(engine, "run", func(event Observation) error { events = append(events, event); return nil })
			if err != nil {
				t.Fatal(err)
			}
			output, status := run.RedactText("call", row.Input)
			if output != row.Output || status != DeliveryOK {
				t.Fatal("history changed current result")
			}
			requireObservationEvents(t, events, row.Events)
			report := engine.Report()
			if report.TotalRedactions != row.Total || report.Counts["fixture"] != row.Total || len(report.Matches) != 1 {
				t.Fatalf("cumulative/last-call report changed: %#v", report)
			}
		})
	}
}

func TestObservationConcurrentReentry(t *testing.T) {
	for _, row := range loadObservationFixtures(t, "unobserved_calls", "report_reentry", "observed_reentry", "unobserved_reentry") {
		t.Run(row.Name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			done := make(chan struct{})
			t.Cleanup(func() {
				cancel()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("reentry cleanup timed out")
				}
			})
			engine := observationEngine(t)
			engine.RedactText(row.Input) // Unobserved history must never acquire an ID.
			var once atomic.Bool
			var events []Observation // One worker goroutine only; controller reads after done.
			var reentry observationResult
			var run *Run
			var err error
			run, err = NewRun(engine, "run", func(event Observation) error {
				events = append(events, event)
				if !once.CompareAndSwap(false, true) {
					return hostileObservationError{}
				}
				switch row.Failure {
				case "report":
					engine.Report()
				case "observed":
					reentry.output, reentry.status = run.RedactText("reentry", row.Input)
				case "unobserved":
					reentry.output = engine.RedactText(row.Input)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			result := make(chan observationResult, 1)
			go func() {
				defer close(done)
				output, status := run.RedactText("call", row.Input)
				result <- observationResult{output, status}
			}()
			got := awaitObservation(t, ctx, result)
			awaitObservation(t, ctx, done)
			if got.output != row.Output || got.status != DeliveryOK {
				t.Fatal("independent reentry delivery contaminated root")
			}
			requireObservationEvents(t, events, row.Events)
			if row.Failure == "observed" && (reentry.status != DeliveryObserverError || reentry.output != row.Output) {
				t.Fatal("reentrant root lost its own delivery result")
			}
			if engine.Report().TotalRedactions != row.Total {
				t.Fatal("reentry report contribution incorrect")
			}
		})
	}
}
