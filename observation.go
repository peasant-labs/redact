package redact

import (
	"sync/atomic"
	"time"

	"github.com/peasant-labs/schema"
)

// Observer receives a detached, content-free completion record synchronously.
// It must be concurrency-safe and terminate. Errors and panics affect delivery only.
type Observer func(Observation) error

// Operation identifies the public operation, not its internal phases.
type Operation uint8

const (
	OperationDetect Operation = iota + 1
	OperationRedact
	OperationRedactText
	OperationRedactJSON
	OperationRedactMetadata
)

// Coverage distinguishes a measured zero from an unavailable fact.
type Coverage uint8

const (
	CoverageUnavailable Coverage = iota
	CoverageComplete
	CoverageNotApplicable
)

// DiagnosticCode is a closed reason. It never contains engine or callback prose.
type DiagnosticCode uint8

const (
	DiagnosticNone DiagnosticCode = iota
	DiagnosticNotMeasured
	DiagnosticEngineRecovered
	DiagnosticEnginePanicked
)

// DeliveryStatus combines callback outcomes for a root and its automatic children.
type DeliveryStatus uint8

const (
	DeliveryDisabled DeliveryStatus = iota
	DeliveryOK
	DeliveryObserverError
	DeliveryObserverPanic
	DeliveryObserverErrorAndPanic
)

// RuleOrigin identifies the source list, independently of a rule's ID.
type RuleOrigin uint8

const (
	RuleOriginBuiltin RuleOrigin = iota + 1
	RuleOriginConfigured
	RuleOriginRuntimeXDG
)

// RuleIdentity distinguishes duplicate IDs with a zero-based index within Origin.
type RuleIdentity struct {
	ID     string
	Origin RuleOrigin
	Index  int
}

// ObservedCount reports direct work only. Unavailable values are always zero.
type ObservedCount struct {
	Value      int
	Coverage   Coverage
	Diagnostic DiagnosticCode
}

// RuleDetection counts accepted regex matches before overlap resolution.
type RuleDetection struct {
	Rule     RuleIdentity
	Category Category
	Count    int
}

// Observation contains no content, offsets, paths, matches, or error payloads.
// RunID, CorrelationID and rule IDs are caller-authorized metadata: do not put
// private content in these fields. Counts exclude work reported by children.
// Duration is the monotonic elapsed engine time for this operation. A parent
// includes automatic child traversal, but pauses while a child callback runs;
// it is not a sum of child durations.
type Observation struct {
	RunID                  string
	CorrelationID          string
	CallID                 uint64
	ParentCallID           uint64
	Operation              Operation
	RegexDetected          ObservedCount
	RegexApplied           ObservedCount
	ContextualReplacements ObservedCount
	Rules                  []RuleDetection
	Diagnostic             DiagnosticCode
	Duration               time.Duration
}

// Run binds one engine and one observer. Use NewRun; do not copy a Run after use.
// Calls may overlap and callbacks may re-enter. No callback holds an engine lock.
type Run struct {
	legacy   Redactor
	engine   *DefaultRedactor
	runID    string
	observer Observer
	counter  atomic.Uint64
}

// NewRun binds observation without changing the engine. Nil observers support any
// valid Redactor; enabled observation requires a non-nil *DefaultRedactor.
func NewRun(r Redactor, runID string, observer Observer) (*Run, error) {
	engine, supported := r.(*DefaultRedactor)
	if r == nil || (supported && engine == nil) {
		return nil, &actionableError{what: "cannot bind a nil redactor", why: "a run requires a usable engine", where: "redact.NewRun", when: "binding before processing", means: "no run was created", fix: "pass a non-nil Redactor from a successful constructor"}
	}
	if observer != nil && !supported {
		return nil, &actionableError{what: "cannot enable observation for this redactor", why: "only DefaultRedactor exposes the canonical observation seam", where: "redact.NewRun", when: "binding before processing", means: "no run was created and no content was processed", fix: "use NewRedactor or pass a nil observer for legacy forwarding"}
	}
	return &Run{legacy: r, engine: engine, runID: runID, observer: observer}, nil
}

// Detect observes accepted matches without changing the input.
func (r *Run) Detect(callID string, input string) (matches []Match, status DeliveryStatus) {
	if r.observer == nil {
		return r.legacy.Detect(input), DeliveryDisabled
	}
	call := r.newCall(callID, OperationDetect, 0)
	defer call.finish(&status)
	call.elapsed.start()
	return r.engine.detect(input, call), DeliveryOK
}

// Redact observes application of caller-supplied spans without trusting their metadata.
func (r *Run) Redact(callID string, input string, matches []Match) (output string, status DeliveryStatus) {
	if r.observer == nil {
		return r.legacy.Redact(input, matches), DeliveryDisabled
	}
	call := r.newCall(callID, OperationRedact, 0)
	defer call.finish(&status)
	call.elapsed.start()
	return r.engine.Redact(input, matches), DeliveryOK
}

// RedactText observes one text operation, including any legacy recovery.
func (r *Run) RedactText(callID string, input string) (output string, status DeliveryStatus) {
	if r.observer == nil {
		return r.legacy.RedactText(input), DeliveryDisabled
	}
	call := r.newCall(callID, OperationRedactText, 0)
	defer call.finish(&status)
	call.elapsed.start()
	return r.engine.redactText(input, call), DeliveryOK
}

// RedactJSON emits text children for string leaves and then a parent completion.
func (r *Run) RedactJSON(callID string, value any) (output any, status DeliveryStatus) {
	if r.observer == nil {
		return r.legacy.RedactJSON(value), DeliveryDisabled
	}
	call := r.newCall(callID, OperationRedactJSON, 0)
	defer call.finish(&status)
	call.elapsed.start()
	return r.engine.redactJSON(value, call), DeliveryOK
}

// RedactMetadata observes the existing metadata traversal without exposing field paths.
func (r *Run) RedactMetadata(callID string, meta *schema.UnifiedMetadata) (output *schema.UnifiedMetadata, status DeliveryStatus) {
	if r.observer == nil {
		return r.legacy.RedactMetadata(meta), DeliveryDisabled
	}
	call := r.newCall(callID, OperationRedactMetadata, 0)
	if meta != nil {
		call.record.ContextualReplacements = unavailableCount(DiagnosticNotMeasured)
	}
	defer call.finish(&status)
	call.elapsed.start()
	return r.engine.redactMetadata(meta, call), DeliveryOK
}

type observationCall struct {
	run      *Run
	parent   *observationCall
	elapsed  observationElapsed
	record   Observation
	delivery DeliveryStatus
}

// observationElapsed is enabled-only clock state. It pauses only while an
// automatic child callback runs so parent traversal remains measurable without
// charging child callback latency to the parent.
type observationElapsed struct {
	started     time.Time
	accumulated time.Duration
}

func (e *observationElapsed) start() {
	e.started = time.Now()
}

func (e *observationElapsed) pause() {
	e.accumulated += time.Since(e.started)
	e.started = time.Time{}
}

func (e *observationElapsed) resume() {
	e.started = time.Now()
}

func (e *observationElapsed) duration() time.Duration {
	if e.started.IsZero() {
		return e.accumulated
	}
	return e.accumulated + time.Since(e.started)
}

func unavailableCount(reason DiagnosticCode) ObservedCount {
	return ObservedCount{Coverage: CoverageUnavailable, Diagnostic: reason}
}

func (r *Run) newCall(correlation string, operation Operation, parent uint64) *observationCall {
	na := ObservedCount{Coverage: CoverageNotApplicable}
	call := &observationCall{run: r, delivery: DeliveryOK, record: Observation{
		RunID: r.runID, CorrelationID: correlation, CallID: r.counter.Add(1), ParentCallID: parent,
		Operation: operation, RegexDetected: na, RegexApplied: na, ContextualReplacements: na,
	}}
	if operation == OperationDetect || operation == OperationRedactText {
		call.record.RegexDetected = ObservedCount{Coverage: CoverageComplete}
	}
	if operation == OperationRedact || operation == OperationRedactText {
		call.record.RegexApplied = unavailableCount(DiagnosticNotMeasured)
	}
	return call
}

func (c *observationCall) failed(reason DiagnosticCode) {
	c.record.Diagnostic = reason
	c.record.Rules = nil
	if c.record.RegexDetected.Coverage != CoverageNotApplicable {
		c.record.RegexDetected = unavailableCount(reason)
	}
	if c.record.RegexApplied.Coverage != CoverageNotApplicable {
		c.record.RegexApplied = unavailableCount(reason)
	}
	if c.record.ContextualReplacements.Coverage != CoverageNotApplicable {
		c.record.ContextualReplacements = unavailableCount(reason)
	}
}

// finish is deferred by the public boundary, outside the text recovery helper.
// The engine panic is preserved; only the callback has a swallowing recovery.
func (c *observationCall) finish(status *DeliveryStatus) {
	panicValue := recover()
	c.record.Duration = c.elapsed.duration()
	if panicValue != nil {
		c.failed(DiagnosticEnginePanicked)
	}
	// Omit inactive/unmatched rules and detach the backing array before delivery.
	var rules []RuleDetection
	for _, rule := range c.record.Rules {
		if rule.Count > 0 {
			rules = append(rules, rule)
		}
	}
	c.record.Rules = rules
	if c.parent != nil {
		c.deliverAutomaticChild()
		*status = c.delivery
		if panicValue != nil {
			panic(panicValue)
		}
		return
	}
	*status = combineDelivery(c.delivery, deliverObservation(c.run.observer, c.record))
	if panicValue != nil {
		panic(panicValue)
	}
}

func (c *observationCall) deliverAutomaticChild() {
	c.parent.elapsed.pause()
	defer c.parent.elapsed.resume()
	c.delivery = deliverObservation(c.run.observer, c.record)
	c.parent.delivery = combineDelivery(c.parent.delivery, c.delivery)
}

func deliverObservation(observer Observer, record Observation) (status DeliveryStatus) {
	status = DeliveryOK
	defer func() {
		if recover() != nil {
			status = DeliveryObserverPanic
		}
	}()
	if observer(record) != nil {
		status = DeliveryObserverError
	}
	return status
}

func combineDelivery(a, b DeliveryStatus) DeliveryStatus {
	hasError := a == DeliveryObserverError || a == DeliveryObserverErrorAndPanic || b == DeliveryObserverError || b == DeliveryObserverErrorAndPanic
	hasPanic := a == DeliveryObserverPanic || a == DeliveryObserverErrorAndPanic || b == DeliveryObserverPanic || b == DeliveryObserverErrorAndPanic
	if hasError && hasPanic {
		return DeliveryObserverErrorAndPanic
	}
	if hasError {
		return DeliveryObserverError
	}
	if hasPanic {
		return DeliveryObserverPanic
	}
	return DeliveryOK
}

func (r *DefaultRedactor) redactTextChild(input string, parent *observationCall) string {
	if parent == nil {
		return r.redactText(input, nil)
	}
	return r.redactTextChildObserved(input, parent)
}

func (r *DefaultRedactor) redactTextChildObserved(input string, parent *observationCall) string {
	child := parent.run.newCall(parent.record.CorrelationID, OperationRedactText, parent.record.CallID)
	child.parent = parent
	var status DeliveryStatus
	defer child.finish(&status)
	child.elapsed.start()
	return r.redactText(input, child)
}
