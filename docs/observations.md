# Run-scoped observations

`NewRun` binds a redactor, an opaque run ID, and an optional callback. This is an
additive API: the existing `Redactor`, `Rule`, `Match`, and title APIs do not change.
Use the pointer returned by a successful constructor; do not copy a used `Run`.
A nil or zero `Run` is not a usable engine.

```go
engine, err := redact.NewRedactor(redact.Standard, nil, redact.XDGPaths{})
if err != nil {
    return err
}
run, err := redact.NewRun(engine, "batch-17", func(o redact.Observation) error {
    // This callback must be concurrency-safe. Retaining o is safe.
    // Do not add input/output content to the facts you store.
    return saveFacts(o)
})
if err != nil {
    return err
}
output, delivery := run.RedactText("item-42", input)
// Use output regardless of observer delivery. A delivery failure is NOT a
// redaction failure and must not select another redaction or fallback path.
switch delivery {
case redact.DeliveryDisabled, redact.DeliveryOK:
case redact.DeliveryObserverError, redact.DeliveryObserverPanic,
    redact.DeliveryObserverErrorAndPanic:
    recordDeliveryFailure(delivery) // Store the closed status, not private prose.
}
```

The example's `saveFacts` and `recordDeliveryFailure` are caller-owned functions.
An executable public-API example is tested with this package.

## Identity and privacy

The method's first string argument becomes `CorrelationID`. `RunID` and
`CorrelationID` may be empty. A positive, atomic `CallID` is unique within one
run. Root calls have `ParentCallID == 0`. IDs identify calls, not completion
order, duration, or a relationship between independent roots.

**Caller IDs and rule IDs are intentionally visible metadata.** Do not put
private content into them. Configured rule IDs are not removed or sanitized.
`RuleIdentity` also includes `Origin` (built-in, configured, runtime XDG) and a
zero-based `Index` within that source list. Duplicate IDs remain distinct,
including duplicates in one configured list. Indexes are stable within one
engine configuration, not across versions/configurations.

Records contain no input/output, `Match`, matched text, offsets, regex source,
replacement text, raw path, map key, residue preview, arbitrary error, or panic
payload. Diagnostics use closed enums. The legacy `Report()` still contains
private matches and warning previews: do not use it as a safe observation log.
Changing the exported rule table concurrently with use remains unsupported.

## Coverage

Records describe **direct work only**, never work already reported by children.
Each enabled record also contains `Duration`, a monotonic elapsed `time.Duration` for
that operation. Timing starts after enabled observation setup and immediately before
the engine operation. A parent's duration covers the parent operation including its
automatic JSON or metadata child traversal; it is not the sum of child durations.
Each child records its own duration. The parent timer pauses while an automatic child
callback runs and resumes after the callback returns, returns an error, or panics, so
callback latency is not included in the parent duration. The child's own duration is
fixed before its callback runs, and the root callback runs after the root duration is
fixed. The value is elapsed time, not a wall-clock timestamp, and adds no content or
identity beyond the fields already documented here.

| Operation | RegexDetected | RegexApplied | ContextualReplacements |
|---|---|---|---|
| Detect | Complete, accepted post-filter matches | NotApplicable | NotApplicable |
| Redact | NotApplicable | Unavailable / NotMeasured | NotApplicable |
| RedactText | Complete, accepted post-filter matches | Unavailable / NotMeasured | NotApplicable |
| RedactJSON parent | NotApplicable | NotApplicable | NotApplicable |
| RedactMetadata parent, non-nil | NotApplicable | NotApplicable | Unavailable / NotMeasured |
| RedactMetadata parent, nil | NotApplicable | NotApplicable | NotApplicable |

Complete zero is a measured zero. NotApplicable has zero value and no diagnostic.
Unavailable has zero value and a closed nonzero reason. Application remains
unmeasured even for empty/no-op calls. Metadata contextual counts remain
unmeasured even when no contextual rewrite occurred.

Detection counts include accepted regex matches **before overlap removal**.
`Rules` contains only rules with accepted matches, in source order, with their
actual categories. These counts exclude AST and entropy changes and residue
warnings. They are not exact applied replacement counts. The legacy cumulative
report retains its detected-count and first-ID category behavior; replacement
selection retains its last-ID behavior. The observation API does not change them.

JSON emits one text child per string leaf immediately when that child finishes, then
emits the parent. Container recursion has no separate record and map order is
unspecified. Metadata emits a text child immediately for each existing text
invocation, including empty fields, then emits the parent. Children inherit
correlation/run IDs, get distinct call IDs, and point to the root parent. Text's
internal detection/application phases are not separate calls. `Duration` measures
the enabled public operation and the automatic traversal, excluding automatic child
callback latency; it does not turn the parent into a total of child timings. Exact
application, contextual replacement counts, and stage timing remain outside this
field.

## Recovery and delivery

Each enabled public operation sends one completion record synchronously. A
successful text fallback sets `DiagnosticEngineRecovered`, clears rule facts,
and marks both regex counts unavailable for that reason. Existing fallback
output and report writes remain unchanged. A child recovery does not claim a
parent recovery. If the engine propagates a panic, its completion record uses
`DiagnosticEnginePanicked`, clears rule facts, and marks applicable counts
unavailable, then the **original panic value is re-panicked**. There is no normal
delivery return in that case.

The callback runs outside all report locks and outside text recovery. Returning
an error or panicking changes only the closed delivery status. Error text and
panic values are not formatted. There is no retry, recursive failure callback,
automatic observer disable, new fallback, or report adjustment. A child fixes its
own duration before delivery, and the parent timer is paused for that delivery.
The root fixes its own duration before root delivery, so callback work is not
reported as redaction time.

Root delivery combines errors/panics from automatic children and its own
callback. A child error plus parent panic produces `DeliveryObserverErrorAndPanic`.
A callback that re-enters starts an **independent root** with its own delivery
result; it is not an automatic child.

Callbacks must be safe for concurrent use and must terminate. They may read
`Report()` or re-enter observed/unobserved operations. Bound your own recursion;
do not hold a recursive `sync.Once` or an application lock across re-entry.
Blocking callbacks block their callers, not unrelated engine work. There is no
timeout, background queue, or persistent journal. Each received value and rule
slice is detached: retaining or changing it cannot change later records or the
engine. The caller owns synchronization for its retained copies.

## Disabled and external engines

A nil observer immediately forwards each operation to its original method and
returns `DeliveryDisabled`, without creating observation records, obtaining call
IDs, reading observation clocks, or invoking callbacks. Construction may allocate.
Valid third-party implementations remain usable with a nil observer and need no
new methods. Enabled observation requires a non-nil `*DefaultRedactor` from
`NewRedactor`; other implementations receive a fixed actionable constructor error
before any operation. Nil interfaces and typed-nil `*DefaultRedactor` values are
rejected. A disabled binding still requires a valid third-party engine.

## Verification and adoption

Run `make release-check` for functional/race, no-CGO, vet, pin, and tidy checks.
Run `go test -run '^TestObservationDisabledAllocations$' -count=3 -v .` separately
with the same toolchain/environment as the baseline. Only this allocation-only
test is excluded from race builds; all functional/source guards remain in them.
The race runtime randomly discards regexp pool entries, so exact allocation
comparisons use a non-race build, with `CGO_ENABLED=1`, `GOMAXPROCS=1`, and matched
effective `GOFLAGS`. Require all three per-operation samples to be identical,
disabled/direct deltas to be exactly zero, and current legacy counts not to
exceed the same-harness baseline. Do not average, select minima, add tolerances,
or retry until green. Heap counts complement, not replace, source inspection for
stack records, callbacks, and clocks.

No consumer dependency is changed here. A published module tag must precede a
future consumer re-pin. This module-only API has no mounted UI or screenshot gate.
