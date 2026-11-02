# Internal regexp engines

`NewRedactor` and `NewTitlePipeline` select go-re2. Go's standard `regexp`
remains the pattern-definition type (`Rule.Pattern` is `*regexp.Regexp`) and the
explicit test baseline; it is not a runtime fallback. Existing redactor
interfaces, rule tables, replacements, and the rule-set version are unchanged.
`AllEngines` enumerates `go-regexp` then `go-re2`; `NewEngineName` validates an
identity against that closed registry without selecting it as the default.

The private constructors accept an `engine`. The go-re2 adapter compiles
each rule's `Pattern.String()` at construction, then shares an immutable pattern
lookup across detection, back-reference replacement, title rule application, and
residue scanning. Configured and generated XDG rules use the same lookup.
The explicit stdlib baseline reuses the original patterns without recompiling them.
Each constructor supplies its pattern sets explicitly: the redactor includes
advisory residue rules, while the title pipeline compiles only its own rules.

Panic recovery and residue preview scrubbing deliberately retain the original
stdlib patterns, independently of the normal-path engine. Title markup cleanup
and contextual path normalization also remain unchanged.

The module requires Go 1.26.0 and pins
go-re2 v1.13.0, matching the benchmarked implementation. Its runtime uses a
pure-Go translation of RE2's WebAssembly via wasm2go. It works with
`CGO_ENABLED=0`; no native RE2 installation or wazero runtime is required.

## Input precondition

The public redaction APIs require valid UTF-8 input. The ingest/parse boundary
guarantees this precondition before invoking redaction. Encoding validation and
normalization do not belong in this package; invalid UTF-8 input is out of scope
and does not gate the engine swap.

## Input-size policy and checked calls

`MaxInputBytesPolicy` is copied at construction. The production values are
`ChunkBytes = 64 << 20` (67,108,864 bytes) and
`CeilingBytes = 2047 << 20` (2,146,435,072 bytes). `WithMaxInputBytes` overrides
them for one redactor; `(*DefaultRedactor).MaxInputBytes` returns that copy.
Both must be positive, chunk must not exceed ceiling, and ceiling must be
strictly below the measured 2048 MiB crash point. No caller cap is changed.

At or above the ceiling the wrapper refuses before any engine scan or rewrite.
It returns an actionable error wrapping `ErrInputAboveEngineCeiling`, without
putting input content into the diagnostic. A production 2 GiB input is refused,
not copied into WASM. The policy applies to both build-selected engines.

Larger-than-chunk inputs use a core of at most `ChunkBytes`, up to 64 KiB of
right read-ahead, and at most one complete UTF-8 rune of left context. Window
edges stay on rune boundaries; this is slicing, not encoding validation. Match
offsets and `FilterFn` arguments always refer to the whole original input.
Each rule advances its own committed cursor only between complete matches, so
overlap does not duplicate matches or callbacks or alter FindAll's non-overlap
selection. Existing report semantics (including pre-overlap detection counts)
are unchanged and equal the unchunked result.

A fixed overlap **cannot** guarantee arbitrary regex semantics: email/path
repetitions are unbounded, and configured expressions can span an entire
document. The wrapper therefore lazily compiles a conservative prefix recognizer
through the **same** selected engine. At an artificial window end it finds the
earliest suffix that might still become a match, and commits nothing beyond
that point. Assertions are relaxed only in this safety recognizer; the actual
matching patterns preserve word/line context and disable fabricated text
begin/end anchors at internal edges. A context-only first alternative consumes
the preceding rune before searching, rather than letting a false slice-start
match suppress a real match.

If the cursor cannot advance safely, `ErrInputCannotChunkSafely` is returned.
Patterns that can match an empty string are conservatively refused when
chunking is needed, including zero-width assertion-only patterns. Prefix
recognition also over-approximates bounded repetitions, so it may refuse a
long repetitive suffix even when a more expensive proof could find a split.
Successful scans remain exact; refusal never silently truncates a match, swaps
engines, or widens the engine buffer. Process complete independent source
records when a pattern cannot be safely split. This is not concurrent streaming.

The original `Redactor` and `JSONRedactor` interfaces are unchanged. The smallest
error seam is additive methods on `*DefaultRedactor`: `DetectChecked`,
`RedactTextChecked`, and `RedactJSONChecked`. For example, a caller holding the
constructor's `Redactor` can assert
`interface { RedactTextChecked(string) (string, error) }`. Checked calls return
no result on refusal; callers must not publish their original input on error.
`RedactJSONLBytes` automatically uses `RedactJSONChecked` when implemented and
returns the original bytes **with an error**, as with existing scanner errors.
The additive `RedactJSONDocBytesChecked` supplies the same observable error for
whole-document callers. A third-party JSONRedactor still owns its own policy.

Legacy no-error text/JSON methods mask a refused string as `<REDACTED>`;
`Detect` returns a full-input synthetic refusal match so Detect → Redact also
masks it, regardless of configured replacements. Refusal diagnostics appear in
`Report().Warnings`, with no input content. Observed legacy calls report
`DiagnosticInputRefused` and unavailable counts, not a measured zero. The legacy
document helper returns the JSON string `"<REDACTED>"` on policy refusal; its
historical malformed-JSON pass-through is unchanged. Title methods already
return errors and propagate refusals. Residue scans use the same bounded path;
the standalone advisory-only scanner reports a content-free refusal warning.

`testdata/engine_chunking.yaml` pins named policy, boundary, context, refusal,
and parity cases. Two 200 MiB synthetic inputs compare actual configured-rule
production scans against unchunked scans at 64 MiB and 16 MiB cores; an additional
smaller test compares the complete built-in and advisory catalogs. The exact
2 GiB integer is checked without a 2 GiB allocation, and small ceilings prove
the public paths refuse before entering the engine. These are direct in-process
tests: no child processes, files, databases, or persistent resources; input and
output buffers are owned by each test and reclaimed by Go. No new performance
budget or corpus harness is introduced.

## Differential coverage

The differential corpus proves synthetic valid-UTF-8 rule spans,
replacements, filters, public redaction operations, residue, and title parity.
It reuses redactor behavior cases at their declared levels, detect-secrets rule
cases, schema redaction examples, false-positive cases, metadata path cases,
residue triggers, and title fixtures. Explicit stdlib constructors remain the
comparison baseline even though the public constructors now select go-re2.
The suite runs against go-re2; explicit stdlib constructors remain the
comparison baseline. Byte-identical outputs and per-rule report
counts are required; no fixture expectations change with engine selection.
Expected report snapshots independently pin legacy detection counts, including
overlap losers and repeated calls. Inputs which cannot be proven safe to chunk
are explicitly refused rather than included in the successful-output equivalence
claim.

## Maintained gates and measurements

`make check` runs `go test ./...` without the race detector. `make test-race`
runs the same suite with it. `make release-check` depends on `check` and also
runs `CGO_ENABLED=0 go test ./...`, so CI and release checks exercise the go-re2
engine.

Run the synthetic benchmarks with Go 1.26.0:

```sh
GOTOOLCHAIN=go1.26.0 make bench
# Equivalent command:
GOTOOLCHAIN=go1.26.0 go test -run '^$' -bench 'Benchmark(RedactorConstruction|FirstDetection)$' -benchmem -count=6
```

Both benchmarks compare explicit `go-regexp` and `go-re2` constructors in the
same normal-build process, with Standard level, no user patterns, and empty XDG
paths. `BenchmarkRedactorConstruction` measures a new redactor per iteration,
including go-re2 compilation of the built-in and residue patterns; stdlib reuses
the patterns compiled at package initialization. `BenchmarkFirstDetection`
includes that construction plus one `Detect` call on the fixed synthetic input
in `testdata/engine_benchmark.yaml`: three lines of prose containing an emoji,
an email address, a Unix home path, a git remote, and a credential-bearing URL.
Fixture decoding is outside the measured loop. Both report time, bytes, and
allocations per operation.

These repeated in-process measurements do not measure cold process startup,
package initialization, or binary size. They set no performance threshold and
are not a benchmark budget gate.
