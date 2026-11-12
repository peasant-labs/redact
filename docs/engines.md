# Internal regexp engines

`NewRedactor` and `NewTitlePipeline` select go-re2 by default. Building with
`-tags no_re2` selects Go's standard `regexp` fallback and excludes go-re2 and its
dependency from the build. Selection is build-tagged, not mutable runtime state;
there is no silent runtime fallback. Existing redactor interfaces,
`Rule.Pattern` (`*regexp.Regexp`), rule tables, replacements, and the rule-set
version are unchanged.
`AllEngines` enumerates `go-regexp` then `go-re2`; `NewEngineName` validates an
identity against that closed registry without selecting it as the default.

The private constructors accept an `engine`. The go-re2 adapter compiles
each rule's `Pattern.String()` at construction, then shares an immutable pattern
lookup across detection, back-reference replacement, title rule application, and
residue scanning. Configured and generated XDG rules use the same lookup.
The stdlib path reuses the original patterns without recompiling them.
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

This seam adds no chunking or input-size policy.

The differential corpus proves synthetic valid-UTF-8 rule spans,
replacements, filters, public redaction operations, residue, and title parity.
It reuses redactor behavior cases at their declared levels, detect-secrets rule
cases, schema redaction examples, false-positive cases, metadata path cases,
residue triggers, and title fixtures. Explicit stdlib constructors remain the
comparison baseline even though the public constructors now select go-re2.
The full suite also runs against both build defaults, including JSONL/document
and metadata output expectations. Byte-identical outputs and per-rule report
counts are required; no fixture expectations change with engine selection.
Expected report snapshots independently pin legacy detection counts, including
overlap losers and repeated calls. It does not claim equivalence for unbounded
inputs.

## Maintained gates and measurements

`make check` runs both `go test -race ./...` and
`go test -tags no_re2 -race ./...`. The fallback can also be checked alone with
`make test-nore2`. `make release-check` depends on `check`, so CI and release
checks exercise both engines.

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
