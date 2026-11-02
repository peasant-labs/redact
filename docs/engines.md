# Internal regexp engines

`NewRedactor` and `NewTitlePipeline` still select Go's standard `regexp`
implementation. Existing redactor interfaces, `Rule.Pattern` (`*regexp.Regexp`),
rule tables, replacements, and the rule-set version are unchanged.
`AllEngines` enumerates `go-regexp` then `go-re2`; `NewEngineName` validates an
identity against that closed registry without selecting it as the default.

The private constructors accept an `engine`. The alternative adapter compiles
each rule's `Pattern.String()` at construction, then shares an immutable pattern
lookup across detection, back-reference replacement, title rule application, and
residue scanning. Configured and generated XDG rules use the same lookup.
The stdlib path reuses the original patterns without recompiling them.
Each constructor supplies its pattern sets explicitly: the redactor includes
advisory residue rules, while the title pipeline compiles only its own rules.

Panic recovery and residue preview scrubbing deliberately retain the original
stdlib patterns, independently of the normal-path engine. Title markup cleanup
and contextual path normalization also remain unchanged.

The go-re2 adapter is included unless built with `-tags no_re2`, but it is not
selected by any public constructor. The module requires Go 1.26.0 and pins
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
Expected report snapshots independently pin legacy detection counts, including
overlap losers and repeated calls. It does not claim equivalence for unbounded
inputs.
