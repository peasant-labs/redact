# Internal regexp engines

`NewRedactor` and `NewTitlePipeline` still select Go's standard `regexp`
implementation. Public interfaces, `Rule.Pattern` (`*regexp.Regexp`), rule tables,
replacements, and the rule-set version are unchanged.

The private constructors accept an `engine`. The alternative adapter compiles
each rule's `Pattern.String()` at construction, then shares an immutable pattern
lookup across detection, back-reference replacement, title rule application, and
residue scanning. Configured and generated XDG rules use the same lookup.
The stdlib path reuses the original patterns without recompiling them.

Panic recovery and residue preview scrubbing deliberately retain the original
stdlib patterns, independently of the normal-path engine. Title markup cleanup
and contextual path normalization also remain unchanged.

The go-re2 adapter is included unless built with `-tags no_re2`, but it is not
selected by any public constructor. go-re2 v1.13.0 uses a pure-Go translation of
RE2's WebAssembly via wasm2go, not wazero, and requires Go 1.26.0. It works with
`CGO_ENABLED=0`; no native RE2 installation is required.

This seam adds no chunking or input-size policy. The adapter also inherits
upstream go-re2's documented invalid-UTF-8 differences from stdlib. Those
boundaries need explicit handling and validation before changing the default.
The current differential corpus proves synthetic valid-UTF-8 rule spans,
replacements, filters, public redaction operations, residue, and title parity;
it does not claim equivalence for arbitrary byte strings or unbounded inputs.
