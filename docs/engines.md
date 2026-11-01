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
selected by any public constructor. go-re2 v1.12.0 declares Go 1.25.0, so this
module retains its Go 1.25.5 minimum. Its default runtime uses a pure-Go
translation of RE2's WebAssembly via wasm2go; upstream also offers an optional
`re2_wazero` build tag. It works with `CGO_ENABLED=0`; no native RE2 installation
is required.

This seam adds no chunking or input-size policy. The adapter also inherits
upstream go-re2's invalid-UTF-8 differences from stdlib. The hex-encoded fixture
`invalid_utf8_between_ascii` explicitly pins the gap: for bytes `61 ff 62` and
pattern `.`, stdlib matches all three bytes, while go-re2 matches only the ASCII
bytes and leaves `ff` unchanged. Both engines' `Detect` spans, `Redact` output,
and `ReplaceAllString` output are asserted against separate byte expectations.
No normalization or fallback hides this difference. These boundaries need an
explicit policy and validation before changing the default.

The differential corpus also proves synthetic valid-UTF-8 rule spans,
replacements, filters, public redaction operations, residue, and title parity.
Expected report snapshots independently pin legacy detection counts, including
overlap losers and repeated calls. It does not claim equivalence for arbitrary
byte strings or unbounded inputs.
