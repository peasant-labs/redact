# Internal regexp engines

`NewRedactor` and `NewTitlePipeline` select go-re2 by default. Building with
`-tags no_re2` selects Go's standard `regexp` fallback and excludes go-re2 and its
dependency from the build. Selection is build-tagged, not mutable runtime state;
there is no silent runtime fallback. Existing redactor interfaces,
`Rule.Pattern` (`*regexp.Regexp`), rule tables, replacements, and the rule-set
version are unchanged.
`AllEngines` enumerates `go-regexp` then `go-re2`; `NewEngineName` validates an
identity against that closed registry without selecting it as the default.
`EngineIdentity` reports the engine this build selected, for a projection row
to record with the redaction output.

The private constructors accept an `engine`. The go-re2 adapter compiles
each rule's `Pattern.String()` at construction, then shares an immutable pattern
lookup across detection, back-reference replacement, title rule application, and
residue scanning. Configured and generated XDG rules use the same lookup.
The stdlib path reuses the original patterns without recompiling them.
Each constructor supplies its pattern sets explicitly: the redactor includes
advisory residue rules, the title pipeline compiles only its own rules, and
`NewResidueDetector` compiles the residue rules through the selected engine.

Panic recovery and residue preview scrubbing deliberately retain the original
stdlib patterns, independently of the normal-path engine. Title markup cleanup
and contextual path normalization also remain unchanged.

## What the injected engine does not run

The engine finds the spans of each rule's pattern. Everything that then reads
a span runs on the standard library, whichever engine was injected:

- A rule's `FilterFn`. A filter that uses a regular expression of its own
  (`awsSecretKeyFilter`, `emailFilter`, `jwkPrivateMemberFilter`) uses Go's
  `regexp`.
- A value finder (`valueRules` in `detect.go`). `key_name_secret`,
  `url_query_secret`, `cookie_header`, `curl_user_password` and the
  prefix-token rules read their own pattern match a second time with Go's
  `regexp` to find the groups, and apply the value test in
  `key_name_rules.go`, which is made of small anchored patterns.
- The decisions `RedactJSON` makes from an object key alone: the value test
  for a key that names a secret, and the member name and value shape of a JSON
  Web Key.

These run once per pattern match or per string under a matching key, on the
match and not on the whole input, so their cost follows the number of matches.

`RedactJSON` does go through the injected engine for the one scan that asks
whether a format rule matches the whole of a value under a secret key, and for
every string it passes to the text pipeline. `TestEngineJSONKeyRouting` pins
those scan counts.

The module requires Go 1.26.0 and pins
go-re2 v1.13.0, matching the benchmarked implementation. Its runtime uses a
pure-Go translation of RE2's WebAssembly via wasm2go. It works with
`CGO_ENABLED=0`; no native RE2 installation or wazero runtime is required.

## Input precondition

The public redaction APIs require valid UTF-8 input. The ingest/parse boundary
guarantees this precondition before invoking redaction. Encoding validation and
normalization do not belong in this package; invalid UTF-8 input is out of scope
and does not gate the engine swap.

The precondition is stated in the package documentation and on every public
entry point. The exact engine divergence is pinned in
`testdata/engine_invalid_utf8.yaml`: stdlib treats an invalid byte as U+FFFD,
while go-re2 skips it, so a violated contract can redact less. That fixture is a
reviewed divergence record, not a parity requirement.
`peasant-labs/peasant#826` owns ingest-level validation.

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
