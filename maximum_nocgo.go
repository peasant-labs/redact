//go:build !cgo

package redact

// MaximumAvailable reports whether the Maximum redaction level (code-aware,
// tree-sitter AST anonymization) is compiled into this binary.
//
// In !cgo builds it is false: tree-sitter is a CGo dependency and is not linked,
// so Maximum is NOT available. NewRedactor(Maximum) returns an actionable error
// at construction time rather than silently degrading to weaker redaction. The
// cgo counterpart (true + the real factory) lives in maximum_cgo.go.
const MaximumAvailable = false

// newMaximumAnonymizer exists ONLY so redactor.go compiles in !cgo builds; it is
// UNREACHABLE at runtime because NewRedactor returns an actionable error (when
// MaximumAvailable == false) before ever calling it for a Maximum request.
//
// It deliberately FAILS LOUD rather than returning a RegexAnonymizer. Returning
// a weaker anonymizer here would mean that if the MaximumAvailable guard in
// NewRedactor were ever removed or regressed, a !cgo build would SILENTLY apply
// regex-as-Maximum — exactly the silent-weaker-redaction failure PROPOSAL-3
// Amendment A forbids. A panic surfaces such a regression immediately and
// unmistakably instead of leaking code identifiers in published transcripts.
func newMaximumAnonymizer() ASTAnonymizer {
	panic("redact: BUG — newMaximumAnonymizer() called in a !cgo build; the Maximum level " +
		"is unavailable without cgo (MaximumAvailable == false) and NewRedactor must reject it " +
		"with an actionable error BEFORE constructing an anonymizer. Reaching this means the " +
		"NewRedactor Maximum-availability guard was removed or regressed — restore it rather than " +
		"silently falling back to weaker (regex) redaction.")
}
