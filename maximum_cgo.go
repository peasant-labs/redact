//go:build cgo

package redact

// MaximumAvailable reports whether the Maximum redaction level (code-aware,
// tree-sitter AST anonymization) is compiled into this binary.
//
// It is a build-tag-set constant, NOT a runtime probe: tree-sitter is a CGo
// dependency, so Maximum is reachable only in cgo builds. CLI help text, error
// paths, and tests branch on this typed constant rather than a stringly check.
//
// In cgo builds it is true and newMaximumAnonymizer() returns the real
// tree-sitter-backed pipeline. The !cgo counterpart lives in maximum_nocgo.go.
const MaximumAvailable = true

// newMaximumAnonymizer constructs the AST anonymizer used at the Maximum level:
// TreeSitterAnonymizer (primary, accurate AST identifier replacement) with
// RegexAnonymizer as the fallback when a language/parse is unsupported.
//
// NewTreeSitterAnonymizer + NewFallbackAnonymizer live in the cgo-only
// tree_sitter.go, so this factory must itself be cgo-gated.
func newMaximumAnonymizer() ASTAnonymizer {
	return NewFallbackAnonymizer(NewTreeSitterAnonymizer(), NewRegexAnonymizer())
}
