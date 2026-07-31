package redact

import (
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// mustNewRedactor is a test helper that constructs a Redactor or fails the test.
// Use this for the common case where user patterns are known-valid (or nil).
//
// When the requested level is Maximum but the binary was built without cgo
// (MaximumAvailable == false), the Maximum-level mechanics under test (entropy,
// residue, AST anonymization) are not compiled in, so the test is SKIPPED with
// an explicit, logged reason — never a silent pass. The hard-error contract for
// Maximum-without-cgo is positively asserted by the untagged negative gate in
// maximum_available_test.go, and the full differential is gated under cgo by
// internal/e2e.TestFixture_MaximumDifferential.
func mustNewRedactor(tb testing.TB, level RedactionLevel, patterns []UserPattern) Redactor {
	tb.Helper()
	if level == Maximum && !MaximumAvailable {
		tb.Skipf("redact: Maximum level unavailable without cgo (MaximumAvailable=false); "+
			"this Maximum-mechanics test is exercised under CGO=1. The hard-error contract is "+
			"asserted by TestMaximumAvailability_NoCGO. (requested level=%s)", level)
	}
	r, err := NewRedactor(level, patterns, XDGPaths{})
	if err != nil {
		tb.Fatalf("NewRedactor: %v", err)
	}
	return r
}
