package redact

import (
	"strings"
	"testing"
)

// TestMaximumAvailability_NoCGO is the build-mode gate for the Maximum redaction
// level. It is UNTAGGED on purpose: it compiles and runs in BOTH the cgo and
// !cgo test legs, branching on the build-tag-set redact.MaximumAvailable constant
// rather than silently skipping. This is the negative gate the CGO=0 CI leg
// relies on (go test ./pkg/redact/), and it doubles as a positive assertion
// under cgo.
//
//   - !cgo (MaximumAvailable == false): NewRedactor(Maximum) MUST fail at
//     construction with an actionable error (what/why/where/how-to-fix per
//     C-actionable-errors). Falling back to weaker redaction is forbidden.
//   - cgo  (MaximumAvailable == true):  NewRedactor(Maximum) MUST succeed.
//
// The two non-Maximum levels are available in every build mode and are asserted
// unconditionally so a regression that broke Standard/Minimal construction under
// !cgo would be caught here too.
func TestMaximumAvailability_NoCGO(t *testing.T) {
	// Standard and Minimal are always constructible, regardless of cgo.
	for _, lvl := range []RedactionLevel{Minimal, Standard} {
		if _, err := NewRedactor(lvl, nil, XDGPaths{}); err != nil {
			t.Fatalf("NewRedactor(%s) must succeed in any build mode, got: %v", lvl, err)
		}
	}

	r, err := NewRedactor(Maximum, nil, XDGPaths{})

	if MaximumAvailable {
		// cgo build: Maximum is linked and must construct cleanly.
		if err != nil {
			t.Fatalf("MaximumAvailable=true but NewRedactor(Maximum) failed: %v", err)
		}
		if r == nil {
			t.Fatal("MaximumAvailable=true: NewRedactor(Maximum) returned nil redactor without error")
		}
		return
	}

	// !cgo build: Maximum must be a hard, actionable error — never a silent
	// downgrade. Fail-closed: no redactor is returned.
	if err == nil {
		t.Fatalf("MaximumAvailable=false but NewRedactor(Maximum) returned no error " +
			"(would mean silent weaker redaction — forbidden)")
	}
	if r != nil {
		t.Fatalf("MaximumAvailable=false: NewRedactor(Maximum) must return a nil redactor (fail-closed), got %v", r)
	}

	// The error must be actionable: name WHAT (maximum), WHY (cgo), and HOW TO
	// FIX (standard / a cgo-enabled build). We match on the typed level strings
	// to stay robust to wording tweaks.
	low := strings.ToLower(err.Error())
	for _, want := range []string{
		Maximum.String(),  // what is unavailable
		"cgo",             // why
		Standard.String(), // how to fix (use standard)
	} {
		if !strings.Contains(low, want) {
			t.Errorf("actionable error must mention %q; got: %v", want, err.Error())
		}
	}
}
