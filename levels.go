// Package redact defines redaction levels for privacy control.
// Each level applies progressively more aggressive redaction. Category defaults
// activate secrets and paths at Minimal, PII and project identity at Standard,
// and individual rules may require Maximum. Maximum also enables AST
// anonymization and entropy detection.
package redact

// RedactionLevel controls the aggressiveness of transcript redaction.
type RedactionLevel string

const (
	// Minimal redacts detected secrets and identifying paths.
	Minimal RedactionLevel = "minimal"
	// Standard adds PII and project-identity rules that use the category default.
	Standard RedactionLevel = "standard"
	// Maximum adds stricter per-rule redaction, AST anonymization, and entropy detection.
	Maximum RedactionLevel = "maximum"
)

func (l RedactionLevel) String() string { return string(l) }

// IsValid returns true if the level is one of the known variants.
func (l RedactionLevel) IsValid() bool {
	switch l {
	case Minimal, Standard, Maximum:
		return true
	}
	return false
}

// Ord returns the ordinal for this level: Minimal=0, Standard=1, Maximum=2.
// Unknown levels return -1.
func (l RedactionLevel) Ord() int {
	switch l {
	case Minimal:
		return 0
	case Standard:
		return 1
	case Maximum:
		return 2
	default:
		return -1
	}
}

// Max returns whichever of a or b has the higher Ord (i.e. stricter redaction).
// If both are equal, a is returned.
func Max(a, b RedactionLevel) RedactionLevel {
	if a.Ord() >= b.Ord() {
		return a
	}
	return b
}
