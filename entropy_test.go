package redact

import (
	"math"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Shannon entropy unit tests
// ---------------------------------------------------------------------------

func TestEntropy_HighEntropyString(t *testing.T) {
	// 32-char high-entropy string: mixed alphanumeric with symbols, high variety.
	// Must be > 20 chars and > 4.0 bits entropy to trigger.
	input := "aB3xQ9mZ7kL2pR8nT4vY6wU1sE5jC0dF"
	r := mustNewRedactor(t, Maximum, nil)
	got := r.RedactText(input)
	if !strings.Contains(got, "<HIGH_ENTROPY>") {
		t.Errorf("HighEntropyString: got %q, want output containing <HIGH_ENTROPY> (entropy=%.2f)",
			got, shannonEntropy(input))
	}
}

func TestEntropy_ShortString(t *testing.T) {
	// 10-char string — below the 20-char threshold even if entropy is high.
	input := "aB3xQ9mZ7k"
	r := mustNewRedactor(t, Maximum, nil)
	got := r.RedactText(input)
	if strings.Contains(got, "<HIGH_ENTROPY>") {
		t.Errorf("ShortString: got %q, but expected no entropy redaction (len=%d < threshold)", got, len(input))
	}
}

func TestEntropy_NormalText(t *testing.T) {
	input := "hello world this is normal text"
	r := mustNewRedactor(t, Maximum, nil)
	got := r.RedactText(input)
	if strings.Contains(got, "<HIGH_ENTROPY>") {
		t.Errorf("NormalText: got %q, but expected no entropy redaction for normal prose", got)
	}
}

func TestEntropy_OnlyAtMaximum(t *testing.T) {
	// A high-entropy string at Standard level should NOT be flagged.
	input := "aB3xQ9mZ7kL2pR8nT4vY6wU1sE5jC0dF"
	r := mustNewRedactor(t, Standard, nil)
	got := r.RedactText(input)
	if strings.Contains(got, "<HIGH_ENTROPY>") {
		t.Errorf("OnlyAtMaximum (Standard): got %q, but entropy detection must be inactive at Standard level", got)
	}
}

// ---------------------------------------------------------------------------
// shannonEntropy unit tests (internal function — package-level test)
// ---------------------------------------------------------------------------

func TestShannonEntropy_EmptyString(t *testing.T) {
	if got := shannonEntropy(""); got != 0 {
		t.Errorf("shannonEntropy(\"\") = %f, want 0", got)
	}
}

func TestShannonEntropy_SingleChar(t *testing.T) {
	if got := shannonEntropy("aaaa"); got != 0 {
		t.Errorf("shannonEntropy(\"aaaa\") = %f, want 0 (all same char)", got)
	}
}

func TestShannonEntropy_TwoChars(t *testing.T) {
	// "ab" repeated: equal probability for each → entropy = 1.0
	got := shannonEntropy("abababab")
	if got < 0.99 || got > 1.01 {
		t.Errorf("shannonEntropy(\"abababab\") = %f, want ~1.0", got)
	}
}

// ---------------------------------------------------------------------------
// UUID pre-filter tests (SLICE-3)
// ---------------------------------------------------------------------------

// TestIsPotentialUUID_V1 verifies that a UUID v1-shaped token is identified as
// a potential UUID and therefore not flagged as high entropy.
func TestIsPotentialUUID_V1(t *testing.T) {
	uuidV1 := "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
	if !isPotentialUUID(uuidV1) {
		t.Errorf("isPotentialUUID(%q) = false, want true (UUID v1 format)", uuidV1)
	}
	// Via detectEntropy: UUID v1 is > 20 chars but should not be flagged.
	got := detectEntropy(uuidV1)
	if got != uuidV1 {
		t.Errorf("detectEntropy(%q) = %q, want unchanged (UUID v1 pre-filter)", uuidV1, got)
	}
}

// TestIsPotentialUUID_V4 verifies that a UUID v4-shaped token is identified as
// a potential UUID and therefore not flagged as high entropy.
func TestIsPotentialUUID_V4(t *testing.T) {
	uuidV4 := "550e8400-e29b-41d4-a716-446655440000"
	if !isPotentialUUID(uuidV4) {
		t.Errorf("isPotentialUUID(%q) = false, want true (UUID v4 format)", uuidV4)
	}
	got := detectEntropy(uuidV4)
	if got != uuidV4 {
		t.Errorf("detectEntropy(%q) = %q, want unchanged (UUID v4 pre-filter)", uuidV4, got)
	}
}

// TestIsPotentialUUID_Embedded verifies that a UUID embedded within a longer token
// is still identified and the whole token is not flagged as high entropy.
func TestIsPotentialUUID_Embedded(t *testing.T) {
	embedded := "prefix-550e8400-e29b-41d4-a716-446655440000-suffix"
	if !isPotentialUUID(embedded) {
		t.Errorf("isPotentialUUID(%q) = false, want true (embedded UUID)", embedded)
	}
	got := detectEntropy(embedded)
	if got != embedded {
		t.Errorf("detectEntropy(%q) = %q, want unchanged (embedded UUID pre-filter)", embedded, got)
	}
}

// ---------------------------------------------------------------------------
// Sequential string pre-filter tests (SLICE-3)
// ---------------------------------------------------------------------------

// TestIsSequentialString_Alpha verifies that an alphabetic run (ABCDEF) is recognized
// as sequential via case-insensitive (lowercase) normalization and sorting.
func TestIsSequentialString_Alpha(t *testing.T) {
	if !isSequentialString("ABCDEF") {
		t.Errorf("isSequentialString(\"ABCDEF\") = false, want true (sequential alpha, case-insensitive)")
	}
}

// TestIsSequentialString_Digits verifies that a digit run is recognized as sequential.
func TestIsSequentialString_Digits(t *testing.T) {
	if !isSequentialString("0123456") {
		t.Errorf("isSequentialString(\"0123456\") = false, want true (sequential digits)")
	}
}

// TestIsSequentialString_Hex verifies that a rotation of the full hex charset is
// recognized as sequential because sorting normalizes the order.
func TestIsSequentialString_Hex(t *testing.T) {
	// All 16 distinct lowercase hex characters in arbitrary order.
	// Sorted lowercase = "0123456789abcdef" which matches the sorted hex charset.
	if !isSequentialString("cdef0123456789ab") {
		t.Errorf("isSequentialString(\"cdef0123456789ab\") = false, want true (hex charset rotation)")
	}
}

// TestIsSequentialString_NotSequential verifies that "BEEF1234" is not sequential:
// it contains a subset of hex digits but their sorted form does not match any
// sorted charset prefix because of repeated characters.
func TestIsSequentialString_NotSequential(t *testing.T) {
	// "BEEF1234" lowercase = "beef1234", sorted = "1234beef"
	// sorted hex charset starts with "0123...", so "1234beef" is not a prefix.
	if isSequentialString("BEEF1234") {
		t.Errorf("isSequentialString(\"BEEF1234\") = true, want false (not sequential)")
	}
}

// ---------------------------------------------------------------------------
// Dollar-sign pre-filter test (SLICE-3)
// ---------------------------------------------------------------------------

// TestDollarPrefixSkipped verifies that a dollar-prefixed shell variable reference
// is not flagged as high entropy, even when it is > 20 chars.
func TestDollarPrefixSkipped(t *testing.T) {
	token := "$MY_SECRET_TOKEN_VARIABLE_HERE"
	if !isPrefixedWithDollarSign(token) {
		t.Errorf("isPrefixedWithDollarSign(%q) = false, want true", token)
	}
	got := detectEntropy(token)
	if got != token {
		t.Errorf("detectEntropy(%q) = %q, want unchanged (dollar-prefix pre-filter)", token, got)
	}
}

// ---------------------------------------------------------------------------
// Base64 charset entropy threshold tests (SLICE-3)
// ---------------------------------------------------------------------------

// TestBase64Entropy_BelowThreshold verifies that a token with base64 entropy below 4.5
// is not flagged as high entropy.
func TestBase64Entropy_BelowThreshold(t *testing.T) {
	// "ababab..." repeated: only 2 distinct chars → b64 entropy = 1.0 < 4.5.
	// Hex entropy = 1.0 < 3.0 as well.
	token := strings.Repeat("ab", 15) // 30 chars
	b64E := shannonEntropyOverCharset(token, b64Charset)
	if b64E >= b64Threshold {
		t.Errorf("base64 entropy of %q = %.4f, want < %.1f", token, b64E, b64Threshold)
	}
	got := detectEntropy(token)
	if got != token {
		t.Errorf("detectEntropy(%q) = %q, want unchanged (b64 entropy %.4f < threshold %.1f)",
			token, got, b64E, b64Threshold)
	}
}

// TestBase64Entropy_AboveThreshold verifies that a token with base64 entropy above 4.5
// is flagged as high entropy. Uses non-hex uppercase letters (G-Z) to ensure the
// hex path does not trigger first, isolating the base64 detection path.
func TestBase64Entropy_AboveThreshold(t *testing.T) {
	// Non-hex b64 chars: G-Z and g-z (40 unique chars, no hex chars).
	// b64 entropy = log2(40) ≈ 5.32 > 4.5; hex entropy = 0.0 (no hex chars present).
	token := "GHIJKLMNOPQRSTUVWXYZghijklmnopqrstuvwxyz"
	b64E := shannonEntropyOverCharset(token, b64Charset)
	if b64E <= b64Threshold {
		t.Fatalf("precondition: base64 entropy of %q = %.4f, want > %.1f", token, b64E, b64Threshold)
	}
	hexE := shannonEntropyOverCharset(token, hexCharset)
	if hexE != 0.0 {
		t.Logf("note: hex entropy = %.4f (expected 0.0 for pure b64-only chars)", hexE)
	}
	got := detectEntropy(token)
	if got != "<HIGH_ENTROPY>" {
		t.Errorf("detectEntropy(%q) = %q, want <HIGH_ENTROPY> (b64 entropy %.4f > threshold %.1f)",
			token, got, b64E, b64Threshold)
	}
}

// ---------------------------------------------------------------------------
// Hex charset entropy threshold tests (SLICE-3)
// ---------------------------------------------------------------------------

// TestHexEntropy_BelowThreshold verifies that a token with hex entropy below 3.0
// is not flagged as high entropy.
func TestHexEntropy_BelowThreshold(t *testing.T) {
	// All same hex char → entropy = 0.0 < 3.0.
	token := strings.Repeat("a", 24) // 24 chars, hex entropy = 0.0
	hexE := shannonEntropyOverCharset(token, hexCharset)
	if hexE >= hexThreshold {
		t.Errorf("hex entropy of %q = %.4f, want < %.1f", token, hexE, hexThreshold)
	}
	got := detectEntropy(token)
	if got != token {
		t.Errorf("detectEntropy(%q) = %q, want unchanged (hex entropy %.4f < threshold %.1f)",
			token, got, hexE, hexThreshold)
	}
}

// TestHexEntropy_AboveThreshold verifies that a token with high hex entropy is
// flagged as high entropy. Uses a realistic hex-like token (e.g. a hash fragment).
func TestHexEntropy_AboveThreshold(t *testing.T) {
	// Mix of all 16 hex digits appearing roughly equally → hex entropy ≈ 3.80 > 3.0.
	// Not a UUID (no hyphens), not sequential (repeated chars), not dollar-prefixed.
	token := "deadbeef0123456789abcdef"
	hexE := shannonEntropyOverCharset(token, hexCharset)
	if hexE <= hexThreshold {
		t.Fatalf("precondition: hex entropy of %q = %.4f, want > %.1f", token, hexE, hexThreshold)
	}
	got := detectEntropy(token)
	if got != "<HIGH_ENTROPY>" {
		t.Errorf("detectEntropy(%q) = %q, want <HIGH_ENTROPY> (hex entropy %.4f > threshold %.1f)",
			token, got, hexE, hexThreshold)
	}
}

// ---------------------------------------------------------------------------
// All-digit hex penalty test (SLICE-3)
// ---------------------------------------------------------------------------

// TestHexAllDigitPenalty verifies that the all-digit penalty formula reduces the
// effective hex entropy of a pure digit string below hexThreshold (3.0).
// The canonical example "0123456789" (10 chars) has raw hex entropy ≈ 3.32;
// after penalty (1.2 / log2(10) ≈ 0.36), effective entropy ≈ 2.96 < 3.0.
//
// Note: detectEntropy does not process strings ≤ 20 chars (length threshold).
// This test validates the penalty arithmetic directly via the underlying helpers
// to confirm that the formula achieves its design goal for the canonical example.
func TestHexAllDigitPenalty(t *testing.T) {
	s := "0123456789"
	rawHex := shannonEntropyOverCharset(s, hexCharset)
	penalty := 1.2 / math.Log2(float64(len(s)))
	effective := rawHex - penalty
	if effective >= hexThreshold {
		t.Errorf("all-digit penalty for %q: raw=%.4f penalty=%.4f effective=%.4f, want effective < %.1f",
			s, rawHex, penalty, effective, hexThreshold)
	}
}

// ---------------------------------------------------------------------------
// shannonEntropyOverCharset direct test (SLICE-3)
// ---------------------------------------------------------------------------

// TestShannonEntropyOverCharset_Direct verifies that a string of identical characters
// that appear in the charset has entropy 0.0 (no variety → no uncertainty).
func TestShannonEntropyOverCharset_Direct(t *testing.T) {
	// 'a' is a valid hex character. Six identical 'a's → only one symbol → entropy = 0.0.
	got := shannonEntropyOverCharset("aaaaaa", hexCharset)
	if got != 0.0 {
		t.Errorf("shannonEntropyOverCharset(\"aaaaaa\", hexCharset) = %.4f, want 0.0", got)
	}
}

// ---------------------------------------------------------------------------
// FilePathFilter test (SLICE-3)
// ---------------------------------------------------------------------------

// TestNoopFilePathFilter_NeverSuppresses verifies that NoopFilePathFilter always
// returns false for any source path, meaning entropy detection runs unconditionally.
func TestNoopFilePathFilter_NeverSuppresses(t *testing.T) {
	f := NoopFilePathFilter{}
	paths := []string{
		"package-lock.json",
		"go.sum",
		"yarn.lock",
		"swagger.json",
		"src/main.go",
		"",
		"/absolute/path/to/file.ts",
	}
	for _, p := range paths {
		if f.SuppressEntropy(p) {
			t.Errorf("NoopFilePathFilter.SuppressEntropy(%q) = true, want false", p)
		}
	}
}
