package redact

import (
	"strings"
	"testing"
	"unsafe"
)

// ---------------------------------------------------------------------------
// AC2: Detect() returns []Match with correct fields
// ---------------------------------------------------------------------------

// TestDetect_ReturnsMatchFields verifies that Detect() returns matches with
// correct Rule, Offset, Length, Category, and MatchedText for a known secret.
func TestDetect_ReturnsMatchFields(t *testing.T) {
	r := mustNewRedactor(t, Minimal, nil)
	input := "token: " + testAnthropicKey
	matches := r.Detect(input)

	if len(matches) == 0 {
		t.Fatalf("Detect(%q): expected at least one match, got none", input)
	}

	// Find the anthropic_key match.
	var found *Match
	for i := range matches {
		if matches[i].Rule == "anthropic_key" {
			found = &matches[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("Detect: no match with Rule=anthropic_key in %+v", matches)
	}

	// Verify Category.
	if found.Category != CategorySecrets {
		t.Errorf("Match.Category = %q, want %q", found.Category, CategorySecrets)
	}

	// Verify Offset and Length are consistent with the input.
	end := found.Offset + found.Length
	if end > len(input) {
		t.Fatalf("Match span [%d, %d] out of range for input len=%d", found.Offset, end, len(input))
	}
	if input[found.Offset:end] != found.MatchedText {
		t.Errorf("input[Offset:Offset+Length] = %q, want MatchedText = %q", input[found.Offset:end], found.MatchedText)
	}
}

// TestDetect_ZeroCopyMatchedText verifies that MatchedText shares the backing
// array of the input string (zero-copy, NFR1).
// We use unsafe.StringData to compare pointer addresses.
func TestDetect_ZeroCopyMatchedText(t *testing.T) {
	r := mustNewRedactor(t, Minimal, nil)
	input := "token: " + testAnthropicKey

	matches := r.Detect(input)
	if len(matches) == 0 {
		t.Fatal("Detect: expected at least one match")
	}

	var found *Match
	for i := range matches {
		if matches[i].Rule == "anthropic_key" {
			found = &matches[i]
			break
		}
	}
	if found == nil {
		t.Fatal("Detect: anthropic_key match not found")
	}

	// unsafe.StringData returns a pointer to the first byte of the string's
	// backing array. For a zero-copy substring slice, this pointer offset must
	// equal inputData + Offset.
	inputData := unsafe.StringData(input)
	matchData := unsafe.StringData(found.MatchedText)

	// The matched text pointer must be exactly input pointer + offset.
	wantPtr := unsafe.Add(unsafe.Pointer(inputData), found.Offset)
	if unsafe.Pointer(matchData) != wantPtr {
		t.Errorf("MatchedText backing pointer = %p, want input[%d] = %p (zero-copy violation)",
			matchData, found.Offset, wantPtr)
	}
}

// TestDetect_SortedByOffset verifies that matches are returned sorted by
// offset in ascending order.
func TestDetect_SortedByOffset(t *testing.T) {
	r := mustNewRedactor(t, Standard, nil)
	// Both anthropic key (Secrets) and email (PII) should match.
	input := testAnthropicKey + " user@example.com"

	matches := r.Detect(input)
	if len(matches) < 2 {
		t.Fatalf("Detect: expected at least 2 matches, got %d: %+v", len(matches), matches)
	}

	for i := 1; i < len(matches); i++ {
		if matches[i].Offset < matches[i-1].Offset {
			t.Errorf("Detect: matches not sorted by offset: matches[%d].Offset=%d < matches[%d].Offset=%d",
				i, matches[i].Offset, i-1, matches[i-1].Offset)
		}
	}
}

// TestDetect_DoesNotModifyInput verifies that Detect() does not modify the input
// string (verified by string equality after the call).
func TestDetect_DoesNotModifyInput(t *testing.T) {
	r := mustNewRedactor(t, Standard, nil)
	input := "token: " + testAnthropicKey + " user@example.com"
	original := input // capture before call

	_ = r.Detect(input)

	if input != original {
		t.Errorf("Detect modified input: got %q, want %q", input, original)
	}
}

// TestDetect_NilMatchesOnNoPatterns verifies that Detect returns nil (not an
// empty slice) when no patterns match.
func TestDetect_NilMatchesOnNoPatterns(t *testing.T) {
	r := mustNewRedactor(t, Minimal, nil)
	matches := r.Detect("hello world no secrets here")
	if matches != nil {
		t.Errorf("Detect (no match): expected nil, got %+v", matches)
	}
}

// TestDetect_EmptyInput verifies that Detect returns nil for empty input.
func TestDetect_EmptyInput(t *testing.T) {
	r := mustNewRedactor(t, Minimal, nil)
	matches := r.Detect("")
	if matches != nil {
		t.Errorf("Detect(%q): expected nil, got %+v", "", matches)
	}
}

// TestDetect_CategoryGating verifies that PII patterns are not returned at
// Minimal level but are returned at Standard level.
func TestDetect_CategoryGating(t *testing.T) {
	emailInput := "user@example.com"

	rMinimal := mustNewRedactor(t, Minimal, nil)
	matchesMinimal := rMinimal.Detect(emailInput)
	for _, m := range matchesMinimal {
		if m.Category == CategoryPII {
			t.Errorf("Detect(Minimal): PII match returned unexpectedly: %+v", m)
		}
	}

	rStandard := mustNewRedactor(t, Standard, nil)
	matchesStandard := rStandard.Detect(emailInput)
	found := false
	for _, m := range matchesStandard {
		if m.Rule == "email" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Detect(Standard): expected email match, got %+v", matchesStandard)
	}
}

// ---------------------------------------------------------------------------
// AC3: Redact(input, matches) replaces only provided spans
// ---------------------------------------------------------------------------

// TestRedact_ReplacesMatchSpans verifies that Redact replaces all match spans
// and leaves non-match text untouched.
func TestRedact_ReplacesMatchSpans(t *testing.T) {
	r := mustNewRedactor(t, Minimal, nil)
	input := "before " + testAnthropicKey + " after"

	matches := r.Detect(input)
	if len(matches) == 0 {
		t.Fatal("Detect: expected at least one match")
	}

	output := r.Redact(input, matches)

	if strings.Contains(output, "sk-ant-api03") {
		t.Errorf("Redact: raw key leaked in output: %q", output)
	}
	if !strings.Contains(output, "<ANTHROPIC_KEY>") {
		t.Errorf("Redact: expected <ANTHROPIC_KEY> in output: %q", output)
	}
	// Non-match text must be preserved.
	if !strings.Contains(output, "before") {
		t.Errorf("Redact: 'before' text missing from output: %q", output)
	}
	if !strings.Contains(output, "after") {
		t.Errorf("Redact: 'after' text missing from output: %q", output)
	}
}

// TestRedact_NilMatchesReturnsInput verifies that Redact(input, nil) returns
// the input string unchanged.
func TestRedact_NilMatchesReturnsInput(t *testing.T) {
	r := mustNewRedactor(t, Minimal, nil)
	input := "hello world"
	output := r.Redact(input, nil)
	if output != input {
		t.Errorf("Redact(input, nil): got %q, want %q", output, input)
	}
}

// TestRedact_EmptyMatchesReturnsInput verifies that Redact(input, []Match{})
// returns the input string unchanged.
func TestRedact_EmptyMatchesReturnsInput(t *testing.T) {
	r := mustNewRedactor(t, Minimal, nil)
	input := "hello world"
	output := r.Redact(input, []Match{})
	if output != input {
		t.Errorf("Redact(input, []Match{}): got %q, want %q", output, input)
	}
}

// TestRedact_DoesNotRescan verifies that Redact does NOT re-scan: when provided
// an empty match list for text that would normally trigger redaction, the raw
// sensitive text passes through unchanged.
func TestRedact_DoesNotRescan(t *testing.T) {
	r := mustNewRedactor(t, Minimal, nil)
	input := "token: " + testAnthropicKey
	// Pass nil matches — Redact must not scan on its own.
	output := r.Redact(input, nil)
	if !strings.Contains(output, "sk-ant-api03") {
		t.Errorf("Redact(input, nil): expected raw key to pass through unchanged, got: %q", output)
	}
}

// TestRedact_OnlyReplacesProvidedSpans verifies that when only a subset of
// matches is provided, only those spans are replaced (others pass through).
func TestRedact_OnlyReplacesProvidedSpans(t *testing.T) {
	r := mustNewRedactor(t, Standard, nil)
	input := testAnthropicKey + " user@example.com"

	allMatches := r.Detect(input)
	if len(allMatches) < 2 {
		t.Fatalf("Detect: expected at least 2 matches, got %d", len(allMatches))
	}

	// Only pass the first match to Redact.
	firstOnly := allMatches[:1]
	output := r.Redact(input, firstOnly)

	// The first match's raw text must be replaced.
	if strings.Contains(output, firstOnly[0].MatchedText) {
		t.Errorf("Redact(firstOnly): match %q still present in output: %q", firstOnly[0].MatchedText, output)
	}
	// The second match's raw text must still be present (not re-scanned).
	if !strings.Contains(output, allMatches[1].MatchedText) {
		t.Errorf("Redact(firstOnly): non-provided match %q unexpectedly redacted in output: %q", allMatches[1].MatchedText, output)
	}
}

// ---------------------------------------------------------------------------
// Parity regression: RedactText == Detect+Redact
// ---------------------------------------------------------------------------

// TestRedactText_ParityWithDetectRedact verifies that RedactText produces
// identical output to r.Redact(input, r.Detect(input)) for fixture inputs.
// This is the key regression test: any divergence means the two code paths
// have drifted and a privacy regression exists.
func TestRedactText_ParityWithDetectRedact(t *testing.T) {
	fixtureInputs := []struct {
		name  string
		level RedactionLevel
		input string
	}{
		{
			name:  "anthropic_key_minimal",
			level: Minimal,
			input: "token: " + testAnthropicKey,
		},
		{
			name:  "email_standard",
			level: Standard,
			input: "contact user@example.com for support",
		},
		{
			name:  "key_and_email_standard",
			level: Standard,
			input: testAnthropicKey + " user@example.com path=/home/alice/config",
		},
		{
			name:  "no_match_minimal",
			level: Minimal,
			input: "hello world no secrets here",
		},
		{
			name:  "empty_string",
			level: Standard,
			input: "",
		},
		{
			name:  "github_pat_minimal",
			level: Minimal,
			input: "ghp_abc123def456abc123def456abc12345",
		},
		{
			name:  "aws_access_key_minimal",
			level: Minimal,
			input: "AKIAIOSFODNN7EXAMPLE config value",
		},
	}

	for _, tt := range fixtureInputs {
		t.Run(tt.name, func(t *testing.T) {
			// Create two independent redactors to avoid shared state.
			r1 := mustNewRedactor(t, tt.level, nil)
			r2 := mustNewRedactor(t, tt.level, nil)

			oldPath := r1.RedactText(tt.input)
			newPath := r2.Redact(tt.input, r2.Detect(tt.input))

			if oldPath != newPath {
				t.Errorf("Parity violation for %q (level=%s):\n  RedactText:    %q\n  Detect+Redact: %q",
					tt.input, tt.level, oldPath, newPath)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Report().Matches — last-call-only semantics
// ---------------------------------------------------------------------------

// TestReport_MatchesLastCallOnly verifies that Report().Matches reflects the
// matches from the last Detect() call, not accumulated across calls.
func TestReport_MatchesLastCallOnly(t *testing.T) {
	r := mustNewRedactor(t, Standard, nil)

	// First Detect: anthropic key only.
	input1 := "token: " + testAnthropicKey
	matches1 := r.Detect(input1)
	report1 := r.Report()

	if len(report1.Matches) != len(matches1) {
		t.Errorf("Report after first Detect: Matches count = %d, want %d",
			len(report1.Matches), len(matches1))
	}

	// Second Detect: email only (different input).
	input2 := "contact user@example.com"
	matches2 := r.Detect(input2)
	report2 := r.Report()

	if len(report2.Matches) != len(matches2) {
		t.Errorf("Report after second Detect: Matches count = %d, want %d (should be last-call-only)",
			len(report2.Matches), len(matches2))
	}

	// Verify the second report contains the email match, not the key match.
	for _, m := range report2.Matches {
		if m.Rule == "anthropic_key" {
			t.Errorf("Report after second Detect: found anthropic_key match — should be last-call-only (second call was email)")
		}
	}
}

// TestReport_MatchesNilAfterNoMatch verifies that Report().Matches is nil
// after a Detect() call that finds no matches.
func TestReport_MatchesNilAfterNoMatch(t *testing.T) {
	r := mustNewRedactor(t, Minimal, nil)
	_ = r.Detect("hello world no secrets")
	report := r.Report()
	if report.Matches != nil {
		t.Errorf("Report().Matches should be nil after no-match Detect, got %+v", report.Matches)
	}
}
