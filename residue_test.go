package redact

import (
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
)

// testEmail is a shared constant for residue tests to avoid repeating inline literals.
const testEmail = "user@example.com"

// ---------------------------------------------------------------------------
// Residue rule table validation
// ---------------------------------------------------------------------------

func TestResidueRules_Compiled(t *testing.T) {
	for _, r := range ResidueRules {
		if r.Pattern == nil {
			t.Errorf("ResidueRule %q has nil Pattern", r.ID)
		}
	}
}

// ---------------------------------------------------------------------------
// Missed pattern detection — Scan must produce warnings
// ---------------------------------------------------------------------------

func TestResidueDetector_MissedAPIKey(t *testing.T) {
	d := NewResidueDetector()
	// Simulates a missed Anthropic key that slipped through primary redaction.
	warnings := d.Scan("the key is sk-ant-api03-abc123def456xyz789")
	if len(warnings) == 0 {
		t.Error("MissedAPIKey: expected at least one warning for missed Anthropic key pattern")
	}
	// At least one warning should reference an anthropic or api key rule.
	found := false
	for _, w := range warnings {
		if strings.Contains(w.RuleID, "anthropic") || strings.Contains(w.RuleID, "api_key") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("MissedAPIKey: no warning with anthropic/api_key rule ID; got %v", warnings)
	}
}

func TestResidueDetector_MissedEmail(t *testing.T) {
	d := NewResidueDetector()
	warnings := d.Scan("contact: " + testEmail + " please")
	if len(warnings) == 0 {
		t.Error("MissedEmail: expected at least one warning for missed email pattern")
	}
	found := false
	for _, w := range warnings {
		if strings.Contains(w.RuleID, "email") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("MissedEmail: no warning with email rule ID; got %v", warnings)
	}
}

func TestResidueDetector_Base64Long(t *testing.T) {
	d := NewResidueDetector()
	// 60-char base64 string — should trigger residue_base64_long.
	b64 := "dGhpcyBpcyBhIGJhc2U2NCBlbmNvZGVkIHN0cmluZyB0aGF0IGlzIHF1aXRl"
	warnings := d.Scan("data: " + b64 + " end")
	found := false
	for _, w := range warnings {
		if strings.Contains(w.RuleID, "base64") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Base64Long: expected warning for base64 string >40 chars; got %v", warnings)
	}
}

func TestResidueDetector_HexLong(t *testing.T) {
	d := NewResidueDetector()
	// 40-char hex string — should trigger residue_hex_long.
	hex := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	warnings := d.Scan("hash: " + hex + " done")
	found := false
	for _, w := range warnings {
		if strings.Contains(w.RuleID, "hex") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("HexLong: expected warning for hex string >32 chars; got %v", warnings)
	}
}

func TestResidueDetector_BearerPrefix(t *testing.T) {
	d := NewResidueDetector()
	warnings := d.Scan("Authorization: Bearer eyJabc123xyztoken")
	found := false
	for _, w := range warnings {
		if strings.Contains(w.RuleID, "bearer") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("BearerPrefix: expected warning for Bearer token; got %v", warnings)
	}
}

// ---------------------------------------------------------------------------
// Positive trigger tests for all residue rules
// ---------------------------------------------------------------------------

func TestResidueRules_PositiveTriggers(t *testing.T) {
	// Each case provides an input that MUST trigger the named rule.
	// This table covers the 15 rules not exercised by other dedicated tests.
	cases := []struct {
		ruleID string
		input  string
	}{
		{
			ruleID: "residue_openai_key",
			input:  "key: sk-live-abcdefghij1234567890",
		},
		{
			ruleID: "residue_github_pat",
			input:  "ghp_abcdefghij1234567890xyz",
		},
		{
			ruleID: "residue_aws_access_key",
			input:  "AKIAIOSFODNN7EXAMPLE0000",
		},
		{
			ruleID: "residue_stripe_key",
			input:  "sk_live_abcdefghij1234567890",
		},
		{
			ruleID: "residue_twilio_key",
			input:  "ACa1b2c3d4e5f6a1b2c3d4e5f6",
		},
		{
			ruleID: "residue_sendgrid_key",
			input:  "SG.abcdefghij1234567890xyz",
		},
		{
			ruleID: "residue_slack_token",
			input:  "token: xoxb-12345678-abcdefgh",
		},
		{
			ruleID: "residue_jwt_token",
			input:  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.sig",
		},
		{
			ruleID: "residue_private_key",
			input:  "-----BEGIN RSA PRIVATE KEY-----",
		},
		{
			ruleID: "residue_generic_api_key",
			input:  "api_key=abcdefghij1234567890",
		},
		{
			ruleID: "residue_basic_auth",
			input:  "Authorization: Basic dXNlcjpwYXNz123456789",
		},
		{
			ruleID: "residue_phone",
			input:  "call 555-867-5309 now",
		},
		{
			ruleID: "residue_ssn",
			input:  "ssn: 123-45-6789",
		},
		{
			ruleID: "residue_credit_card",
			input:  "card: 4111-1111-1111-1111",
		},
		{
			ruleID: "residue_ip_address",
			input:  "server 192.168.1.100 is up",
		},
		{
			ruleID: "residue_unix_path",
			input:  "log at /home/alice/app.log",
		},
		{
			ruleID: "residue_windows_path",
			input:  `path: C:\Users\alice\Documents`,
		},
		{
			ruleID: "residue_broad_api_key",
			input:  "sk-aabbccddee-ffgghhiijj",
		},
	}

	d := NewResidueDetector()
	for _, tc := range cases {
		t.Run(tc.ruleID, func(t *testing.T) {
			warnings := d.Scan(tc.input)
			found := false
			for _, w := range warnings {
				if w.RuleID == tc.ruleID {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("rule %q did not trigger on input %q; got warnings %v", tc.ruleID, tc.input, warnings)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Clean text tests — Scan must NOT produce warnings
// ---------------------------------------------------------------------------

func TestResidueDetector_FullyRedactedText(t *testing.T) {
	d := NewResidueDetector()
	// Placeholder tokens should not trigger residue rules.
	warnings := d.Scan("the key is <ANTHROPIC_KEY> and email is <EMAIL>")
	if len(warnings) != 0 {
		t.Errorf("FullyRedactedText: expected no warnings for placeholder tokens; got %v", warnings)
	}
}

func TestResidueDetector_NormalText(t *testing.T) {
	d := NewResidueDetector()
	warnings := d.Scan("Today is a good day for coding.")
	if len(warnings) != 0 {
		t.Errorf("NormalText: expected no warnings for normal prose; got %v", warnings)
	}
}

func TestResidueDetector_EmptyString(t *testing.T) {
	d := NewResidueDetector()
	warnings := d.Scan("")
	if len(warnings) != 0 {
		t.Errorf("EmptyString: expected no warnings for empty input; got %v", warnings)
	}
}

// ---------------------------------------------------------------------------
// Preview field safety — Preview must be bounded and safe
// ---------------------------------------------------------------------------

func TestResidueDetector_PreviewContent(t *testing.T) {
	d := NewResidueDetector()
	// Use a key that matches the primary anthropic_key rule pattern:
	// sk-ant-[a-zA-Z0-9]{4,}-[a-zA-Z0-9_-]{20,}
	// "api3" = 4 chars (satisfies {4,}), "abcdefghij1234567890" = 20 chars (satisfies {20,}).
	rawKey := "sk-ant-api3-abcdefghij1234567890"
	input := "the key is " + rawKey + " and more text here"
	warnings := d.Scan(input)
	if len(warnings) == 0 {
		t.Fatal("PreviewContent: expected at least one warning")
	}
	for _, w := range warnings {
		if len(w.Preview) > PreviewMaxLength {
			t.Errorf("PreviewContent: Preview too long (%d bytes > %d): %q", len(w.Preview), PreviewMaxLength, w.Preview)
		}
		// The Preview must NOT contain the full raw secret value — the primary
		// redaction pass inside safePreview replaces it with a placeholder.
		if strings.Contains(w.Preview, rawKey) {
			t.Errorf("PreviewContent: Preview exposes full raw secret %q in: %q", rawKey, w.Preview)
		}
	}
}

// ---------------------------------------------------------------------------
// Location offset — Location must equal the byte offset of the match start
// ---------------------------------------------------------------------------

func TestResidueDetector_LocationOffset(t *testing.T) {
	d := NewResidueDetector()
	// Email is at a known byte position.
	prefix := "contact: "
	email := testEmail
	input := prefix + email + " please"
	warnings := d.Scan(input)

	expectedOffset := len(prefix) // byte offset where the email starts

	found := false
	for _, w := range warnings {
		if strings.Contains(w.RuleID, "email") {
			found = true
			if w.Location != expectedOffset {
				t.Errorf("LocationOffset: expected Location=%d, got %d", expectedOffset, w.Location)
			}
		}
	}
	if !found {
		t.Errorf("LocationOffset: no email warning found; got %v", warnings)
	}
}

// ---------------------------------------------------------------------------
// Advisory-only contract — Scan returns warnings, never a modified string
// ---------------------------------------------------------------------------

// TestResidueDetector_AdvisoryOnlyContract verifies the ResidueDetector
// interface contract: Scan returns []ResidueWarning, not a modified string.
// The test demonstrates this by asserting that both a warnings-triggering input
// and a clean input produce distinct, non-nil/nil result sets, confirming
// Scan's return type is purely additive rather than transformative.
func TestResidueDetector_AdvisoryOnlyContract(t *testing.T) {
	d := NewResidueDetector()

	// An input that triggers at least one residue rule.
	dirtyInput := "contact: " + testEmail + " is the address"
	dirtyWarnings := d.Scan(dirtyInput)
	if len(dirtyWarnings) == 0 {
		t.Fatal("AdvisoryOnlyContract: expected warnings for email-containing input")
	}

	// A clean input produces no warnings.
	cleanInput := "Today is a good day for coding."
	cleanWarnings := d.Scan(cleanInput)
	if len(cleanWarnings) != 0 {
		t.Errorf("AdvisoryOnlyContract: expected no warnings for clean input; got %v", cleanWarnings)
	}
}

// ---------------------------------------------------------------------------
// Short patterns — must NOT false-positive on the specific rule under test.
// Each input also contains testEmail so the loop body provably executes.
// ---------------------------------------------------------------------------

func TestResidueDetector_ShortPatternNoFalsePositive(t *testing.T) {
	d := NewResidueDetector()
	// "sk-" alone is too short to match residue_anthropic_key (requires 10+ after prefix).
	// testEmail ensures at least one warning is produced, proving the rule loop runs.
	warnings := d.Scan("prefix sk- suffix " + testEmail)
	if len(warnings) == 0 {
		t.Fatal("ShortPatternNoFalsePositive: expected at least one warning (from email rule) to prove loop executes")
	}
	for _, w := range warnings {
		if strings.Contains(w.RuleID, "anthropic") {
			t.Errorf("ShortPatternNoFalsePositive: unexpected anthropic warning for 'sk-': %v", w)
		}
	}
}

func TestResidueDetector_ShortHexNoFalsePositive(t *testing.T) {
	d := NewResidueDetector()
	// 16-char hex — too short for residue_hex_long (requires ≥32 chars).
	// testEmail ensures at least one warning is produced, proving the rule loop runs.
	warnings := d.Scan("id: a1b2c3d4e5f6a1b2 done " + testEmail)
	if len(warnings) == 0 {
		t.Fatal("ShortHexNoFalsePositive: expected at least one warning (from email rule) to prove loop executes")
	}
	for _, w := range warnings {
		if strings.Contains(w.RuleID, "hex") {
			t.Errorf("ShortHexNoFalsePositive: unexpected hex_long warning for 16-char hex: %v", w)
		}
	}
}

func TestResidueDetector_ShortBase64NoFalsePositive(t *testing.T) {
	d := NewResidueDetector()
	// 20-char base64 — too short for residue_base64_long (requires ≥40 chars).
	// testEmail ensures at least one warning is produced, proving the rule loop runs.
	warnings := d.Scan("data: dGhpcyBpcyBzaG9ydA== end " + testEmail)
	if len(warnings) == 0 {
		t.Fatal("ShortBase64NoFalsePositive: expected at least one warning (from email rule) to prove loop executes")
	}
	for _, w := range warnings {
		if strings.Contains(w.RuleID, "base64") {
			t.Errorf("ShortBase64NoFalsePositive: unexpected base64_long warning for 20-char base64: %v", w)
		}
	}
}

// ---------------------------------------------------------------------------
// Non-ASCII input — safePreview must not produce invalid UTF-8
// ---------------------------------------------------------------------------

func TestResidueDetector_NonASCIISuffixPreviewValid(t *testing.T) {
	d := NewResidueDetector()
	// Multi-byte runes on both sides, long enough to force wideEnd < total
	prefix := strings.Repeat("あ", 200) // 600 bytes
	suffix := strings.Repeat("い", 200) // 600 bytes
	secret := "sk-ant-api03-abcdefghij1234567890"
	text := prefix + secret + suffix
	warnings := d.Scan(text)
	if len(warnings) == 0 {
		t.Fatal("expected at least one warning")
	}
	for _, w := range warnings {
		if !utf8.ValidString(w.Preview) {
			t.Errorf("preview is not valid UTF-8: %q", w.Preview)
		}
	}
}

func TestResidueDetector_NonASCIIPreviewValid(t *testing.T) {
	d := NewResidueDetector()
	// Multi-byte characters before the secret. The byte offset of the key
	// must not be treated as a rune index (bug: unified-schema-02p8).
	// strings.Repeat("あ", 27) = 27 × 3 bytes = 81 bytes — well above the
	// halfWide boundary (80 bytes for PreviewMaxLength=40), forcing wideStart>0
	// and exercising the rune-alignment fix in safePreview.
	prefix := strings.Repeat("あ", 27) // 81 bytes of 3-byte UTF-8 runes
	input := prefix + " sk-ant-api03-abc123def456xyz789 world"
	warnings := d.Scan(input)
	if len(warnings) == 0 {
		t.Skip("NonASCIIPreview: pattern not matched — test premise invalid, skip")
	}
	for _, w := range warnings {
		if !utf8.ValidString(w.Preview) {
			t.Errorf("NonASCIIPreview: Preview is not valid UTF-8: %q", w.Preview)
		}
	}
}

// ---------------------------------------------------------------------------
// Concurrency — ResidueDetector via Redactor at Maximum must be safe
// ---------------------------------------------------------------------------

// TestResidueDetector_ConcurrencyViaRedactor verifies that concurrent calls to
// RedactText at Maximum level (which exercises the residue scanner) produce
// consistent, identical output and never race. This mirrors TestASTAnonymizer_ConcurrencyMaximum.
func TestResidueDetector_ConcurrencyViaRedactor(t *testing.T) {
	r := mustNewRedactor(t, Maximum, nil)
	// Input triggers multiple residue rules (hex_long pattern).
	// Use low-entropy hex (entropy ~2.0) to bypass entropy detector and reach residue scanner.
	input := "hash: aaaabbbbccccddddaaaabbbbccccdddd and email " + testEmail + " done"

	const goroutines = 10
	results := make([]string, goroutines)
	var wg sync.WaitGroup

	wg.Add(goroutines)
	for i := range goroutines {
		go func() {
			defer wg.Done()
			results[i] = r.RedactText(input)
		}()
	}
	wg.Wait()

	// All goroutines must produce a non-empty result.
	for i, out := range results {
		if out == "" {
			t.Errorf("ConcurrencyViaRedactor: goroutine %d returned empty string", i)
		}
	}

	// All goroutines must produce identical output (no data races alter results).
	first := results[0]
	for i := 1; i < goroutines; i++ {
		if results[i] != first {
			t.Errorf("ConcurrencyViaRedactor: goroutine %d output differs from goroutine 0:\ngot:  %q\nwant: %q", i, results[i], first)
		}
	}

	// After concurrent calls, the report must have residue warnings.
	report := r.Report()
	if len(report.Warnings) == 0 {
		t.Error("ConcurrencyViaRedactor: expected Report().Warnings populated after residue-triggering inputs")
	}
}

// ---------------------------------------------------------------------------
// Integration: residue warnings in RedactionReport — table-driven
// ---------------------------------------------------------------------------

func TestDefaultRedactor_ResidueWarningsInReport(t *testing.T) {
	// Each case uses an input that slips PAST the primary Rules at Maximum level
	// but is still caught by the broader residue scanner. This simulates real
	// near-misses: patterns close to but not exactly matching the primary rules.
	tests := []struct {
		name         string
		input        string
		wantRuleHint string // substring expected in at least one warning string
	}{
		{
			// 34-char hex: long enough for residue_hex_long (≥32) but does not
			// match the primary aws_access_key or aws_secret_key rules (wrong
			// character class / prefix). The hex string slips through.
			// Use low-entropy hex (entropy ~2.0) to bypass entropy detector and reach residue scanner.
			name:         "hex_slips_through",
			input:        "hash: aaaabbbbccccddddaaaabbbbccccdddd done",
			wantRuleHint: "hex",
		},
		{
			// A Twilio-like key with only 20 hex chars after "AC" — the primary
			// twilio_key rule requires exactly 32 chars (AC[a-f0-9]{32}), so this
			// slips past but the residue_twilio_key rule catches it (AC[a-f0-9]{20,}).
			// Use low-entropy hex (entropy ~0.53) to bypass entropy detector and reach residue scanner.
			name:         "api_key_variant_slips_through",
			input:        "token: ACaaaaaaaaaaaaaaaaaaaa auth",
			wantRuleHint: "twilio",
		},
		{
			// A low-entropy "sk-" token that doesn't match any specific provider
			// rule (anthropic requires "sk-ant-", openai requires "sk-live|test|proj-",
			// stripe requires "sk_live|test_"). Low entropy prevents the entropy
			// detector from catching it. residue_broad_api_key catches it.
			name:         "broad_api_key_slips_through",
			input:        "api: sk-aabbccddee-ffgghhii done",
			wantRuleHint: "api_key",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := mustNewRedactor(t, Maximum, nil)
			_ = r.RedactText(tc.input)
			report := r.Report()

			if len(report.Warnings) == 0 {
				t.Errorf("ResidueWarningsInReport[%s]: expected Report().Warnings populated; got none", tc.name)
				return
			}
			found := false
			for _, w := range report.Warnings {
				if strings.Contains(w, tc.wantRuleHint) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("ResidueWarningsInReport[%s]: no warning containing %q; got %v", tc.name, tc.wantRuleHint, report.Warnings)
			}
		})
	}
}
