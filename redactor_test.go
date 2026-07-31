package redact

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/peasant-labs/schema"
)

// testAnthropicKey is the shared Anthropic API key fixture used across tests.
// It is short enough to be distinct from the longer variant in TestRedactText_SecretsRules
// but long enough to satisfy the regex (20+ chars after the prefix segment).
const testAnthropicKey = "sk-ant-api03-abc123def456abc123def456"

// testHighEntropyToken is a 33-char high-entropy string used to verify entropy detection
// at Maximum level. It must be >20 chars and have Shannon entropy >4.0 bits.
const testHighEntropyToken = "aB3xQ9mZ7kL2pR8nT4vY6wU1sE5jC0dF"

// ---------------------------------------------------------------------------
// L1 type tests
// ---------------------------------------------------------------------------

func TestRules_Compiled(t *testing.T) {
	for _, r := range Rules {
		if r.Pattern == nil {
			t.Errorf("Rule %q has nil Pattern", r.ID)
		}
		if _, ok := effectiveMinimumLevel(r); !ok {
			t.Errorf("Rule %q has invalid category/minimum-level activation metadata", r.ID)
		}
	}
}

func TestIsActiveRule_InvalidMetadataFailsClosed(t *testing.T) {
	r := &DefaultRedactor{level: Minimal}
	rule := Rule{Category: CategoryProject, MinimumLevel: RedactionLevel("invalid")}
	if !r.isActiveRule(rule) {
		t.Fatal("isActiveRule returned false for invalid metadata; runtime fallback must favor redaction")
	}
}

// ---------------------------------------------------------------------------
// Secrets rule tests
// ---------------------------------------------------------------------------

func TestRedactText_SecretsRules(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		contains string
	}{
		{
			"anthropic_key",
			"sk-ant-api03-abc123def456abc123def456abc123def456abc123",
			"<ANTHROPIC_KEY>",
		},
		{
			// Real-format OpenAI key: 20 chars + T3BlbkFJ marker + 20 chars.
			// Synthetic body with the documented format anchors.
			"openai_key",
			"sk-abcdefghij0123456789T3BlbkFJabcdefghij0123456789",
			"<OPENAI_KEY>",
		},
		{
			// Real-format GitHub PAT from detect-secrets/tests/plugins/github_token_test.py.
			"github_pat",
			"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",
			"<GITHUB_PAT>",
		},
		{
			"aws_access_key",
			"AKIAIOSFODNN7EXAMPLE",
			"<AWS_ACCESS_KEY>",
		},
		{
			// Trailing space is a sentinel delimiter — must be preserved in output.
			// AWS context keyword ("aws_secret_access_key") is required by FilterFn.
			"aws_secret_key",
			`aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" next`,
			"<AWS_SECRET_KEY>",
		},
		{
			// Real-format Stripe key: sk_live_ + exactly 24 alphanumeric chars.
			"stripe_key",
			"sk_live_abcdefghijklmnopqrstuvwx",
			"<STRIPE_KEY>",
		},
		{
			// Twilio Account SID: AC + exactly 32 lowercase hex chars.
			"twilio_key",
			"ACabc123def456abc123def456abc123de",
			"<TWILIO_KEY>",
		},
		{
			// Twilio Auth Token: SK + exactly 32 lowercase hex chars.
			"twilio_auth_token",
			"SKabc123def456abc123def456abc123de",
			"<TWILIO_AUTH_TOKEN>",
		},
		{
			// Real-format SendGrid key from detect-secrets/tests/plugins/sendgrid_test.py:
			// SG. + exactly 22 chars + . + exactly 43 chars.
			"sendgrid_key",
			"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",
			"<SENDGRID_KEY>",
		},
		{
			// Real-shape Slack token from detect-secrets/tests/plugins/slack_test.py:
			// xoxb- + numeric segments + alphanumeric token.
			"slack_token",
			"xoxb-34532454-e039d02840a0b9379c",
			"<SLACK_TOKEN>",
		},
		{
			"jwt_token",
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.abc123def456",
			"<JWT_TOKEN>",
		},
		{
			"private_key_block",
			"-----BEGIN RSA PRIVATE KEY-----",
			"<PRIVATE_KEY>",
		},
		{
			"generic_api_key",
			"api_key=abc123def456abc123def456abc123def456",
			"<API_KEY>",
		},
		{
			"bearer_token",
			"Bearer abc123def456abc123def456",
			"<BEARER_TOKEN>",
		},
		{
			"basic_auth",
			"Authorization: Basic dXNlcjpwYXNz",
			"<BASIC_AUTH>",
		},
		{
			"access_code",
			"Please enter verification code: ABCD-1234",
			"<ACCESS_CODE>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := mustNewRedactor(t, Minimal, nil)
			got := r.RedactText(tt.input)
			if !strings.Contains(got, tt.contains) {
				t.Errorf("RedactText(%q) = %q, want output containing %q", tt.input, got, tt.contains)
			}
		})
	}
}

// TestRedactText_AWSSecretKeyTrailingSentinel verifies that the trailing
// sentinel character (space) after an AWS secret key is preserved in output.
// Regression test for A-B1: the old pattern consumed the sentinel into the
// replacement, silently dropping the character that followed the key.
// The input includes AWS context ("aws_secret_access_key") required by FilterFn
// to classify this as a true positive.
func TestRedactText_AWSSecretKeyTrailingSentinel(t *testing.T) {
	r := mustNewRedactor(t, Minimal, nil)
	input := `aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" next`
	got := r.RedactText(input)

	if !strings.Contains(got, "<AWS_SECRET_KEY>") {
		t.Errorf("AWSSecretKeyTrailingSentinel: expected <AWS_SECRET_KEY> in output: %q", got)
	}
	// The space sentinel and the word "next" must be preserved.
	if !strings.Contains(got, "next") {
		t.Errorf("AWSSecretKeyTrailingSentinel: trailing sentinel consumed — 'next' missing from output: %q", got)
	}
}

// ---------------------------------------------------------------------------
// PII rule tests (5 cases + level gating)
// ---------------------------------------------------------------------------

func TestRedactText_PIIRules(t *testing.T) {
	tests := []struct {
		name     string
		level    RedactionLevel
		input    string
		contains string
		absent   string
	}{
		{
			name:     "email_standard",
			level:    Standard,
			input:    "user@example.com",
			contains: "<EMAIL>",
		},
		{
			name:   "email_minimal_unchanged",
			level:  Minimal,
			input:  "user@example.com",
			absent: "<EMAIL>",
		},
		{
			name:     "phone_us_standard",
			level:    Standard,
			input:    "+1-555-123-4567",
			contains: "<PHONE>",
		},
		{
			name:     "ssn_standard",
			level:    Standard,
			input:    "123-45-6789",
			contains: "<SSN>",
		},
		{
			name:     "credit_card_standard",
			level:    Standard,
			input:    "4111 1111 1111 1111",
			contains: "<CREDIT_CARD>",
		},
		{
			name:     "ip_address_standard",
			level:    Standard,
			input:    "192.168.1.100",
			contains: "<IP_ADDRESS>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := mustNewRedactor(t, tt.level, nil)
			got := r.RedactText(tt.input)
			if tt.contains != "" && !strings.Contains(got, tt.contains) {
				t.Errorf("level=%s: RedactText(%q) = %q, want output containing %q", tt.level, tt.input, got, tt.contains)
			}
			if tt.absent != "" && strings.Contains(got, tt.absent) {
				t.Errorf("level=%s: RedactText(%q) = %q, want output NOT containing %q", tt.level, tt.input, got, tt.absent)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Path rule tests (2 cases + level gating)
// ---------------------------------------------------------------------------

func TestRedactText_PathRules(t *testing.T) {
	tests := []struct {
		name     string
		level    RedactionLevel
		input    string
		contains string
	}{
		{
			name:     "unix_home_standard",
			level:    Standard,
			input:    "/Users/alice/projects/foo",
			contains: "/Users/<USER>/projects/foo",
		},
		{
			name:     "windows_home_standard",
			level:    Standard,
			input:    `C:\Users\alice\projects\foo`,
			contains: `C:\Users\<USER>\projects\foo`,
		},
		{
			name:     "unix_home_space_in_segment",
			level:    Standard,
			input:    "/home/SFU CLASSES/project/file.go",
			contains: "/home/<USER>/project/file.go",
		},
		{
			name:     "windows_home_space_in_segment",
			level:    Standard,
			input:    `C:\Users\John Doe\Documents\file.txt`,
			contains: `C:\Users\<USER>\Documents\file.txt`,
		},
		{
			name:     "unix_home_dual_path_on_line",
			level:    Standard,
			input:    "Loaded config from /home/alice and /home/bob/x",
			contains: "Loaded config from /home/<USER> and /home/<USER>/x",
		},
		// Slug path rules — unconditional (all levels).
		// The \W anchor requires a non-word character before the slug prefix.
		// In real data, this is typically "/" from file paths or whitespace.
		{
			name:     "claude_project_slug_minimal",
			level:    Minimal,
			input:    "/home/<USER>/.claude/projects/-home-alice-dev-project/uuid.jsonl",
			contains: "-home-<USER>-",
		},
		{
			name:     "claude_project_slug_users_variant",
			level:    Standard,
			input:    " -Users-johndoe-dev-project",
			contains: "-Users-<USER>-",
		},
		{
			name:     "peasant_host_slug_minimal",
			level:    Minimal,
			input:    " --home--alice--dev--project",
			contains: "--home--<USER>--",
		},
		{
			name:     "peasant_host_slug_users_variant",
			level:    Standard,
			input:    " --Users--johndoe--dev--project",
			contains: "--Users--<USER>--",
		},
		// False-positive protection: natural English text should NOT trigger slug rules.
		// The \W anchor prevents matching when a word character precedes the -home- segment.
		{
			name:     "false_positive_go_home_early",
			level:    Standard,
			input:    "go-home-early",
			contains: "go-home-early", // must be preserved unchanged
		},
		{
			name:     "false_positive_home_assistant",
			level:    Standard,
			input:    "home-assistant",
			contains: "home-assistant", // must be preserved unchanged
		},
		{
			name:     "false_positive_home_automation",
			level:    Standard,
			input:    "home-automation-system",
			contains: "home-automation-system", // must be preserved unchanged
		},
		{
			name:     "false_positive_go_home_early_feature",
			level:    Standard,
			input:    "the-go-home-early-feature",
			contains: "the-go-home-early-feature", // word char 'o' before -home- prevents match
		},
		{
			name:     "false_positive_some_home_page_widget",
			level:    Standard,
			input:    "some-home-page-widget",
			contains: "some-home-page-widget", // word char 'e' before -home- prevents match
		},
		{
			name:     "slug_after_space",
			level:    Standard,
			input:    " -home-alice-dev-project",
			contains: "-home-<USER>-", // space is \W, match fires
		},
		{
			name:     "slug_after_slash",
			level:    Standard,
			input:    "/-home-alice-dev-project",
			contains: "-home-<USER>-", // slash is \W, match fires
		},
		// Path rules fire at Minimal (unconditional).
		{
			name:     "unix_path_at_minimal",
			level:    Minimal,
			input:    "/home/alice/dev/project",
			contains: "/home/<USER>/dev/project",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := mustNewRedactor(t, tt.level, nil)
			got := r.RedactText(tt.input)
			if !strings.Contains(got, tt.contains) {
				t.Errorf("level=%s: RedactText(%q) = %q, want output containing %q", tt.level, tt.input, got, tt.contains)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Level gating tests
// ---------------------------------------------------------------------------

func TestRedactText_MinimalLevel(t *testing.T) {
	r := mustNewRedactor(t, Minimal, nil)
	input := "key: " + testAnthropicKey + " email: user@example.com path: /Users/alice/foo"
	got := r.RedactText(input)

	// Secrets redacted.
	if !strings.Contains(got, "<ANTHROPIC_KEY>") {
		t.Errorf("Minimal: expected ANTHROPIC_KEY redacted in %q", got)
	}
	// PII not redacted.
	if strings.Contains(got, "<EMAIL>") {
		t.Errorf("Minimal: expected EMAIL not redacted in %q", got)
	}
	// Paths ARE redacted at Minimal (CategoryPaths is unconditional — privacy-critical).
	if !strings.Contains(got, "<USER>") {
		t.Errorf("Minimal: expected path redacted in %q", got)
	}
}

func TestRedactText_StandardLevel(t *testing.T) {
	r := mustNewRedactor(t, Standard, nil)
	input := "key: " + testAnthropicKey + " email: user@example.com path: /Users/alice/foo"
	got := r.RedactText(input)

	// Secrets redacted.
	if !strings.Contains(got, "<ANTHROPIC_KEY>") {
		t.Errorf("Standard: expected ANTHROPIC_KEY redacted in %q", got)
	}
	// PII redacted.
	if !strings.Contains(got, "<EMAIL>") {
		t.Errorf("Standard: expected EMAIL redacted in %q", got)
	}
	// Paths redacted.
	if !strings.Contains(got, "<USER>") {
		t.Errorf("Standard: expected path redacted in %q", got)
	}
}

func TestRedactText_MaximumLevel(t *testing.T) {
	r := mustNewRedactor(t, Maximum, nil)
	input := "key: " + testAnthropicKey + " email: user@example.com path: /Users/alice/foo entropy: " + testHighEntropyToken
	got := r.RedactText(input)

	// Secrets redacted.
	if !strings.Contains(got, "<ANTHROPIC_KEY>") {
		t.Errorf("Maximum: expected ANTHROPIC_KEY redacted in %q", got)
	}
	// PII redacted.
	if !strings.Contains(got, "<EMAIL>") {
		t.Errorf("Maximum: expected EMAIL redacted in %q", got)
	}
	// Paths redacted.
	if !strings.Contains(got, "<USER>") {
		t.Errorf("Maximum: expected path redacted in %q", got)
	}
	// Entropy detection active at Maximum.
	if !strings.Contains(got, "<HIGH_ENTROPY>") {
		t.Errorf("Maximum: expected HIGH_ENTROPY redacted in %q", got)
	}
}

// ---------------------------------------------------------------------------
// RedactJSON tests
// ---------------------------------------------------------------------------

func TestRedactJSON_StringValue(t *testing.T) {
	r := mustNewRedactor(t, Minimal, nil)
	input := map[string]any{"key": testAnthropicKey}
	got := r.RedactJSON(input).(map[string]any)
	if val, ok := got["key"].(string); !ok || !strings.Contains(val, "<ANTHROPIC_KEY>") {
		t.Errorf("RedactJSON string: got %v, want key containing <ANTHROPIC_KEY>", got["key"])
	}
}

func TestRedactJSON_NestedObject(t *testing.T) {
	r := mustNewRedactor(t, Standard, nil)
	// Real-format OpenAI key: 20 chars + T3BlbkFJ marker + 20 chars.
	input := map[string]any{
		"a": map[string]any{"b": "sk-abcdefghij0123456789T3BlbkFJabcdefghij0123456789"},
		"c": "user@example.com",
	}
	got := r.RedactJSON(input).(map[string]any)

	nested := got["a"].(map[string]any)
	if val, ok := nested["b"].(string); !ok || !strings.Contains(val, "<OPENAI_KEY>") {
		t.Errorf("RedactJSON nested: got %v, want <OPENAI_KEY>", nested["b"])
	}
	if val, ok := got["c"].(string); !ok || !strings.Contains(val, "<EMAIL>") {
		t.Errorf("RedactJSON nested: got %v, want <EMAIL>", got["c"])
	}
}

func TestRedactJSON_ArrayValue(t *testing.T) {
	r := mustNewRedactor(t, Minimal, nil)
	input := []any{testAnthropicKey, "hello"}
	got := r.RedactJSON(input).([]any)

	if val, ok := got[0].(string); !ok || !strings.Contains(val, "<ANTHROPIC_KEY>") {
		t.Errorf("RedactJSON array[0]: got %v, want <ANTHROPIC_KEY>", got[0])
	}
	if val, ok := got[1].(string); !ok || val != "hello" {
		t.Errorf("RedactJSON array[1]: got %v, want 'hello'", got[1])
	}
}

func TestRedactJSON_IntegerPassthrough(t *testing.T) {
	r := mustNewRedactor(t, Minimal, nil)
	input := map[string]any{"count": 42}
	got := r.RedactJSON(input).(map[string]any)
	if val, ok := got["count"].(int); !ok || val != 42 {
		t.Errorf("RedactJSON integer: got %v (%T), want 42 (int)", got["count"], got["count"])
	}
}

func TestRedactJSON_NilPassthrough(t *testing.T) {
	r := mustNewRedactor(t, Minimal, nil)
	got := r.RedactJSON(nil)
	if got != nil {
		t.Errorf("RedactJSON nil: got %v, want nil", got)
	}
}

// ---------------------------------------------------------------------------
// RedactMetadata tests
// ---------------------------------------------------------------------------

func makeTestMetadata() *schema.UnifiedMetadata {
	m := schema.NewUnifiedMetadata()
	remote := "git@github.com:alice/private-repo"
	branch := "feature/alice-refactor"
	worktree := "/Users/alice/.git/worktrees/main"
	tracking := "origin/main"
	m.Source.FilePath = "/Users/alice/code/session.jsonl"
	m.Git.Remote = &remote
	m.Git.Branch = &branch
	m.Git.Worktree = &worktree
	m.Git.Tracking = &tracking
	m.Project.FilePath = "/Users/alice/code"
	m.Project.Name = "alice-project"
	m.Diagnostics.Warnings = []schema.DiagnosticEntry{
		{
			ErrorType:   "parse_error",
			Location:    "/Users/alice/main.go",
			Message:     "failed to parse file",
			Remediation: "check syntax",
		},
	}
	return &m
}

func TestRedactMetadata_DeepCopy(t *testing.T) {
	original := makeTestMetadata()
	origFilePath := original.Source.FilePath
	origRemote := *original.Git.Remote
	origWarningLoc := original.Diagnostics.Warnings[0].Location

	r := mustNewRedactor(t, Standard, nil)
	result := r.RedactMetadata(original)

	// The original must not be mutated.
	if original.Source.FilePath != origFilePath {
		t.Errorf("DeepCopy: original Source.FilePath mutated: got %q, want %q", original.Source.FilePath, origFilePath)
	}
	if *original.Git.Remote != origRemote {
		t.Errorf("DeepCopy: original Git.Remote mutated: got %q, want %q", *original.Git.Remote, origRemote)
	}
	if original.Diagnostics.Warnings[0].Location != origWarningLoc {
		t.Errorf("DeepCopy: original Diagnostics.Warnings[0].Location mutated")
	}

	// The result must be a different pointer.
	if result == original {
		t.Error("DeepCopy: RedactMetadata returned same pointer as original")
	}
}

func TestRedactMetadata_SourceFilePath(t *testing.T) {
	meta := makeTestMetadata()
	r := mustNewRedactor(t, Standard, nil)
	result := r.RedactMetadata(meta)

	if !strings.Contains(result.Source.FilePath, "<USER>") {
		t.Errorf("SourceFilePath: got %q, want path containing <USER>", result.Source.FilePath)
	}
}

func TestRedactMetadata_GitRemote(t *testing.T) {
	m := schema.NewUnifiedMetadata()
	// Use a remote URL with an embedded email — the PII email rule fires at Standard.
	remote := "https://user@example.com@github.com/repo"
	m.Git.Remote = &remote

	r := mustNewRedactor(t, Standard, nil)
	result := r.RedactMetadata(&m)

	if result.Git.Remote == nil {
		t.Fatal("GitRemote: result Git.Remote is nil")
	}
	// The email must be replaced with the <EMAIL> token.
	if !strings.Contains(*result.Git.Remote, "<EMAIL>") {
		t.Errorf("GitRemote: got %q, want remote containing <EMAIL>", *result.Git.Remote)
	}
	// Original must be unchanged.
	if *m.Git.Remote != remote {
		t.Errorf("GitRemote: original mutated to %q", *m.Git.Remote)
	}
}

func TestRedactMetadata_GitBranch(t *testing.T) {
	m := schema.NewUnifiedMetadata()
	branch := "feature/user@example.com-refactor"
	m.Git.Branch = &branch

	r := mustNewRedactor(t, Standard, nil)
	result := r.RedactMetadata(&m)

	if result.Git.Branch == nil {
		t.Fatal("GitBranch: result Git.Branch is nil")
	}
	if !strings.Contains(*result.Git.Branch, "<EMAIL>") {
		t.Errorf("GitBranch: got %q, want branch containing <EMAIL>", *result.Git.Branch)
	}
	// Original unchanged.
	if *m.Git.Branch != branch {
		t.Errorf("GitBranch: original mutated to %q", *m.Git.Branch)
	}
}

func TestRedactMetadata_Diagnostics(t *testing.T) {
	meta := makeTestMetadata()
	r := mustNewRedactor(t, Standard, nil)
	result := r.RedactMetadata(meta)

	if len(result.Diagnostics.Warnings) == 0 {
		t.Fatal("Diagnostics: result has no warnings")
	}
	loc := result.Diagnostics.Warnings[0].Location
	if !strings.Contains(loc, "<USER>") {
		t.Errorf("Diagnostics: Location = %q, want containing <USER>", loc)
	}
	// Original unchanged.
	if meta.Diagnostics.Warnings[0].Location != "/Users/alice/main.go" {
		t.Errorf("Diagnostics: original Location mutated to %q", meta.Diagnostics.Warnings[0].Location)
	}
}

// ---------------------------------------------------------------------------
// Meta-test: all rule IDs must have coverage
// ---------------------------------------------------------------------------

// TestRules_AllIDsHaveTestCoverage verifies that every rule ID in the Rules
// table has at least one matching test case name in the secrets, PII, or path
// test tables. This catches rules silently added to Rules without a test.
func TestRules_AllIDsHaveTestCoverage(t *testing.T) {
	// Collect all rule IDs from the live rule table.
	ruleIDs := make(map[string]bool, len(Rules))
	for _, r := range Rules {
		ruleIDs[r.ID] = false
	}

	// Mark covered: secrets test names match rule IDs exactly.
	// Original 17 rules (covered by TestRedactText_SecretsRules above + YAML fixtures).
	secretsCases := []string{
		"anthropic_key", "openai_key", "github_pat", "aws_access_key",
		"aws_secret_key", "stripe_key", "twilio_key", "twilio_auth_token",
		"sendgrid_key", "slack_token", "slack_webhook_url",
		"jwt_token", "private_key_block",
		"generic_api_key", "bearer_token", "basic_auth", "basic_auth_uri", "access_code",
		// 17 new detect-secrets expansion rules (covered by TestRule_* in rules_test.go).
		"artifactory_api_token", "artifactory_password", "azure_storage_key",
		"discord_bot_token", "gitlab_pat", "gitlab_runner_registration",
		"gitlab_cicd", "gitlab_incoming_mail", "gitlab_trigger",
		"gitlab_agent", "gitlab_oauth_secret", "mailchimp_api_key",
		"npm_auth_token", "pypi_api_token", "pypi_test_token",
		"square_oauth_secret", "telegram_bot_token",
	}
	for _, id := range secretsCases {
		ruleIDs[id] = true
	}

	// Mark covered: PII test names match rule IDs exactly.
	piiCases := []string{"email", "phone_us", "ssn", "credit_card", "ip_address"}
	for _, id := range piiCases {
		ruleIDs[id] = true
	}

	// Mark covered: path test names match rule IDs exactly.
	pathCases := []string{"unix_home_path", "unix_home_path_spaced", "windows_home_path", "windows_home_path_spaced", "claude_project_slug", "peasant_host_slug"}
	for _, id := range pathCases {
		ruleIDs[id] = true
	}

	// Mark covered: the 10 CategoryProject rules (covered in project_rules_test.go).
	for _, rule := range projectRules {
		ruleIDs[rule.ID] = true
	}

	for id, covered := range ruleIDs {
		if !covered {
			t.Errorf("rule %q has no test coverage — add a test case for it", id)
		}
	}
}

// ---------------------------------------------------------------------------
// Edge case tests
// ---------------------------------------------------------------------------

func TestRedactText_EmptyString(t *testing.T) {
	r := mustNewRedactor(t, Maximum, nil)
	if got := r.RedactText(""); got != "" {
		t.Errorf("RedactText(\"\") = %q, want \"\"", got)
	}
}

func TestRedactJSON_EmptyString(t *testing.T) {
	r := mustNewRedactor(t, Minimal, nil)
	got := r.RedactJSON("")
	s, ok := got.(string)
	if !ok || s != "" {
		t.Errorf("RedactJSON(\"\") = %v (%T), want \"\" (string)", got, got)
	}
}

func TestRedactMetadata_NilInput(t *testing.T) {
	r := mustNewRedactor(t, Standard, nil)
	result := r.RedactMetadata(nil)
	if result != nil {
		t.Errorf("RedactMetadata(nil) = %v, want nil", result)
	}
}

func TestRedactMetadata_NilGitFields(t *testing.T) {
	m := schema.NewUnifiedMetadata()
	// All Git pointer fields are nil by default from NewUnifiedMetadata.
	r := mustNewRedactor(t, Standard, nil)
	result := r.RedactMetadata(&m)
	if result == nil {
		t.Fatal("NilGitFields: RedactMetadata returned nil for non-nil input")
	}
	if result.Git.Remote != nil {
		t.Errorf("NilGitFields: Remote should be nil, got %v", result.Git.Remote)
	}
	if result.Git.Branch != nil {
		t.Errorf("NilGitFields: Branch should be nil, got %v", result.Git.Branch)
	}
	if result.Git.Worktree != nil {
		t.Errorf("NilGitFields: Worktree should be nil, got %v", result.Git.Worktree)
	}
	if result.Git.Tracking != nil {
		t.Errorf("NilGitFields: Tracking should be nil, got %v", result.Git.Tracking)
	}
}

// TestMaskCodeBlocks verifies maskCodeBlocks removes fenced code blocks.
// The function is package-internal but tested here because it is a
// meaningful behaviour with known edge cases.
func TestMaskCodeBlocks(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "standard_fences",
			input: "before\n```\nsome secret code\n```\nafter",
			want:  "before<CODE_BLOCK>after",
		},
		{
			name:  "indented_fences",
			input: "before\n    ```\n    indented code\n    ```\nafter",
			want:  "before<CODE_BLOCK>after",
		},
		{
			name:  "no_fences",
			input: "just normal text with no code blocks",
			want:  "just normal text with no code blocks",
		},
		{
			name:  "fences_with_lang",
			input: "text\n```go\npackage main\n```\nmore",
			want:  "text<CODE_BLOCK>more",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := maskCodeBlocks(tt.input)
			if got != tt.want {
				t.Errorf("maskCodeBlocks(%q) =\n  %q\nwant\n  %q", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// v3: User-defined pattern tests
// ---------------------------------------------------------------------------

// TestNewRedactor_UserPattern_Matches verifies a custom secrets pattern compiles
// and its replacement is applied when redacting text containing a match.
func TestNewRedactor_UserPattern_Matches(t *testing.T) {
	patterns := []UserPattern{
		{
			ID:          "internal_api_key",
			Category:    CategorySecrets,
			Pattern:     `myco-[A-Za-z0-9]{32}`,
			Replacement: "[INTERNAL-API-KEY]",
		},
	}
	r := mustNewRedactor(t, Minimal, patterns)
	input := "token=myco-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
	got := r.RedactText(input)
	if !strings.Contains(got, "[INTERNAL-API-KEY]") {
		t.Errorf("UserPattern: got %q, want output containing [INTERNAL-API-KEY]", got)
	}
	if strings.Contains(got, "myco-") {
		t.Errorf("UserPattern: raw token leaked in output: %q", got)
	}
}

// TestNewRedactor_UserPattern_InvalidRegex verifies that an invalid regex pattern
// causes NewRedactor to return an error (fail-closed: no partial redactor returned).
func TestNewRedactor_UserPattern_InvalidRegex(t *testing.T) {
	patterns := []UserPattern{
		{
			ID:          "bad_pattern",
			Category:    CategorySecrets,
			Pattern:     `[invalid`,
			Replacement: "<BAD>",
		},
	}
	_, err := NewRedactor(Minimal, patterns, XDGPaths{})
	if err == nil {
		t.Error("UserPattern invalid regex: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "bad_pattern") {
		t.Errorf("UserPattern invalid regex: error should mention pattern ID, got: %v", err)
	}
}

// TestNewRedactor_UserPattern_SecretsAtMinimal verifies that a custom secrets
// pattern is applied even at Minimal level (secrets are always active).
func TestNewRedactor_UserPattern_SecretsAtMinimal(t *testing.T) {
	patterns := []UserPattern{
		{
			ID:          "internal_codename",
			Category:    CategorySecrets,
			Pattern:     `Project-(Alpha|Beta|Gamma)-\d+`,
			Replacement: "[CODENAME]",
		},
	}
	r := mustNewRedactor(t, Minimal, patterns)
	got := r.RedactText("Working on Project-Alpha-42 today")
	if !strings.Contains(got, "[CODENAME]") {
		t.Errorf("UserPattern secrets at Minimal: got %q, want [CODENAME]", got)
	}
}

// TestNewRedactor_UserPattern_PIIGatedAtMinimal verifies that a custom PII
// pattern is NOT applied at Minimal level (PII is gated to Standard+).
func TestNewRedactor_UserPattern_PIIGatedAtMinimal(t *testing.T) {
	patterns := []UserPattern{
		{
			ID:          "internal_name",
			Category:    CategoryPII,
			Pattern:     `EMPLOYEE-\d{6}`,
			Replacement: "[EMPLOYEE-ID]",
		},
	}
	r := mustNewRedactor(t, Minimal, patterns)
	got := r.RedactText("Contact EMPLOYEE-123456 for details")
	if strings.Contains(got, "[EMPLOYEE-ID]") {
		t.Errorf("UserPattern PII at Minimal: got %q, want PII NOT applied", got)
	}
	if !strings.Contains(got, "EMPLOYEE-123456") {
		t.Errorf("UserPattern PII at Minimal: original text should be preserved: %q", got)
	}
}

// TestNewRedactor_UserPattern_PIIAtStandard verifies that a custom PII pattern
// IS applied at Standard level.
func TestNewRedactor_UserPattern_PIIAtStandard(t *testing.T) {
	patterns := []UserPattern{
		{
			ID:          "internal_name",
			Category:    CategoryPII,
			Pattern:     `EMPLOYEE-\d{6}`,
			Replacement: "[EMPLOYEE-ID]",
		},
	}
	r := mustNewRedactor(t, Standard, patterns)
	got := r.RedactText("Contact EMPLOYEE-123456 for details")
	if !strings.Contains(got, "[EMPLOYEE-ID]") {
		t.Errorf("UserPattern PII at Standard: got %q, want [EMPLOYEE-ID]", got)
	}
}

// TestNewRedactor_UserPattern_MultiplePatterns verifies that two custom patterns
// for the same category are both applied independently.
func TestNewRedactor_UserPattern_MultiplePatterns(t *testing.T) {
	patterns := []UserPattern{
		{
			ID:          "token_a",
			Category:    CategorySecrets,
			Pattern:     `tok-a-[A-Z]{8}`,
			Replacement: "[TOKEN-A]",
		},
		{
			ID:          "token_b",
			Category:    CategorySecrets,
			Pattern:     `tok-b-[A-Z]{8}`,
			Replacement: "[TOKEN-B]",
		},
	}
	r := mustNewRedactor(t, Minimal, patterns)
	got := r.RedactText("first=tok-a-ABCDEFGH second=tok-b-IJKLMNOP")
	if !strings.Contains(got, "[TOKEN-A]") {
		t.Errorf("MultiplePatterns: [TOKEN-A] not found in %q", got)
	}
	if !strings.Contains(got, "[TOKEN-B]") {
		t.Errorf("MultiplePatterns: [TOKEN-B] not found in %q", got)
	}
}

// TestNewRedactor_UserPattern_EmptySlice verifies that an empty user patterns
// slice produces behaviour identical to nil (no regression against v2).
func TestNewRedactor_UserPattern_EmptySlice(t *testing.T) {
	r1 := mustNewRedactor(t, Standard, nil)
	r2 := mustNewRedactor(t, Standard, []UserPattern{})
	input := testAnthropicKey + " user@example.com"
	got1 := r1.RedactText(input)
	got2 := r2.RedactText(input)
	if got1 != got2 {
		t.Errorf("EmptySlice: nil vs empty differ:\n  nil=%q\n  empty=%q", got1, got2)
	}
}

// TestNewRedactor_UserPattern_ReportTracking verifies that user-pattern hits are
// tracked in RedactionReport (Counts and TotalRedactions).
func TestNewRedactor_UserPattern_ReportTracking(t *testing.T) {
	patterns := []UserPattern{
		{
			ID:          "internal_api_key",
			Category:    CategorySecrets,
			Pattern:     `myco-[A-Za-z0-9]{32}`,
			Replacement: "[INTERNAL-API-KEY]",
		},
	}
	r := mustNewRedactor(t, Minimal, patterns)
	_ = r.RedactText("a=myco-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef b=myco-ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZa")

	report := r.Report()
	if report.Counts["internal_api_key"] != 2 {
		t.Errorf("ReportTracking: Counts[internal_api_key] = %d, want 2", report.Counts["internal_api_key"])
	}
	if report.TotalRedactions < 2 {
		t.Errorf("ReportTracking: TotalRedactions = %d, want >= 2", report.TotalRedactions)
	}
}

// TestNewRedactor_UserPattern_EmptyID verifies that a pattern with empty ID
// causes NewRedactor to return an error.
func TestNewRedactor_UserPattern_EmptyID(t *testing.T) {
	patterns := []UserPattern{
		{
			ID:          "",
			Category:    CategorySecrets,
			Pattern:     `myco-[A-Za-z0-9]{32}`,
			Replacement: "[INTERNAL-API-KEY]",
		},
	}
	_, err := NewRedactor(Minimal, patterns, XDGPaths{})
	if err == nil {
		t.Error("UserPattern empty ID: expected error, got nil")
	}
}

// TestNewRedactor_UserPattern_UnknownCategory verifies that a pattern with an
// unknown category causes NewRedactor to return an error.
func TestNewRedactor_UserPattern_UnknownCategory(t *testing.T) {
	patterns := []UserPattern{
		{
			ID:          "bad_cat",
			Category:    Category("unknown"),
			Pattern:     `foo`,
			Replacement: "[FOO]",
		},
	}
	_, err := NewRedactor(Minimal, patterns, XDGPaths{})
	if err == nil {
		t.Error("UserPattern unknown category: expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// RedactMetadata 3-phase slug redaction tests
// ---------------------------------------------------------------------------

// TestRedactMetadata_ContextAwareSlug verifies Phase 2 context-aware slug redaction:
// when CWD is set, the slug derived from the CWD path is redacted via buildPrivateReplacer.
func TestRedactMetadata_ContextAwareSlug(t *testing.T) {
	meta := makeTestMetadata()
	meta.CWD = "/home/testuser/dev/project"
	meta.Source.FilePath = "/home/testuser/.claude/projects/-home-testuser-dev-project/uuid.jsonl"
	meta.HostSlug = "laptop--home--testuser--dev--project"

	r := mustNewRedactor(t, Minimal, nil)
	result := r.RedactMetadata(meta)

	// AC2/AC8: The slug "-home-testuser-dev-" must be replaced with context-aware placeholders.
	if strings.Contains(result.Source.FilePath, "testuser") {
		t.Errorf("ContextAwareSlug: username leaked in Source.FilePath: %q", result.Source.FilePath)
	}
	if !strings.Contains(result.Source.FilePath, "<USER>") {
		t.Errorf("ContextAwareSlug: expected <USER> in Source.FilePath: %q", result.Source.FilePath)
	}
}

// TestRedactMetadata_HostSlugRedaction verifies that HostSlug containing a username
// slug is redacted (AC11).
func TestRedactMetadata_HostSlugRedaction(t *testing.T) {
	meta := makeTestMetadata()
	meta.CWD = "/home/testuser/dev/project"
	meta.Source.FilePath = "/home/testuser/.claude/projects/-home-testuser-dev-project/uuid.jsonl"
	meta.HostSlug = "laptop--home--testuser--dev--project"

	r := mustNewRedactor(t, Minimal, nil)
	result := r.RedactMetadata(meta)

	// AC11: HostSlug must not leak the username.
	if strings.Contains(string(result.HostSlug), "testuser") {
		t.Errorf("HostSlugRedaction: username leaked in HostSlug: %q", result.HostSlug)
	}
	if !strings.Contains(string(result.HostSlug), "<USER>") {
		t.Errorf("HostSlugRedaction: expected <USER> in HostSlug: %q", result.HostSlug)
	}
}

// TestRedactMetadata_CWDFieldRedaction verifies that the CWD field itself is redacted
// (the username in the path is replaced with <USER>).
func TestRedactMetadata_CWDFieldRedaction(t *testing.T) {
	meta := makeTestMetadata()
	meta.CWD = "/home/testuser/dev/project"
	meta.Source.FilePath = "/home/testuser/.claude/projects/-home-testuser-dev-project/uuid.jsonl"

	r := mustNewRedactor(t, Minimal, nil)
	result := r.RedactMetadata(meta)

	if strings.Contains(result.CWD, "testuser") {
		t.Errorf("CWDFieldRedaction: username leaked in CWD: %q", result.CWD)
	}
	if !strings.Contains(result.CWD, "<USER>") {
		t.Errorf("CWDFieldRedaction: expected <USER> in CWD: %q", result.CWD)
	}
}

// TestRedactMetadata_FallbackWithoutCWD verifies that when CWD is empty,
// the regex fallback (Phase 3) still redacts the username from slug paths (AC3).
func TestRedactMetadata_FallbackWithoutCWD(t *testing.T) {
	meta := makeTestMetadata()
	meta.CWD = "" // no CWD available
	meta.Source.FilePath = "/home/testuser/.claude/projects/-home-testuser-dev-project/uuid.jsonl"
	meta.HostSlug = "laptop--home--testuser--dev--project"

	r := mustNewRedactor(t, Minimal, nil)
	result := r.RedactMetadata(meta)

	// AC3: Even without CWD, the username-only fallback replacer + regex rules should redact.
	if strings.Contains(result.Source.FilePath, "testuser") {
		t.Errorf("FallbackWithoutCWD: username leaked in Source.FilePath: %q", result.Source.FilePath)
	}
	if !strings.Contains(result.Source.FilePath, "<USER>") {
		t.Errorf("FallbackWithoutCWD: expected <USER> in Source.FilePath: %q", result.Source.FilePath)
	}
	// HostSlug should also be redacted via the fallback path.
	if strings.Contains(string(result.HostSlug), "testuser") {
		t.Errorf("FallbackWithoutCWD: username leaked in HostSlug: %q", result.HostSlug)
	}
}

// ---------------------------------------------------------------------------
// Concurrency test
// ---------------------------------------------------------------------------

func TestRedactText_Concurrency(t *testing.T) {
	r := mustNewRedactor(t, Minimal, nil)
	const goroutines = 10
	input := testAnthropicKey

	errs := make(chan string, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			out := r.RedactText(input)
			if !strings.Contains(out, "<ANTHROPIC_KEY>") {
				errs <- fmt.Sprintf("output %q does not contain <ANTHROPIC_KEY>", out)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Errorf("Concurrency: %s", e)
	}

	report := r.Report()
	if report.TotalRedactions != goroutines {
		t.Errorf("Concurrency: TotalRedactions = %d, want %d", report.TotalRedactions, goroutines)
	}
	if report.Counts["anthropic_key"] != goroutines {
		t.Errorf("Concurrency: Counts[anthropic_key] = %d, want %d", report.Counts["anthropic_key"], goroutines)
	}
}

// ---------------------------------------------------------------------------
// Parity tests: RedactText(input) == Redact(input, Detect(input))
// ---------------------------------------------------------------------------

// TestRedactText_ParityWithDetectRedact_FilterCases verifies that RedactText produces
// identical output to r.Redact(input, r.Detect(input)) for inputs that exercise the
// FilterFn code path (aws_secret_key with and without context) and back-reference rules
// (unix_home_path, claude_project_slug, peasant_host_slug).
//
// This test verifies that RedactText's internal Detect-then-Redact path preserves
// bit-for-bit parity with the explicit Detect-then-Redact call sequence.
func TestRedactText_ParityWithDetectRedact_FilterCases(t *testing.T) {
	cases := []struct {
		name  string
		level RedactionLevel
		input string
	}{
		{
			// File path false positive: aws_secret_key regex fires but FilterFn rejects it
			// (no AWS context). RedactText must leave the string unchanged.
			name:  "file_path_false_positive",
			level: Minimal,
			input: "nttea/codebases/dayvidpham/bestiary/main.",
		},
		{
			// Bare base64, no context: regex fires but FilterFn rejects.
			name:  "bare_base64_no_context",
			level: Minimal,
			input: "5Y9syZ8W5sLJHHGM7EqzeVBf37Sq/f4k1p0YAQAA",
		},
		{
			// Real AWS key with context: FilterFn accepts.
			name:  "real_aws_key_with_context",
			level: Minimal,
			input: `aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`,
		},
		{
			// Back-reference rule: unix_home_path uses "${1}<USER>" replacement.
			name:  "back_reference_unix_home_path",
			level: Minimal,
			input: "/home/alice/dev/project",
		},
		{
			// Back-reference rule: claude_project_slug uses "${1}${2}<USER>${4}".
			name:  "back_reference_claude_project_slug",
			level: Minimal,
			input: "/home/<USER>/.claude/projects/-home-alice-dev-project/uuid.jsonl",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Two independent redactors to avoid shared lastMatches state.
			r1 := mustNewRedactor(t, tc.level, nil)
			r2 := mustNewRedactor(t, tc.level, nil)

			redactTextOut := r1.RedactText(tc.input)
			detectRedactOut := r2.Redact(tc.input, r2.Detect(tc.input))

			if redactTextOut != detectRedactOut {
				t.Errorf("Parity violation for %q (level=%s):\n  RedactText:    %q\n  Detect+Redact: %q",
					tc.input, tc.level, redactTextOut, detectRedactOut)
			}
		})
	}
}

// sumCounts returns the sum of all values in a map[string]int.
func sumCounts(counts map[string]int) int {
	total := 0
	for _, v := range counts {
		total += v
	}
	return total
}

// TestReport_CountsParity verifies that after RedactText on a mixed input
// (real AWS key + file path false positive + email):
//   - aws_secret_key count > 0 (true positive with AWS context)
//   - email count > 0 (PII at Standard)
//   - TotalRedactions == sum of all Counts values
//
// This exercises the count-recording path used by RedactText.
func TestReport_CountsParity(t *testing.T) {
	r := mustNewRedactor(t, Standard, nil)

	// Mixed input: real AWS key with context, a file path that is a false positive
	// for aws_secret_key (no AWS context → filtered out), and an email address.
	input := `aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" contact user@example.com`
	_ = r.RedactText(input)

	report := r.Report()

	if report.Counts["aws_secret_key"] == 0 {
		t.Errorf("CountsParity: aws_secret_key count = 0, want > 0 (real key with context should be redacted)")
	}
	if report.Counts["email"] == 0 {
		t.Errorf("CountsParity: email count = 0, want > 0 (email should be redacted at Standard level)")
	}

	// TotalRedactions must equal the sum of all per-rule counts.
	sum := sumCounts(report.Counts)
	if report.TotalRedactions != sum {
		t.Errorf("CountsParity: TotalRedactions = %d, sum(Counts) = %d — they must be equal",
			report.TotalRedactions, sum)
	}
}

// TestReport_MatchesPopulatedAfterRedactText verifies that Report().Matches
// contains the filtered matches from the internal Detect() call after RedactText.
// Earlier versions populated Matches only through explicit Detect() calls.
func TestReport_MatchesPopulatedAfterRedactText(t *testing.T) {
	r := mustNewRedactor(t, Standard, nil)

	// Input with a real AWS key (has keyword context) and an email.
	input := `aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" contact user@example.com`
	_ = r.RedactText(input)

	report := r.Report()

	// Report().Matches must be non-nil after RedactText on input with matches.
	if report.Matches == nil {
		t.Fatal("Report().Matches is nil after RedactText — expected filtered matches")
	}

	// Must contain at least 2 matches: aws_secret_key + email.
	if len(report.Matches) < 2 {
		t.Errorf("Report().Matches has %d entries, want >= 2 (aws_secret_key + email)",
			len(report.Matches))
	}

	// Verify aws_secret_key match is present (true positive with context).
	foundAWS := false
	foundEmail := false
	for _, m := range report.Matches {
		if m.Rule == "aws_secret_key" {
			foundAWS = true
		}
		if m.Rule == "email" {
			foundEmail = true
		}
	}
	if !foundAWS {
		t.Error("Report().Matches missing aws_secret_key match (should be kept — has keyword context)")
	}
	if !foundEmail {
		t.Error("Report().Matches missing email match")
	}

	// A second RedactText with no matches should clear Matches (last-call-only).
	_ = r.RedactText("hello world no secrets")
	report2 := r.Report()
	if report2.Matches != nil {
		t.Errorf("Report().Matches should be nil after RedactText with no matches, got %d entries",
			len(report2.Matches))
	}
}
