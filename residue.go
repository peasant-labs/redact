// Package redact provides post-redaction residue detection.
// ResidueDetector scans already-redacted text for patterns that may have
// slipped through the primary redaction rules. It is advisory only —
// it never modifies content, only produces warnings.
package redact

import (
	"regexp"
	"unicode/utf8"
)

// PreviewMaxLength is the maximum number of bytes in a ResidueWarning.Preview.
const PreviewMaxLength = 40

// ResidueDetector scans already-redacted text for potential missed patterns.
// Advisory only — never modifies content.
type ResidueDetector interface {
	// Scan examines redactedText for patterns that may indicate missed
	// sensitive data. Returns zero or more warnings; all matches are
	// returned. The input string is never modified.
	// Callers that need deduplicated results should filter by RuleID/Location.
	Scan(redactedText string) []ResidueWarning
}

// ResidueWarning describes a potential missed sensitive pattern found
// during post-redaction residue scanning.
type ResidueWarning struct {
	RuleID   string // identifies which residue rule triggered
	Location int    // byte offset in redactedText where the match starts
	Preview  string // up to PreviewMaxLength bytes of surrounding context (itself redacted for safety)
}

// ResidueRule is a compiled pattern for advisory residue scanning.
// Residue rules are intentionally broader/noisier than the primary Rules
// table — a higher false-positive rate is acceptable because warnings
// are advisory and never block the pipeline.
type ResidueRule struct {
	ID      string
	Pattern *regexp.Regexp
}

// ResidueRules is the complete compiled residue rule table.
// All patterns are compiled at package init via regexp.MustCompile.
//
// These are intentionally broader versions of the main 20 Rules
// (13 secrets + 5 PII + 2 paths), plus 3 additional patterns for
// base64, hex, and bearer tokens. They are designed to catch near-misses —
// patterns that are close to but not exactly matching the primary rules.
//
// Trade-off note: residue_aws_secret_key was removed. The primary aws_secret_key
// rule matches exactly 40-char base64 (30-char keys with padding). A residue rule
// at [A-Za-z0-9+/]{30,} would be broader than residue_base64_long ([A-Za-z0-9+/]{40,}),
// covering 30–39 char strings that base64_long misses. However, this range produces
// significant noise on random base64-encoded data. We accept the 30–39 char detection
// gap in exchange for reduced false-positive rate. Document if a future high-confidence
// rule for that range becomes available.
var ResidueRules = []ResidueRule{
	// --- Simplified secrets patterns (broader than main rules) ---
	{ID: "residue_anthropic_key", Pattern: regexp.MustCompile(`sk-ant-[a-zA-Z0-9_-]{10,}`)},
	{ID: "residue_openai_key", Pattern: regexp.MustCompile(`sk-(?:live|test|proj)-[a-zA-Z0-9_-]{10,}`)},
	{ID: "residue_github_pat", Pattern: regexp.MustCompile(`gh[pours]_[a-zA-Z0-9]{10,}`)},
	{ID: "residue_aws_access_key", Pattern: regexp.MustCompile(`(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,}`)},
	{ID: "residue_stripe_key", Pattern: regexp.MustCompile(`sk_(?:live|test)_[a-zA-Z0-9]{10,}`)},
	{ID: "residue_twilio_key", Pattern: regexp.MustCompile(`AC[a-f0-9]{20,}`)},
	{ID: "residue_sendgrid_key", Pattern: regexp.MustCompile(`SG\.[a-zA-Z0-9_-]{10,}`)},
	{ID: "residue_slack_token", Pattern: regexp.MustCompile(`xox[baprs]-[a-zA-Z0-9-]{8,}`)},
	{ID: "residue_jwt_token", Pattern: regexp.MustCompile(`eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]+`)},
	{ID: "residue_private_key", Pattern: regexp.MustCompile(`-----BEGIN\s+\S*\s*PRIVATE\s+KEY`)},
	{ID: "residue_generic_api_key", Pattern: regexp.MustCompile(`(?i)(?:api[_-]?key|apikey)\s*[=:]\s*\S{10,}`)},
	{ID: "residue_bearer_token", Pattern: regexp.MustCompile(`(?i)Bearer\s+\S{8,}`)},
	{ID: "residue_basic_auth", Pattern: regexp.MustCompile(`(?i)(?:Authorization:\s*Basic|Basic\s+auth)\s+\S{8,}`)},

	// --- Simplified PII patterns (broader) ---
	{ID: "residue_email", Pattern: regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)},
	{ID: "residue_phone", Pattern: regexp.MustCompile(`(?:\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}`)},
	{ID: "residue_ssn", Pattern: regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)},
	{ID: "residue_credit_card", Pattern: regexp.MustCompile(`\b(?:\d{4}[-\s]?){3}\d{4}\b`)},
	{ID: "residue_ip_address", Pattern: regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)},

	// --- Simplified path patterns (broader) ---
	{ID: "residue_unix_path", Pattern: regexp.MustCompile(`/(?:Users|home)/[a-zA-Z0-9._-]+`)},
	{ID: "residue_windows_path", Pattern: regexp.MustCompile(`(?i)C:\\Users\\[a-zA-Z0-9._-]+`)},

	// --- Additional patterns (not in main rules) ---
	{ID: "residue_base64_long", Pattern: regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`)},
	{ID: "residue_hex_long", Pattern: regexp.MustCompile(`\b[0-9a-f]{32,}\b`)},
	{ID: "residue_broad_api_key", Pattern: regexp.MustCompile(`(?:sk|xox[baprs])-[A-Za-z0-9\-]{10,}`)},

	// --- detect-secrets expansion residue (17 broader advisory patterns) ---
	// These are intentionally broader/noisier than the 17 new primary rules.
	// They catch near-misses: partial prefix matches, slightly-wrong length, etc.
	{ID: "residue_artifactory_api_token", Pattern: regexp.MustCompile(`AKC[a-zA-Z0-9]{8,}`)},
	{ID: "residue_artifactory_password", Pattern: regexp.MustCompile(`AP[0-9A-F][a-zA-Z0-9]{6,}`)},
	{ID: "residue_azure_storage_key", Pattern: regexp.MustCompile(`AccountKey=[a-zA-Z0-9+/=]{40,}`)},
	{ID: "residue_discord_bot_token", Pattern: regexp.MustCompile(`[MNO][a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{20,}`)},
	{ID: "residue_gitlab_pat", Pattern: regexp.MustCompile(`(?:glpat|gldt|glft|glsoat|glrt)-[A-Za-z0-9_-]{15,}`)},
	{ID: "residue_gitlab_runner_registration", Pattern: regexp.MustCompile(`GR1348941[A-Za-z0-9_-]{15,}`)},
	{ID: "residue_gitlab_cicd", Pattern: regexp.MustCompile(`glcbt-[A-Za-z0-9_-]{15,}`)},
	{ID: "residue_gitlab_incoming_mail", Pattern: regexp.MustCompile(`glimt-[A-Za-z0-9_-]{20,}`)},
	{ID: "residue_gitlab_trigger", Pattern: regexp.MustCompile(`glptt-[A-Za-z0-9_-]{30,}`)},
	{ID: "residue_gitlab_agent", Pattern: regexp.MustCompile(`glagent-[A-Za-z0-9_-]{40,}`)},
	{ID: "residue_gitlab_oauth_secret", Pattern: regexp.MustCompile(`gloas-[A-Za-z0-9_-]{50,}`)},
	{ID: "residue_mailchimp_api_key", Pattern: regexp.MustCompile(`[0-9a-z]{28,}-us[0-9]{1,2}`)},
	{ID: "residue_npm_auth_token", Pattern: regexp.MustCompile(`/:_authToken=\s*\S{10,}`)},
	{ID: "residue_pypi_token", Pattern: regexp.MustCompile(`pypi-AgEI[A-Za-z0-9_-]{40,}`)},
	{ID: "residue_pypi_test_token", Pattern: regexp.MustCompile(`pypi-AgEN[A-Za-z0-9_-]{40,}`)},
	{ID: "residue_square_oauth_secret", Pattern: regexp.MustCompile(`sq0csp-[0-9A-Za-z_-]{30,}`)},
	{ID: "residue_telegram_bot_token", Pattern: regexp.MustCompile(`\d{7,}:[0-9A-Za-z_-]{30,}`)},

	// --- Project identity residue rules (10 broader advisory patterns) ---
	// These are intentionally broader/noisier than the 10 primary project rules.
	// They catch near-misses: partial URL matches, any github.com URL, loose CI var patterns.
	{
		// Matches any github.com, gitlab.com, or bitbucket.org HTTPS URL — broader than the
		// primary rule which requires org/repo. Catches bare domain mentions that may still
		// be project-identifying in context.
		ID:      "residue_git_remote_https",
		Pattern: regexp.MustCompile(`https?://(?:github\.com|gitlab\.com|bitbucket\.org)/\S*`),
	},
	{
		// Matches any git@ SSH URL for the three major hosters.
		ID:      "residue_git_remote_ssh",
		Pattern: regexp.MustCompile(`git@(?:github\.com|gitlab\.com|bitbucket\.org):\S*`),
	},
	{
		// Matches any github.com path (quoted or unquoted) — broader than the primary
		// rule which requires the full import path format.
		ID:      "residue_go_import_path",
		Pattern: regexp.MustCompile(`github\.com/[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+`),
	},
	{
		// Matches the "module github.com/..." declaration anywhere in text.
		ID:      "residue_go_module_path",
		Pattern: regexp.MustCompile(`module\s+github\.com/\S+`),
	},
	{
		// Matches any package.json URL-like field referencing github.com.
		ID:      "residue_npm_repo_url",
		Pattern: regexp.MustCompile(`"(?:repository|homepage|bugs)":\s*"https?://github\.com`),
	},
	{
		// Matches any FROM or image: line regardless of whether it has a slash.
		// This is broader than the primary rule to catch bare official image overrides.
		ID:      "residue_docker_image_ref",
		Pattern: regexp.MustCompile(`(?:FROM|image:)\s+[a-zA-Z0-9_./:-]+`),
	},
	{
		// Matches any ghcr.io reference regardless of path depth.
		ID:      "residue_ghcr_image_ref",
		Pattern: regexp.MustCompile(`ghcr\.io/\S+`),
	},
	{
		// Matches any "* something" or "origin/something" pattern in git output.
		ID:      "residue_git_branch_output",
		Pattern: regexp.MustCompile(`(?:\*\s+|origin/)[a-zA-Z0-9_./-]+`),
	},
	{
		// Matches any CI_PROJECT_* variable (any suffix), broader than the primary rule
		// which limits to NAME/PATH/URL.
		ID:      "residue_gitlab_ci_project",
		Pattern: regexp.MustCompile(`CI_PROJECT_[A-Z_]+\s*[=:]\s*\S*`),
	},
	{
		// Matches the GITHUB_REPOSITORY variable name even if value is empty or on next line.
		ID:      "residue_github_actions_repo",
		Pattern: regexp.MustCompile(`GITHUB_REPOSITORY\s*[=:]?\s*\S*`),
	},
}

// DefaultResidueDetector is the production implementation of ResidueDetector.
type DefaultResidueDetector struct{}

// Compile-time guard: DefaultResidueDetector must implement ResidueDetector.
var _ ResidueDetector = (*DefaultResidueDetector)(nil)

// NewResidueDetector returns a ResidueDetector that scans for missed patterns.
func NewResidueDetector() ResidueDetector {
	return &DefaultResidueDetector{}
}

// Scan examines redactedText for patterns that may indicate missed sensitive data.
// Returns zero or more warnings; all matches are returned — callers that need
// deduplicated results should filter by RuleID/Location.
// The input string is never modified.
func (d *DefaultResidueDetector) Scan(redactedText string) []ResidueWarning {
	if len(redactedText) == 0 {
		return nil
	}

	var warnings []ResidueWarning
	for _, rule := range ResidueRules {
		matches := rule.Pattern.FindAllStringIndex(redactedText, -1)
		for _, loc := range matches {
			start := loc[0]
			preview := safePreview(redactedText, start, PreviewMaxLength)
			warnings = append(warnings, ResidueWarning{
				RuleID:   rule.ID,
				Location: start,
				Preview:  preview,
			})
		}
	}
	return warnings
}

// safePreview extracts up to maxLen bytes of context around the byte offset,
// applies a minimal redaction pass so no raw secrets appear in the preview,
// and returns the result. The preview is truncated to avoid exposing full
// matched values.
//
// offset is a byte offset (as returned by regexp.FindAllStringIndex).
// The preview is centered on the offset using byte arithmetic. After computing
// byte-aligned window boundaries, both wideStart and previewEnd are advanced
// to the nearest valid UTF-8 rune boundary to prevent slicing mid-rune.
//
// Design note: redaction is applied to a wider window (4× maxLen) before
// trimming. This ensures that long secrets (e.g. 60-char tokens) that start
// at the preview boundary are still fully redacted even though the final
// preview is only maxLen bytes. Without the wider window, a partial match
// at the edge would not satisfy the primary rule's length requirements.
func safePreview(text string, offset, maxLen int) string {
	total := len(text)
	if total == 0 || maxLen <= 0 {
		return ""
	}

	// Extract a wider context window for redaction (4× maxLen).
	// After redaction, we trim to center maxLen bytes around the offset.
	wideLen := maxLen * 4
	halfWide := wideLen / 2
	wideStart := max(offset-halfWide, 0)
	wideEnd := wideStart + wideLen
	if wideEnd > total {
		wideEnd = total
		wideStart = max(wideEnd-wideLen, 0)
	}

	// Advance wideStart forward to the next UTF-8 rune boundary so we never
	// slice a multi-byte rune. offset itself is guaranteed to be a valid rune
	// start (regexp engine only matches at rune boundaries). Since wideStart is
	// at most halfWide bytes before offset, the loop advances at most 3 bytes
	// (max UTF-8 continuation sequence) and cannot reach offset.
	for wideStart > 0 && wideStart < len(text) && !utf8.RuneStart(text[wideStart]) {
		wideStart++
	}

	// Walk wideEnd backward to the previous UTF-8 rune boundary so we never
	// slice a multi-byte rune at the end of the wide window.
	for wideEnd > wideStart && wideEnd < total && !utf8.RuneStart(text[wideEnd]) {
		wideEnd--
	}

	// Slice by bytes — offset is a byte index, so byte arithmetic is correct.
	wide := text[wideStart:wideEnd]

	// Apply a minimal redaction pass so no raw secret appears in the preview.
	// We cannot call RedactText (would be circular), so we apply applyAllRules
	// directly — the same rules used by the primary pipeline.
	wide = applyAllRules(wide)

	// Now trim the redacted wide window to the final maxLen-byte preview,
	// centered on the offset relative to the wide window.
	offsetInWide := max(offset-wideStart, 0)
	halfWindow := maxLen / 2
	previewStart := max(offsetInWide-halfWindow, 0)
	previewEnd := previewStart + maxLen
	if previewEnd > len(wide) {
		previewEnd = len(wide)
		previewStart = max(previewEnd-maxLen, 0)
	}

	// Advance previewStart forward to the next UTF-8 rune boundary so we never
	// return a string that begins mid-rune. offsetInWide may be computed from
	// byte arithmetic and can fall in the continuation bytes of a multi-byte rune
	// when the surrounding context contains non-ASCII characters.
	for previewStart > 0 && previewStart < len(wide) && !utf8.RuneStart(wide[previewStart]) {
		previewStart++
	}

	// Walk previewEnd backward to the previous UTF-8 rune boundary so we never
	// return a string that ends mid-rune.
	for previewEnd > previewStart && previewEnd < len(wide) && !utf8.RuneStart(wide[previewEnd]) {
		previewEnd--
	}

	return wide[previewStart:previewEnd]
}
