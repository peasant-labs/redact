package redact

import (
	"regexp"
	"strings"
)

// Category classifies what kind of sensitive data a Rule targets.
type Category string

const (
	// CategorySecrets targets API keys, tokens, credentials, and other secret values.
	CategorySecrets Category = "secrets"
	// CategoryPII targets personally identifiable information (email, phone, SSN, etc.).
	CategoryPII Category = "pii"
	// CategoryPaths targets filesystem paths that may expose usernames.
	CategoryPaths Category = "paths"
	// CategoryProject targets project identity information: git remotes, import
	// paths, Docker image refs, branch names, and CI environment variables.
	// Individual rules may require a stricter level than the category default.
	CategoryProject Category = "project"
)

var allCategories = [...]Category{
	CategorySecrets,
	CategoryPII,
	CategoryPaths,
	CategoryProject,
}

// AllCategories returns the canonical engine-category enumeration. The caller
// receives a copy so it cannot mutate validation or mapping behavior.
func AllCategories() []Category {
	categories := make([]Category, len(allCategories))
	copy(categories, allCategories[:])
	return categories
}

// IsValid returns true if the category is one of the known variants.
func (c Category) IsValid() bool {
	for _, category := range allCategories {
		if c == category {
			return true
		}
	}
	return false
}

// Rule is a compiled regex redaction rule with a category and replacement string.
type Rule struct {
	ID           string
	Category     Category
	MinimumLevel RedactionLevel // empty uses the category's default minimum
	Pattern      *regexp.Regexp // compiled at package init via regexp.MustCompile
	Replacement  string
	// FilterFn is an optional post-match filter applied after the regex fires.
	// If non-nil, FilterFn(matched, input, offset) must return true for the
	// match to be kept. A false return suppresses the match entirely.
	// Parameters:
	//   matched — the full matched text (same as input[offset:offset+len(matched)])
	//   input   — the original full input string being scanned
	//   offset  — byte offset of matched within input
	// FilterFn must be safe for concurrent use (stateless).
	FilterFn func(matched string, input string, offset int) bool
}

// UserPattern is a user-defined regex redaction rule loaded from config.yaml.
// Compiled and applied by NewRedactor. User patterns inherit their semantic
// category's default minimum; the configuration surface does not currently
// expose stricter per-pattern activation.
type UserPattern struct {
	ID          string
	Category    Category
	Pattern     string // raw regex string — compiled by NewRedactor
	Replacement string
}

// Rules is the complete compiled rule table.
// All patterns are compiled at package init — no runtime compilation cost.
//
// Rules is exported as a mutable var to allow test injection (e.g., nil-Pattern
// rules for fail-closed testing). Production code treats it as read-only after init.
// An accessor returning a copy was considered but adds API surface for a single test.
var Rules = []Rule{
	// --- Secrets ---
	// Patterns aligned with Yelp/detect-secrets canonical regexes where coverage overlaps.
	// Intentional deviations are documented per-rule. See:
	//   https://github.com/Yelp/detect-secrets/tree/master/detect_secrets/plugins
	{
		// Anthropic API key. No detect-secrets equivalent — Anthropic's key format
		// is documented at https://docs.anthropic.com/en/api/getting-started.
		// Format: sk-ant-{type}-{secret} where {type} is e.g. api03, admin03.
		ID:          "anthropic_key",
		Category:    CategorySecrets,
		Pattern:     regexp.MustCompile(`sk-ant-[a-zA-Z0-9]{4,}-[a-zA-Z0-9_-]{20,}`),
		Replacement: "<ANTHROPIC_KEY>",
	},
	{
		// OpenAI API key. Aligned with detect-secrets/openai.py:
		//   sk-[A-Za-z0-9-_]*[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}
		// Real OpenAI keys always contain the literal substring "T3BlbkFJ"
		// (base64 of "OpenAI"). Covers both legacy keys (sk-{20}T3BlbkFJ{20})
		// and project-scoped keys (sk-proj-{name}-{20}T3BlbkFJ{20}).
		// ref: https://community.openai.com/t/what-are-the-valid-characters-for-the-apikey/288643
		ID:          "openai_key",
		Category:    CategorySecrets,
		Pattern:     regexp.MustCompile(`sk-[A-Za-z0-9_-]*[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}`),
		Replacement: "<OPENAI_KEY>",
	},
	{
		// GitHub Personal Access Token. Aligned with detect-secrets/github_token.py:
		//   (ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}
		// Real GitHub tokens are exactly 36 chars after the prefix.
		// ref: https://github.blog/2021-04-05-behind-githubs-new-authentication-token-formats/
		ID:          "github_pat",
		Category:    CategorySecrets,
		Pattern:     regexp.MustCompile(`(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}`),
		Replacement: "<GITHUB_PAT>",
	},
	{
		// AWS Access Key ID. Superset of detect-secrets' prefix list:
		//   detect-secrets: (A3T[A-Z0-9]|ABIA|ACCA|AKIA|ASIA)
		//   ours:           (A3T[A-Z0-9]|ABIA|ACCA|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)
		// We include detect-secrets' full set (ABIA = SSO user access keys,
		// ACCA = SSO role credentials) plus AGPA/AIDA/AROA/AIPA/ANPA/ANVA which
		// are documented IAM resource ID prefixes per AWS docs:
		//   https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html
		// All 11 prefixes are sensitive AWS identifiers worth redacting.
		ID:          "aws_access_key",
		Category:    CategorySecrets,
		Pattern:     regexp.MustCompile(`(?:A3T[A-Z0-9]|ABIA|ACCA|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`),
		Replacement: "<AWS_ACCESS_KEY>",
	},
	{
		// AWS Secret Key. Pattern matches any 40-char base64 string (with optional
		// =/== padding); awsSecretKeyFilter wired in init() applies post-match
		// context filtering — analogous to detect-secrets' two-pass approach
		// (regex + AWS keyword/AKIA proximity check).
		//
		// Group 2 captures the trailing boundary character so it survives the
		// replacement ("aws_secret_access_key = ${KEY}\"" → "...${KEY}\"" with
		// the quote intact). RE2 lacks lookbehind, so this is the closest
		// equivalent of detect-secrets' get_secret_access_keys boundary scan.
		ID:          "aws_secret_key",
		Category:    CategorySecrets,
		Pattern:     regexp.MustCompile(`([A-Za-z0-9+/]{40}|[A-Za-z0-9+/]{39}=|[A-Za-z0-9+/]{38}==)([^A-Za-z0-9+/=]|$)`),
		Replacement: "<AWS_SECRET_KEY>${2}",
		// FilterFn is wired in init() to avoid an initialization cycle:
		// awsSecretKeyFilter → findRuleByID → Rules (the var being initialised).
	},
	{
		// Stripe API key. Aligned with detect-secrets/stripe.py:
		//   (?:r|s)k_live_[0-9a-zA-Z]{24}
		// Extended to also cover test keys (sk_test_, rk_test_) which detect-secrets
		// does not cover — Stripe documents both live and test variants:
		//   https://docs.stripe.com/keys
		// Real Stripe keys are exactly 24 chars after the prefix.
		ID:          "stripe_key",
		Category:    CategorySecrets,
		Pattern:     regexp.MustCompile(`(?:r|s)k_(?:live|test)_[0-9a-zA-Z]{24}`),
		Replacement: "<STRIPE_KEY>",
	},
	{
		// Twilio Account SID. Aligned with detect-secrets/twilio.py:
		//   AC[a-z0-9]{32}
		ID:          "twilio_key",
		Category:    CategorySecrets,
		Pattern:     regexp.MustCompile(`AC[a-z0-9]{32}`),
		Replacement: "<TWILIO_KEY>",
	},
	{
		// Twilio Auth Token. Aligned with detect-secrets/twilio.py:
		//   SK[a-z0-9]{32}
		// Separate rule from twilio_key (Account SID) because the SK prefix
		// identifies an Auth Token specifically.
		ID:          "twilio_auth_token",
		Category:    CategorySecrets,
		Pattern:     regexp.MustCompile(`SK[a-z0-9]{32}`),
		Replacement: "<TWILIO_AUTH_TOKEN>",
	},
	{
		// SendGrid API key. Aligned with detect-secrets/sendgrid.py:
		//   SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}
		// Real SendGrid keys are exactly 22 chars . exactly 43 chars after SG.
		ID:          "sendgrid_key",
		Category:    CategorySecrets,
		Pattern:     regexp.MustCompile(`SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`),
		Replacement: "<SENDGRID_KEY>",
	},
	{
		// Slack token. Aligned with detect-secrets/slack.py:
		//   xox(?:a|b|p|o|s|r)-(?:\d+-)+[a-z0-9]+   (case-insensitive)
		// Requires numeric segments after the type prefix — real Slack tokens
		// embed workspace/bot/user IDs as digit groups, then end with an
		// alphanumeric token segment. Case-insensitive per detect-secrets.
		ID:          "slack_token",
		Category:    CategorySecrets,
		Pattern:     regexp.MustCompile(`(?i)xox[abopsr]-(?:\d+-)+[a-z0-9]+`),
		Replacement: "<SLACK_TOKEN>",
	},
	{
		// Slack incoming webhook URL. Aligned with detect-secrets/slack.py
		// second denylist pattern. Webhook URLs are active credentials — anyone
		// with the URL can post messages to the channel.
		ID:          "slack_webhook_url",
		Category:    CategorySecrets,
		Pattern:     regexp.MustCompile(`(?i)https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+`),
		Replacement: "<SLACK_WEBHOOK_URL>",
	},
	{
		// JWT token. Aligned with detect-secrets/jwt.py regex shape:
		//   eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*?
		// We keep "second segment must also start with eyJ" because in transcript
		// text a real JWT payload almost always starts with eyJ (encoded "{").
		// Trailing signature segment is optional (\.?) to cover unsigned JWTs
		// (alg=none) which are still data leaks worth redacting.
		// detect-secrets adds a base64 + JSON formal-validity check; we don't
		// replicate it in Go — the FP cost in transcripts is one extra redaction.
		//
		// The {10,} minimum on head and payload bodies guards against doc-example
		// shapes like "eyJa.eyJb". The shortest valid JSON object {"a":1} encodes
		// to "eyJhIjoxfQ" (10 chars), so a {10,} floor keeps all real unsigned JWTs
		// while rejecting tiny synthetic test-vector shapes that are structurally
		// plausible but semantically empty.
		ID:          "jwt_token",
		Category:    CategorySecrets,
		Pattern:     regexp.MustCompile(`eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}(?:\.[a-zA-Z0-9_-]+)?`),
		Replacement: "<JWT_TOKEN>",
	},
	{
		// Private key PEM header. Aligned with detect-secrets/private_key.py:
		//   BEGIN (DSA|EC|OPENSSH|PGP|RSA|SSH2 ENCRYPTED|PRIVATE) KEY
		// plus PuTTY-User-Key-File-2 sentinel.
		//
		// PGP has its own dedicated arm because real PGP headers include the word
		// "BLOCK" — the correct header is "-----BEGIN PGP PRIVATE KEY BLOCK-----",
		// not "-----BEGIN PGP PRIVATE KEY-----". Keeping PGP inside the optional-
		// prefix group would generate the wrong (non-existent) "BEGIN PGP PRIVATE KEY"
		// form. All other key types (RSA, EC, DSA, OPENSSH, SSH2 ENCRYPTED) use the
		// standard "BEGIN {TYPE} PRIVATE KEY" form without BLOCK.
		ID:          "private_key_block",
		Category:    CategorySecrets,
		Pattern:     regexp.MustCompile(`(?:-----BEGIN (?:RSA |EC |DSA |OPENSSH |SSH2 ENCRYPTED )?PRIVATE KEY-----|-----BEGIN PGP PRIVATE KEY BLOCK-----|PuTTY-User-Key-File-2)`),
		Replacement: "<PRIVATE_KEY>",
	},
	{
		// Generic API key in assignment form. No direct detect-secrets equivalent
		// (their KeywordDetector takes a different approach with language-specific
		// per-file parsing). We use a simpler regex over text content.
		ID:          "generic_api_key",
		Category:    CategorySecrets,
		Pattern:     regexp.MustCompile(`(?i)(?:api[_-]?key|apikey)\s*[=:]\s*["']?([a-zA-Z0-9_\-]{20,})["']?`),
		Replacement: "<API_KEY>",
	},
	{
		// HTTP Authorization Bearer token. No direct detect-secrets equivalent —
		// detect-secrets does not redact HTTP Authorization headers (focused on
		// source-code secret leakage). Transcript content commonly contains
		// captured HTTP request/response, so this rule covers that surface.
		ID:          "bearer_token",
		Category:    CategorySecrets,
		Pattern:     regexp.MustCompile(`(?i)Bearer\s+([a-zA-Z0-9_\-\.+/=]{20,})`),
		Replacement: "<BEARER_TOKEN>",
	},
	{
		// HTTP Authorization Basic header. Covers transcript-captured request
		// headers (detect-secrets/basic_auth.py does not — it covers URI form;
		// see basic_auth_uri rule below).
		ID:          "basic_auth",
		Category:    CategorySecrets,
		Pattern:     regexp.MustCompile(`(?i)(?:Authorization:\s*Basic\s+|Basic\s+auth(?:orization)?\s*[=:]\s*)([a-zA-Z0-9+/=]{10,})`),
		Replacement: "<BASIC_AUTH>",
	},
	{
		// URI-form basic auth. Aligned with detect-secrets/basic_auth.py:
		//   ://[^reserved]+:[^reserved]+@
		// where reserved = ':/?#[]@' + '!$&\'()*+,;=' per RFC 3986.
		// Captures embedded credentials in URLs like https://user:pass@host.
		//
		// Template-variable braces { } are also excluded from the userinfo
		// character classes so placeholder URLs such as
		// "https://{user}:{pass}@host" or "https://${USER}:${PASS}@host" do NOT
		// match — they are config templates, not real leaked credentials. This
		// mirrors detect-secrets, which excludes templated values.
		ID:          "basic_auth_uri",
		Category:    CategorySecrets,
		Pattern:     regexp.MustCompile(`://[^:/?#\[\]@!$&'()*+,;={}\s]+:[^:/?#\[\]@!$&'()*+,;={}\s]+@`),
		Replacement: "://<BASIC_AUTH_URI>@",
	},
	{
		// Access/verification code in prompt text (Cursor login/device flow).
		// These are short-lived but still sensitive because they can grant
		// account/session access while valid.
		//
		// Examples:
		//   "Access code: ABCD-1234"
		//   "verification code is 8K3P2Q"
		//   "OTP code 123456"
		//
		// The keyword prefix keeps this rule narrow so generic short alphanumeric
		// values are not redacted without surrounding "code" context.
		ID:       "access_code",
		Category: CategorySecrets,
		Pattern: regexp.MustCompile(
			`(?i)\b((?:access|verification|device|one[- ]?time|otp)\s*code(?:\s*(?:is|:|=)\s*|\s+))([A-Za-z0-9][A-Za-z0-9-]{5,31})\b`,
		),
		Replacement: "${1}<ACCESS_CODE>",
	},

	// --- Secrets: detect-secrets expansion ---
	{
		// Boundary anchors prevent matching tokens embedded in identifiers
		// (e.g. "xAKCabc123defghi" without a leading word-break does NOT flag).
		ID:          "artifactory_api_token",
		Category:    CategorySecrets,
		Pattern:     regexp.MustCompile(`(?:^|[\s=:"])AKC[a-zA-Z0-9]{10,}(?:[\s"]|$)`),
		Replacement: "<ARTIFACTORY_API_TOKEN>",
	},
	{
		// AP followed by one uppercase hex digit (0-9, A-F) then 8+ alphanum chars.
		// Boundary anchors match detect-secrets' (?:\s|=|:|"|^) before and (?:\s|"|$) after.
		ID:          "artifactory_password",
		Category:    CategorySecrets,
		Pattern:     regexp.MustCompile(`(?:^|[\s=:"])AP[0-9A-F][a-zA-Z0-9]{8,}(?:[\s"]|$)`),
		Replacement: "<ARTIFACTORY_PASSWORD>",
	},
	{
		// Azure Storage AccountKey is exactly 88 base64 chars after "AccountKey=".
		ID:          "azure_storage_key",
		Category:    CategorySecrets,
		Pattern:     regexp.MustCompile(`AccountKey=[a-zA-Z0-9+/=]{88}`),
		Replacement: "<AZURE_STORAGE_KEY>",
	},
	{
		// Discord bot token: three dot-separated segments.
		// Aligned with detect-secrets/discord.py:
		//   [MNO][a-zA-Z\d_-]{23,25}\.[a-zA-Z\d_-]{6}\.[a-zA-Z\d_-]{27}
		// Per Discord docs the third segment is exactly 27 chars; we no longer
		// accept {27,} because longer values are not part of the documented format.
		// ref: https://discord.com/developers/docs/reference#authentication
		ID:          "discord_bot_token",
		Category:    CategorySecrets,
		Pattern:     regexp.MustCompile(`[MNO][a-zA-Z0-9_-]{23,25}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27}`),
		Replacement: "<DISCORD_BOT_TOKEN>",
	},
	{
		// GitLab Personal Access Token and similar token types (deploy, feed, etc.).
		// RE2 does not support lookaheads; (?:[^A-Za-z0-9_]|$) is the RE2-compatible
		// equivalent of Python's (?!\w) negative lookahead.
		ID:          "gitlab_pat",
		Category:    CategorySecrets,
		Pattern:     regexp.MustCompile(`(?:glpat|gldt|glft|glsoat|glrt)-[A-Za-z0-9_\-]{20,50}(?:[^A-Za-z0-9_]|$)`),
		Replacement: "<GITLAB_TOKEN>",
	},
	{
		// GitLab Runner Registration Token.
		ID:          "gitlab_runner_registration",
		Category:    CategorySecrets,
		Pattern:     regexp.MustCompile(`GR1348941[A-Za-z0-9_\-]{20,50}(?:[^A-Za-z0-9_]|$)`),
		Replacement: "<GITLAB_RUNNER_TOKEN>",
	},
	{
		// GitLab CI/CD Token (optional 2-char hex partition_id prefix).
		ID:          "gitlab_cicd",
		Category:    CategorySecrets,
		Pattern:     regexp.MustCompile(`glcbt-(?:[0-9a-fA-F]{2}_)?[A-Za-z0-9_\-]{20,50}(?:[^A-Za-z0-9_]|$)`),
		Replacement: "<GITLAB_CICD_TOKEN>",
	},
	{
		// GitLab Incoming Mail Token — exactly 25 chars after prefix.
		ID:          "gitlab_incoming_mail",
		Category:    CategorySecrets,
		Pattern:     regexp.MustCompile(`glimt-[A-Za-z0-9_\-]{25}(?:[^A-Za-z0-9_]|$)`),
		Replacement: "<GITLAB_MAIL_TOKEN>",
	},
	{
		// GitLab Trigger Token — exactly 40 chars after prefix.
		ID:          "gitlab_trigger",
		Category:    CategorySecrets,
		Pattern:     regexp.MustCompile(`glptt-[A-Za-z0-9_\-]{40}(?:[^A-Za-z0-9_]|$)`),
		Replacement: "<GITLAB_TRIGGER_TOKEN>",
	},
	{
		// GitLab Agent Token. Aligned with detect-secrets/gitlab_token.py:
		//   glagent-[A-Za-z0-9_\-]{50,1024}(?!\w)
		// Go's regexp (RE2) caps a single bounded repetition at 1000, so the
		// literal {50,1024} fails to compile. We express the same 50–1024 total
		// length as a composed bound: {50,1000} followed by {0,24} — both
		// classes are identical ([A-Za-z0-9_\-]), split purely to satisfy RE2's
		// repeat limit. This rejects 1025+ char tokens, matching detect-secrets'
		// upper cap exactly (their test asserts a 1025-char token does NOT match).
		ID:          "gitlab_agent",
		Category:    CategorySecrets,
		Pattern:     regexp.MustCompile(`glagent-[A-Za-z0-9_\-]{50,1000}[A-Za-z0-9_\-]{0,24}(?:[^A-Za-z0-9_]|$)`),
		Replacement: "<GITLAB_AGENT_TOKEN>",
	},
	{
		// GitLab OAuth Application Secret — exactly 64 chars after prefix.
		ID:          "gitlab_oauth_secret",
		Category:    CategorySecrets,
		Pattern:     regexp.MustCompile(`gloas-[A-Za-z0-9_\-]{64}(?:[^A-Za-z0-9_]|$)`),
		Replacement: "<GITLAB_OAUTH_SECRET>",
	},
	{
		// Mailchimp API key: 32 lowercase hex chars + "-us" + 1–2 digit datacenter.
		// Trailing (?:[^0-9]|$) prevents matching "us10" when "-us1" is the valid key part.
		ID:          "mailchimp_api_key",
		Category:    CategorySecrets,
		Pattern:     regexp.MustCompile(`[0-9a-z]{32}-us[0-9]{1,2}(?:[^0-9]|$)`),
		Replacement: "<MAILCHIMP_API_KEY>",
	},
	{
		// npm .npmrc auth token: //<registry>/:_authToken= followed by npm_ or UUID.
		// The registry URL portion requires at least one non-slash character (.+).
		// Env var placeholders like ${NPM_TOKEN} do NOT match because npm_...
		// requires a literal value, not a ${...} template.
		ID:          "npm_auth_token",
		Category:    CategorySecrets,
		Pattern:     regexp.MustCompile(`//.+/:_authToken=\s*(?:npm_.+|[A-Fa-f0-9-]{36})`),
		Replacement: "<NPM_AUTH_TOKEN>",
	},
	{
		// PyPI production token — fixed base64 prefix encoding pypi.org namespace.
		ID:          "pypi_api_token",
		Category:    CategorySecrets,
		Pattern:     regexp.MustCompile(`pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{70,}`),
		Replacement: "<PYPI_TOKEN>",
	},
	{
		// PyPI test instance token — fixed base64 prefix encoding test.pypi.org namespace.
		ID:          "pypi_test_token",
		Category:    CategorySecrets,
		Pattern:     regexp.MustCompile(`pypi-AgENdGVzdC5weXBpLm9yZw[A-Za-z0-9_-]{70,}`),
		Replacement: "<PYPI_TEST_TOKEN>",
	},
	{
		// Square OAuth application secret — exactly 43 chars: alphanumeric + underscore + dash + backslash.
		// The Python original uses [0-9A-Za-z\\\-_]{43} which includes a literal backslash.
		// In Go RE2, place \\ and _ before - to avoid accidental range \-_: use [0-9A-Za-z\\_\-]{43}.
		ID:          "square_oauth_secret",
		Category:    CategorySecrets,
		Pattern:     regexp.MustCompile(`sq0csp-[0-9A-Za-z\\_\-]{43}`),
		Replacement: "<SQUARE_OAUTH_SECRET>",
	},
	{
		// Telegram bot token: 8–10 digit bot ID + ":" + 35 [0-9A-Za-z_-] chars.
		// [^0-9A-Za-z] (not just [^A-Za-z]) is required before the digit run: RE2 alternation
		// with ^ can zero-width match mid-string, so [^A-Za-z] alone permits "bot110201543:..."
		// to match (the ^ branch fires at the digit run). Excluding digits too prevents this.
		// The trailing (?:[^A-Za-z0-9_-]|$) prevents AWS ARN false positives.
		ID:          "telegram_bot_token",
		Category:    CategorySecrets,
		Pattern:     regexp.MustCompile(`(?:^|[^0-9A-Za-z])\d{8,10}:[0-9A-Za-z_-]{35}(?:[^A-Za-z0-9_-]|$)`),
		Replacement: "<TELEGRAM_BOT_TOKEN>",
	},

	// --- PII ---
	{
		ID:          "email",
		Category:    CategoryPII,
		Pattern:     regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
		Replacement: "<EMAIL>",
		FilterFn:    emailFilter,
	},
	{
		ID:          "phone_us",
		Category:    CategoryPII,
		Pattern:     regexp.MustCompile(`(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}`),
		Replacement: "<PHONE>",
	},
	{
		ID:          "ssn",
		Category:    CategoryPII,
		Pattern:     regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
		Replacement: "<SSN>",
	},
	{
		// Trade-off: this pattern matches any 16-digit number (with optional separators),
		// which may produce false positives on numeric IDs or version numbers that happen
		// to be 16 digits long. The alternative — requiring at least one separator — would
		// miss cards stored without formatting (e.g. in databases or logs). We accept the
		// false-positive risk here because the cost of missing a real card number is higher
		// than the cost of over-redacting a numeric ID.
		ID:          "credit_card",
		Category:    CategoryPII,
		Pattern:     regexp.MustCompile(`\b(?:\d{4}[-\s]?){3}\d{4}\b`),
		Replacement: "<CREDIT_CARD>",
	},
	{
		ID:          "ip_address",
		Category:    CategoryPII,
		Pattern:     regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b`),
		Replacement: "<IP_ADDRESS>",
	},

	// --- Paths ---
	{
		ID:          "unix_home_path",
		Category:    CategoryPaths,
		Pattern:     regexp.MustCompile(`(/(?:Users|home)/)[^/\s]+`),
		Replacement: "${1}<USER>",
	},
	{
		// Two-word unix home username segments (e.g. /home/SFU CLASSES/project).
		// Single-segment unix_home_path deliberately skips these; see unixHomeSingleSegmentFilter.
		ID:          "unix_home_path_spaced",
		Category:    CategoryPaths,
		Pattern:     regexp.MustCompile(`(/(?:Users|home)/)([^/\s]+ [^/\s]+)/`),
		Replacement: "${1}<USER>/",
	},
	{
		ID:          "windows_home_path",
		Category:    CategoryPaths,
		Pattern:     regexp.MustCompile(`((?i)C:\\Users\\)[^\\\s]+`),
		Replacement: `${1}<USER>`,
	},
	{
		ID:          "windows_home_path_spaced",
		Category:    CategoryPaths,
		Pattern:     regexp.MustCompile(`((?i)C:\\Users\\)([^\\\s]+ [^\\\s]+)\\`),
		Replacement: `${1}<USER>\`,
	},
	{
		// Claude project slug: -home-{user}- or -Users-{user}-
		// Captures the username segment between the OS prefix and the next dash separator.
		// Uses non-greedy *? with trailing (-) anchor to match the shortest valid username.
		// The leading (\W) anchor prevents false positives on natural English words like
		// "go-home-early-feature" or "some-home-page-widget" where a word character precedes
		// the -home- segment. Slugs at string start (no \W prefix) are handled by the
		// context-aware buildPrivateReplacer in RedactMetadata; this regex is a fallback.
		ID:          "claude_project_slug",
		Category:    CategoryPaths,
		Pattern:     regexp.MustCompile(`(\W)(-(?:home|Users)-)([a-zA-Z0-9_][a-zA-Z0-9_.-]*?)(-)`),
		Replacement: "${1}${2}<USER>${4}",
	},
	{
		// Peasant host slug: --home--{user}-- or --Users--{user}--
		// Double-dash variant used in DeriveHostSlug for untracked projects.
		// Same non-greedy matching strategy and \W anchor as claude_project_slug.
		// Slugs at string start are handled by buildPrivateReplacer; this is a fallback.
		ID:          "peasant_host_slug",
		Category:    CategoryPaths,
		Pattern:     regexp.MustCompile(`(\W)(--(?:home|Users)--)([a-zA-Z0-9_][a-zA-Z0-9_.-]*?)(--)`),
		Replacement: "${1}${2}<USER>${4}",
	},
}

// emailFilter rejects the email-shaped prefix of an SCP-style git remote.
// For example, the email regex sees "git@github.com" inside
// "git@github.com:org/repo.git". Treating that prefix as PII would partially
// redact a remote even when the git-remote rule is intentionally inactive.
func emailFilter(matched, input string, offset int) bool {
	if !strings.HasPrefix(strings.ToLower(matched), "git@") || offset < 0 || offset >= len(input) {
		return true
	}
	location := gitRemoteSSHPattern.FindStringIndex(input[offset:])
	return location == nil || location[0] != 0
}

// init wires FilterFn onto the aws_secret_key rule after all package-level vars
// are initialised. We cannot set FilterFn in the Rules literal because
// awsSecretKeyFilter calls findRuleByID which reads Rules — that would create
// an initialization cycle.
func init() {
	for i := range Rules {
		switch Rules[i].ID {
		case "aws_secret_key":
			Rules[i].FilterFn = awsSecretKeyFilter
		case "credit_card":
			Rules[i].FilterFn = creditCardFilter
		case "unix_home_path":
			Rules[i].FilterFn = unixHomeSingleSegmentFilter
		case "windows_home_path":
			Rules[i].FilterFn = windowsHomeSingleSegmentFilter
		}
	}
}

// unixHomeSingleSegmentFilter rejects single-segment unix_home_path matches that are
// only the first word of a multi-word username (e.g. /home/SFU in /home/SFU CLASSES/project).
func unixHomeSingleSegmentFilter(matched, input string, offset int) bool {
	return !homeSingleSegmentIsSpacedUsernamePrefix(input, offset+len(matched), '/')
}

// windowsHomeSingleSegmentFilter is the Windows backslash variant of unixHomeSingleSegmentFilter.
func windowsHomeSingleSegmentFilter(matched, input string, offset int) bool {
	return !homeSingleSegmentIsSpacedUsernamePrefix(input, offset+len(matched), '\\')
}

// homeSingleSegmentIsSpacedUsernamePrefix reports whether rest of input after a
// single-segment home match continues with " word/pathSep" (multi-word username).
func homeSingleSegmentIsSpacedUsernamePrefix(input string, end int, pathSep byte) bool {
	if end >= len(input) || input[end] != ' ' {
		return false
	}
	i := end + 1
	for i < len(input) && input[i] != ' ' && input[i] != pathSep {
		i++
	}
	return i < len(input) && input[i] == pathSep
}

// awsKeywords are the lowercase context signals that indicate a nearby string
// is likely an AWS secret key. Only AWS-specific phrases are included — bare
// words like "secret", "password", and "aws" cause too many false positives in
// coding transcripts where these words appear constantly.
var awsKeywords = []string{"aws_secret", "aws_secret_access_key", "secret_access_key", "access_key", "credential", "amazon"}

// awsSecretKeyFilter rejects aws_secret_key matches that lack AWS context.
//
// A 40-char base64 string is only kept if:
//  1. It is NOT a sequential string (isSequentialString), AND
//  2. It is NOT a UUID (isPotentialUUID), AND
//  3. At least one of:
//     a. An AWS keyword appears within 200 chars (awsKeywords)
//     b. An AWS access key ID (AKIA/ASIA/A3T prefix) appears within 200 chars
//
// No structural path heuristic is applied: a real AWS key containing "/" chars
// that appears near AWS keywords is a true positive and must not be rejected by
// shape alone. Bare file-path strings are rejected naturally by the context
// check — they have no AWS keyword nearby and fall through to the false return.
//
// This is safe for concurrent use — it is stateless and reads only package-level
// vars (awsKeywords, Rules) which are write-once at init time.
func awsSecretKeyFilter(matched, input string, offset int) bool {
	body := extractBase64Body(matched)

	// Pre-filters: reject patterns that are structurally never real secrets.
	// These run before the context window scan as a fast-path rejection.
	// isSequentialString and isPotentialUUID are defined in entropy.go.
	if isSequentialString(body) {
		return false
	}
	if isPotentialUUID(body) {
		return false
	}

	// Context window: 200 chars before and after the match.
	windowStart := max(0, offset-200)
	windowEnd := min(len(input), offset+len(matched)+200)
	window := strings.ToLower(input[windowStart:windowEnd])

	// Check for AWS keywords in the surrounding context.
	for _, kw := range awsKeywords {
		if strings.Contains(window, kw) {
			return true
		}
	}

	// Check for an AWS access key ID (AKIA/ASIA/A3T prefix) in the window.
	// We reuse the compiled aws_access_key regex to avoid duplicating the pattern.
	accessKeyRule := findRuleByID("aws_access_key")
	if accessKeyRule != nil && accessKeyRule.Pattern.MatchString(input[windowStart:windowEnd]) {
		return true
	}

	return false // no context → reject
}

// creditCardFilter rejects credit_card matches that contain dashes.
// Real credit cards use spaces or no separator — dashes strongly indicate UUID
// fragments (8-4-4-4-12 hex), order numbers, or other non-card identifiers.
func creditCardFilter(matched, _ string, _ int) bool {
	return !strings.Contains(matched, "-")
}

// extractBase64Body returns the base64 body of an aws_secret_key match, stripping
// the trailing boundary character captured by group 2 of the pattern.
//
// The aws_secret_key pattern is:
//
//	([A-Za-z0-9+/]{40}|[A-Za-z0-9+/]{39}=|[A-Za-z0-9+/]{38}==)([^A-Za-z0-9+/=]|$)
//
// Group 2 is either a boundary character (non-base64) or an empty string (end-of-string).
// If the last byte is NOT a base64 character ([A-Za-z0-9+/=]), strip it.
// If it IS base64 (end-of-string case where group 2 matched empty), return full match.
func extractBase64Body(matched string) string {
	if len(matched) == 0 {
		return matched
	}
	last := matched[len(matched)-1]
	isBase64Char := (last >= 'A' && last <= 'Z') ||
		(last >= 'a' && last <= 'z') ||
		(last >= '0' && last <= '9') ||
		last == '+' || last == '/' || last == '='
	if isBase64Char {
		return matched // end-of-string case: full match is the base64 body
	}
	return matched[:len(matched)-1] // strip trailing boundary char
}

// findRuleByID scans the package-level Rules slice for a rule with the given ID
// and returns a pointer to it. Returns nil if no rule with that ID exists.
//
// Rules is written once at package init and is read-only thereafter, so this
// function is safe for concurrent use without locking.
func findRuleByID(id string) *Rule {
	for i := range Rules {
		if Rules[i].ID == id {
			return &Rules[i]
		}
	}
	return nil
}
