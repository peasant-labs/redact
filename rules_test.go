package redact

// rules_test.go — per-rule fixture tests for the 17 detect-secrets expansion rules.
//
// Pattern: each rule gets a []struct{payload string; shouldFlag bool} table
// with at least one true positive and boundary negatives (too short, wrong
// prefix, embedded-in-word, env-var reference, special false-positive guards).
//
// The helper matchesRule(t, ruleID, payload) applies the single named rule from
// the Rules table so tests are independent of unrelated rule matches.

import (
	"strings"
	"testing"
)

// matchesRule returns true if the rule with the given ID matches payload.
// It skips the test if the rule ID is not found (prevents silent test gap).
func matchesRule(t *testing.T, ruleID, payload string) bool {
	t.Helper()
	for _, r := range Rules {
		if r.ID == ruleID {
			return r.Pattern.MatchString(payload)
		}
	}
	t.Fatalf("matchesRule: rule %q not found in Rules table — was it added?", ruleID)
	return false
}

// ---------------------------------------------------------------------------
// Artifactory API Token (artifactory_api_token)
// ---------------------------------------------------------------------------

func TestRule_ArtifactoryAPIToken(t *testing.T) {
	cases := []struct {
		payload    string
		shouldFlag bool
	}{
		// True positives — boundary anchors: leading space/=/:/" or start-of-string
		{"AKCxxxxxxxxxx1234", true},                  // start of string
		{" AKCxxxxxxxxxx1234", true},                 // leading space
		{"=AKCxxxxxxxxxx1234", true},                 // '=' separator
		{":AKCxxxxxxxxxx1234", true},                 // ':' separator
		{`"AKCxxxxxxxxxx1234"`, true},                // quoted
		{"artif-key:AKCxxxxxxxxxx1234", true},        // colon separator (header)
		{"X-JFrog-Art-Api: AKCxxxxxxxxxx1234", true}, // HTTP header

		// Boundary negatives — embedded in a word (no leading word-break)
		{"testAKCwithinsomeirrelevantstring", false}, // no boundary — must NOT flag
		{"testAP6withinsomeirrelevantstring", false}, // same for AP prefix
		{"xAKCabc123defghi", false},                  // embedded, no boundary

		// Env var reference — must NOT flag
		{"X-JFrog-Art-Api: $API_KEY", false},
		{"X-JFrog-Art-Api: $PASSWORD", false},

		// Too short — prefix correct but token too short (< 10 chars after AKC)
		{"AKCxxxxxxxx", false}, // only 8 chars after AKC
		{":AKCxxxxxxxx", false},

		// Wrong prefix
		{"AKDxxxxxxxxxx1234", false}, // 'D' not 'C'
		{"BKCxxxxxxxxxx1234", false}, // 'B' not 'A'
	}

	for _, tc := range cases {
		t.Run(tc.payload, func(t *testing.T) {
			got := matchesRule(t, "artifactory_api_token", tc.payload)
			if got != tc.shouldFlag {
				t.Errorf("artifactory_api_token: matchesRule(%q) = %v, want %v",
					tc.payload, got, tc.shouldFlag)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Artifactory Encrypted Password (artifactory_password)
// ---------------------------------------------------------------------------

func TestRule_ArtifactoryPassword(t *testing.T) {
	cases := []struct {
		payload    string
		shouldFlag bool
	}{
		// True positives — AP[0-9A-F] prefix + 8+ alphanum chars + boundary
		{"AP6xxxxxxxxxx", true},           // start of string, '6' in [0-9A-F]
		{" AP6xxxxxxxxxx", true},          // leading space
		{"=AP6xxxxxxxxxx", true},          // '='
		{":AP6xxxxxxxxxx", true},          // ':'
		{`"AP6xxxxxxxxxx"`, true},         // quoted
		{"APAxxxxxxxxxx", true},           // 'A' in [0-9A-F]
		{"APFxxxxxxxxxx", true},           // 'F' in [0-9A-F]
		{"artif-key:AP6xxxxxxxxxx", true}, // colon separator

		// Boundary negatives — embedded in word
		{"testAP6withinsomeirrelevantstring", false},

		// Too short — < 8 chars after AP[0-9A-F]
		{"AP6xxxxxxx", false}, // 7 chars after AP6

		// Wrong hex digit — 'G' is not in [0-9A-F]
		{"APGxxxxxxxxxx", false},

		// Wrong prefix entirely
		{"BPAxxxxxxxxxx", false},
	}

	for _, tc := range cases {
		t.Run(tc.payload, func(t *testing.T) {
			got := matchesRule(t, "artifactory_password", tc.payload)
			if got != tc.shouldFlag {
				t.Errorf("artifactory_password: matchesRule(%q) = %v, want %v",
					tc.payload, got, tc.shouldFlag)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Azure Storage Key (azure_storage_key)
// ---------------------------------------------------------------------------

func TestRule_AzureStorageKey(t *testing.T) {
	// True positive: AccountKey= followed by exactly 88 base64 chars.
	// From detect-secrets fixtures.
	validKey := "lJzRc1YdHaAA2KCNJJ1tkYwF/+mKK6Ygw0NGe170Xu592euJv2wYUtBlV8z+qnlcNQSnIYVTkLWntUO1F8j8rQ=="

	cases := []struct {
		payload    string
		shouldFlag bool
	}{
		{"AccountKey=" + validKey, true},

		// Too short — only 87 base64 chars
		{"AccountKey=" + validKey[:87], false},

		// Too long — 89 chars (still matches because regex requires exactly 88 via {88})
		// Actually {88} means exactly 88, so 89 still matches (the first 88 are consumed).
		// This is acceptable — the regex matches a prefix of 88.

		// Wrong key prefix
		{"StorageKey=" + validKey, false},
		{"accountkey=" + validKey, false}, // case-sensitive

		// Missing prefix entirely
		{validKey, false},
	}

	for _, tc := range cases {
		t.Run(tc.payload, func(t *testing.T) {
			got := matchesRule(t, "azure_storage_key", tc.payload)
			if got != tc.shouldFlag {
				t.Errorf("azure_storage_key: matchesRule(%q) = %v, want %v",
					tc.payload, got, tc.shouldFlag)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Discord Bot Token (discord_bot_token)
// ---------------------------------------------------------------------------

func TestRule_DiscordBotToken(t *testing.T) {
	cases := []struct {
		payload    string
		shouldFlag bool
	}{
		// True positives — from detect-secrets fixtures
		{"MTk4NjIyNDgzNDcxOTI1MjQ4.Cl2FMQ.ZnCjm1XVW7vRze4b7Cq4se7kKWs", true}, // 24.6.27
		{"Nzk5MjgxNDk0NDc2NDU1OTg3.YABS5g.2lmzECVlZv3vv6miVnUaKPQi2wI", true}, // 24.6.27
		{"MZ1yGvKTjE0rY0cV8i47CjAa.uRHQPq.Xb1Mk2nEhe-4iUcrGOuegj57zMC", true}, // 24.6.27
		{"OTUyNED5MDk2MTMxNzc2MkEz.YjESug.UNf-1GhsIG8zWT409q2C7Bh_zWQ", true}, // 24.6.27
		// Third segment is 38 chars. The pattern requires exactly {27} (narrowed
		// from {27,} in v2.0.0), but matchesRule uses an unanchored search, so the
		// engine still finds a valid 27-char run inside the longer segment → match.
		{"OTUyNED5MDk2MTMxNzc2MkEz.GSroKE.g2MTwve8OnUAAByz8KV_ZTV1Ipzg4o_NmQWUMs", true},
		// First segment is 26 chars total: leading 'M' + 25-char body, and 25 is
		// within the body quantifier [a-zA-Z0-9_-]{23,25}.
		{"MTAyOTQ4MTN5OTU5MTDwMEcxNg.GSwJyi.sbaw8msOR3Wi6vPUzeIWy_P0vJbB0UuRVjH8l8", true},

		// Negatives — all segments short (23.5.26)
		{"MZ1yGvKTj0rY0cV8i47CjAa.uHQPq.Xb1Mk2nEhe-4icrGOuegj57zMC", false},

		// First segment short (23.6.27)
		{"MZ1yGvKTj0rY0cV8i47CjAa.uRHQPq.Xb1Mk2nEhe-4iUcrGOuegj57zMC", false},

		// Middle segment short (24.5.27)
		{"MZ1yGvKTjE0rY0cV8i47CjAa.uHQPq.Xb1Mk2nEhe-4iUcrGOuegj57zMC", false},

		// Last segment short (24.6.26)
		{"MZ1yGvKTjE0rY0cV8i47CjAa.uRHQPq.Xb1Mk2nEhe-4iUcrGOuegj57zM", false},

		// Invalid char in last segment (comma is invalid)
		{"MZ1yGvKTjE0rY0cV8i47CjAa.uRHQPq.Xb1Mk2nEhe,4iUcrGOuegj57zMC", false},

		// Wrong first character ('P' is not M/N/O)
		{"PZ1yGvKTjE0rY0cV8i47CjAa.uRHQPq.Xb1Mk2nEhe-4iUcrGOuegj57zMC", false},
	}

	for _, tc := range cases {
		t.Run(tc.payload, func(t *testing.T) {
			got := matchesRule(t, "discord_bot_token", tc.payload)
			if got != tc.shouldFlag {
				t.Errorf("discord_bot_token: matchesRule(%q) = %v, want %v",
					tc.payload, got, tc.shouldFlag)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// GitLab PAT (gitlab_pat)
// ---------------------------------------------------------------------------

func TestRule_GitLabPAT(t *testing.T) {
	cases := []struct {
		payload    string
		shouldFlag bool
	}{
		// True positives — valid prefix + 20–50 chars + word boundary
		{"glpat-hellOworld380_testin ", true},  // trailing space = non-word char
		{"glpat-hellOworld380_testin\n", true}, // newline
		{"gldt-HwllOuhfw-wu0rlD_yepXXXX ", true},
		{"glft-HwllOuhfw-wu0rlD_yepXXXX ", true},
		{"glsoat-PREfix_helloworld380_testin_pretty_long_token_ ", true}, // 50 chars, trailing space
		{"glrt-HwllOuhfw-wu0rlD_yepXXXX ", true},

		// End of string is a valid boundary
		{"glpat-hellOworld380_testin", true},

		// Too short — < 20 chars after prefix
		{"gldt-seems_too000Sshor", false}, // 19 chars

		// Too long — > 50 chars after prefix (+ word char = still bounded by {20,50})
		{"glsoat-PREfix_helloworld380_testin_pretty_long_token_long_x", false}, // 51 chars + 'x'

		// Wrong separator (underscore instead of dash)
		{"glpat_hellOworld380_testin", false},

		// Invalid prefix
		{"foo-hello-world80_testin_abcdefghij ", false},

		// GitHub token — wrong platform
		{"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", false},

		// Space in token body — breaks token
		{"glpat-hellOWorld380 testin", false},
	}

	for _, tc := range cases {
		t.Run(tc.payload, func(t *testing.T) {
			got := matchesRule(t, "gitlab_pat", tc.payload)
			if got != tc.shouldFlag {
				t.Errorf("gitlab_pat: matchesRule(%q) = %v, want %v",
					tc.payload, got, tc.shouldFlag)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// GitLab Runner Registration Token (gitlab_runner_registration)
// ---------------------------------------------------------------------------

func TestRule_GitLabRunnerRegistration(t *testing.T) {
	cases := []struct {
		payload    string
		shouldFlag bool
	}{
		// True positives
		{"GR1348941PREfix_helloworld380 ", true},
		{"GR1348941PREfix_helloworld380_testin_pretty_long_token_lon ", true}, // 50 chars, space

		// End of string
		{"GR1348941PREfix_helloworld380", true},

		// Too short — < 20 chars after GR1348941
		{"GR1348941helloWord0", false}, // 10 chars only

		// Too long — 51 chars after prefix + word char
		{"GR1348941PREfix_helloworld380_testin_pretty_long_token_long_x", false},

		// Wrong prefix
		{"GR1238941PREfix_helloworld380", false},
	}

	for _, tc := range cases {
		t.Run(tc.payload, func(t *testing.T) {
			got := matchesRule(t, "gitlab_runner_registration", tc.payload)
			if got != tc.shouldFlag {
				t.Errorf("gitlab_runner_registration: matchesRule(%q) = %v, want %v",
					tc.payload, got, tc.shouldFlag)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// GitLab CI/CD Token (gitlab_cicd)
// ---------------------------------------------------------------------------

func TestRule_GitLabCICD(t *testing.T) {
	cases := []struct {
		payload    string
		shouldFlag bool
	}{
		// True positives — with and without partition_id
		{"glcbt-PREfix_helloworld380_test ", true},  // no partition_id
		{"glcbt-ab_PREfix_helloworld380_te ", true}, // with 2-char hex partition_id
		{"glcbt-FF_PREfix_helloworld380_te ", true}, // uppercase hex ok
		{"glcbt-PREfix_helloworld380_test", true},   // end of string

		// Too short
		{"glcbt-short_12345678 ", false}, // < 20 chars

		// Too long — 51 chars + word char
		{"glcbt-PREfix_helloworld380_testin_pretty_long_token_long_x", false},

		// Wrong prefix
		{"glact-PREfix_helloworld380_test ", false},

		// Invalid partition_id (3 chars instead of 2)
		// Note: with 'abc_' as prefix, 'a' is valid hex but 'abc_' is not '[0-9a-fA-F]{2}_'
		// The regex tries both paths (with/without partition). 'abc' does not match '[0-9a-fA-F]{2}_'
		// so it falls through to matching the whole thing as the token body.
		// This is fine — the test below exercises the wrong-prefix case, not ambiguous partition.
	}

	for _, tc := range cases {
		t.Run(tc.payload, func(t *testing.T) {
			got := matchesRule(t, "gitlab_cicd", tc.payload)
			if got != tc.shouldFlag {
				t.Errorf("gitlab_cicd: matchesRule(%q) = %v, want %v",
					tc.payload, got, tc.shouldFlag)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// GitLab Incoming Mail Token (gitlab_incoming_mail)
// ---------------------------------------------------------------------------

func TestRule_GitLabIncomingMail(t *testing.T) {
	cases := []struct {
		payload    string
		shouldFlag bool
	}{
		// True positives — exactly 25 chars after glimt-
		{"glimt-abcdefghij1234567890abcde ", true}, // trailing space
		{"glimt-abcdefghij1234567890abcde", true},  // end of string
		{"glimt-ABCDEFGHIJ1234567890ABCDE ", true}, // uppercase

		// Wrong length — 24 chars (too short)
		{"glimt-abcdefghij1234567890abcd ", false},

		// Wrong length — 26 chars (too long — {25} is exact, so 26th char starts new match)
		// Actually {25} matches exactly 25. The 26th being a word char triggers boundary failure.
		{"glimt-abcdefghij1234567890abcdef", false}, // 26 chars + end-of-string: boundary check fails

		// Wrong prefix
		{"glimb-abcdefghij1234567890abcde ", false},
	}

	for _, tc := range cases {
		t.Run(tc.payload, func(t *testing.T) {
			got := matchesRule(t, "gitlab_incoming_mail", tc.payload)
			if got != tc.shouldFlag {
				t.Errorf("gitlab_incoming_mail: matchesRule(%q) = %v, want %v",
					tc.payload, got, tc.shouldFlag)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// GitLab Trigger Token (gitlab_trigger)
// ---------------------------------------------------------------------------

func TestRule_GitLabTrigger(t *testing.T) {
	// Build a valid 40-char suffix.
	suffix40 := strings.Repeat("a", 40)

	cases := []struct {
		payload    string
		shouldFlag bool
	}{
		// True positives
		{"glptt-" + suffix40 + " ", true}, // trailing space
		{"glptt-" + suffix40, true},       // end of string

		// Too short — 39 chars
		{"glptt-" + suffix40[:39] + " ", false},

		// Too long — 41 chars + word char (41st is 'a' = word char, boundary fails)
		{"glptt-" + suffix40 + "a", false},

		// Wrong prefix
		{"glptx-" + suffix40 + " ", false},
	}

	for _, tc := range cases {
		t.Run(tc.payload, func(t *testing.T) {
			got := matchesRule(t, "gitlab_trigger", tc.payload)
			if got != tc.shouldFlag {
				t.Errorf("gitlab_trigger: matchesRule(%q) = %v, want %v",
					tc.payload, got, tc.shouldFlag)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// GitLab Agent Token (gitlab_agent)
// ---------------------------------------------------------------------------

func TestRule_GitLabAgent(t *testing.T) {
	// Build a valid 50-char suffix.
	suffix50 := strings.Repeat("a", 50)

	cases := []struct {
		payload    string
		shouldFlag bool
	}{
		// True positives — 50+ chars
		{"glagent-" + suffix50 + " ", true},     // 50 chars, trailing space
		{"glagent-" + suffix50, true},           // end of string
		{"glagent-" + suffix50 + "bcde ", true}, // 54 chars — still valid

		// Too short — 49 chars
		{"glagent-" + suffix50[:49] + " ", false},

		// Wrong prefix
		{"glagenn-" + suffix50 + " ", false},
	}

	for _, tc := range cases {
		t.Run(tc.payload, func(t *testing.T) {
			got := matchesRule(t, "gitlab_agent", tc.payload)
			if got != tc.shouldFlag {
				t.Errorf("gitlab_agent: matchesRule(%q) = %v, want %v",
					tc.payload, got, tc.shouldFlag)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// GitLab OAuth Application Secret (gitlab_oauth_secret)
// ---------------------------------------------------------------------------

func TestRule_GitLabOAuthSecret(t *testing.T) {
	// Build a valid 64-char suffix.
	suffix64 := strings.Repeat("a", 64)

	cases := []struct {
		payload    string
		shouldFlag bool
	}{
		// True positives
		{"gloas-" + suffix64 + " ", true}, // trailing space
		{"gloas-" + suffix64, true},       // end of string

		// Too short — 63 chars
		{"gloas-" + suffix64[:63] + " ", false},

		// Too long — 65 chars + word char (boundary fails)
		{"gloas-" + suffix64 + "a", false},

		// Wrong prefix
		{"gloat-" + suffix64 + " ", false},
	}

	for _, tc := range cases {
		t.Run(tc.payload, func(t *testing.T) {
			got := matchesRule(t, "gitlab_oauth_secret", tc.payload)
			if got != tc.shouldFlag {
				t.Errorf("gitlab_oauth_secret: matchesRule(%q) = %v, want %v",
					tc.payload, got, tc.shouldFlag)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Mailchimp API Key (mailchimp_api_key)
// ---------------------------------------------------------------------------

func TestRule_MailchimpAPIKey(t *testing.T) {
	cases := []struct {
		payload    string
		shouldFlag bool
	}{
		// True positives — 32 lowercase hex chars + -us + 1–2 digits + non-digit/end
		{"343ea45721923ed956e2b38c31db76aa-us30", true}, // us30, end of string
		{"a2937653ed38c31a43ea46e2b19257db-us2", true},  // us2, end of string
		{"343ea45721923ed956e2b38c31db76aa-us1 ", true}, // trailing space

		// Wrong datacenter prefix (no "us")
		{"3ea4572956e2b381923ed34c31db76aa-2", false},    // missing "us"
		{"aea462953eb192d38c31a433e76257db-al32", false}, // "al" not "us"

		// Uppercase chars in hex portion (regex is [0-9a-z] lowercase only)
		{"9276a43e2951aa46e2b1c33ED38357DB-us2", false},

		// Too short — < 32 hex chars
		{"3a5633e829d3c71-us2", false},
	}

	for _, tc := range cases {
		t.Run(tc.payload, func(t *testing.T) {
			got := matchesRule(t, "mailchimp_api_key", tc.payload)
			if got != tc.shouldFlag {
				t.Errorf("mailchimp_api_key: matchesRule(%q) = %v, want %v",
					tc.payload, got, tc.shouldFlag)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// npm Auth Token (npm_auth_token)
// ---------------------------------------------------------------------------

func TestRule_NpmAuthToken(t *testing.T) {
	cases := []struct {
		payload    string
		shouldFlag bool
	}{
		// True positives — UUID format
		{"//registry.npmjs.org/:_authToken=743b294a-cd03-11ec-9d64-0242ac120002", true},
		{"//registry.npmjs.org/:_authToken=346a14f2-a672-4668-a892-956a462ab56e", true},
		// Space before UUID is allowed
		{"//registry.npmjs.org/:_authToken= 743b294a-cd03-11ec-9d64-0242ac120002", true},
		// npm_ prefix format
		{"//registry.npmjs.org/:_authToken=npm_xxxxxxxxxxx", true},

		// Missing '/:' — only ':_authToken' without slash
		{"//registry.npmjs.org:_authToken=743b294a-cd03-11ec-9d64-0242ac120002", false},

		// Missing '//' prefix
		{"registry.npmjs.org/:_authToken=743b294a-cd03-11ec-9d64-0242ac120002", false},

		// No registry URL (just '///')
		{"///:_authToken=743b294a-cd03-11ec-9d64-0242ac120002", false},

		// Missing '//' prefix entirely
		{"_authToken=743b294a-cd03-11ec-9d64-0242ac120002", false},

		// Env var placeholder — MUST NOT flag (the value is ${NPM_TOKEN}, not a literal)
		{"//registry.npmjs.org/:_authToken=${NPM_TOKEN}", false},

		// Unrelated
		{"foo", false},
	}

	for _, tc := range cases {
		t.Run(tc.payload, func(t *testing.T) {
			got := matchesRule(t, "npm_auth_token", tc.payload)
			if got != tc.shouldFlag {
				t.Errorf("npm_auth_token: matchesRule(%q) = %v, want %v",
					tc.payload, got, tc.shouldFlag)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// PyPI Production Token (pypi_api_token)
// ---------------------------------------------------------------------------

func TestRule_PyPIToken(t *testing.T) {
	// Full token from detect-secrets test fixtures.
	validPyPI := "pypi-AgEIcHlwaS5vcmcCJDU3OTM1MjliLWIyYTYtNDEwOC05NzRkLTM0MjNiNmEwNWIzYgACF1sxLFsibWluaW1hbC1wcm9qZWN0Il1dAAIsWzIsWyJjYWY4OTAwZi0xNDMwLTRiYQstYmFmMi1mMDE3OGIyNWZhNTkiXV0AAAYgh2UINPjWBDwT0r3tQ1o5oZyswcjN0-IluP6z34SX3KM"

	cases := []struct {
		payload    string
		shouldFlag bool
	}{
		{validPyPI, true},

		// Too short — < 70 chars after fixed prefix "pypi-AgEIcHlwaS5vcmc"
		{"pypi-AgEIcHlwaS5vcmcCJDU3OTM1MjliLWIyYTYtNDEwOC05NzRkLTM0MjNiNmEwNWIzYgACF1sxLFsibWluaW1h", false},
		// Note: the above is ~71 chars total but the part after "pypi-AgEIcHlwaS5vcmc" is only ~64 chars
		// Let me use a clearly too-short case:
		{"pypi-AgEIcHlwaS5vcmcABCDEFGHIJ", false}, // only 10 chars after fixed prefix

		// Wrong prefix (test.pypi.org token) — does NOT match pypi_api_token
		{"pypi-AgENdGVzdC5weXBpLm9yZwIkN2YxOWZhOWEt", false},

		// Not a pypi token
		{"sk-ant-api03-test", false},
	}

	for _, tc := range cases {
		t.Run(tc.payload, func(t *testing.T) {
			got := matchesRule(t, "pypi_api_token", tc.payload)
			if got != tc.shouldFlag {
				t.Errorf("pypi_api_token: matchesRule(%q) = %v, want %v",
					tc.payload, got, tc.shouldFlag)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// PyPI Test Token (pypi_test_token)
// ---------------------------------------------------------------------------

func TestRule_PyPITestToken(t *testing.T) {
	// Full token from detect-secrets test fixtures.
	validTestPyPI := "pypi-AgENdGVzdC5weXBpLm9yZwIkN2YxOWZhOWEtY2FjYS00MGZhLTj2MGEtODFjMnE2MjdmMzY0AAIqWzMsImJlM2FiOWI5LTRmYUTnNEg4ZS04Mjk0LWFlY2Y2NWYzNGYzNyJdAAAGIMb5Hb8nVvhcAizcVVzA-bKKnwN7Pe0RmgPRCvrPwyJf"

	cases := []struct {
		payload    string
		shouldFlag bool
	}{
		{validTestPyPI, true},

		// Too short — < 70 chars after "pypi-AgENdGVzdC5weXBpLm9yZw"
		{"pypi-AgENdGVzdC5weXBpLm9yZwABCDEFGHIJ", false}, // only 10 chars after prefix

		// Wrong prefix (pypi.org token) — does NOT match pypi_test_token
		{"pypi-AgEIcHlwaS5vcmcABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwx", false},

		// Not a pypi token
		{"sk-ant-api03-test", false},
	}

	for _, tc := range cases {
		t.Run(tc.payload, func(t *testing.T) {
			got := matchesRule(t, "pypi_test_token", tc.payload)
			if got != tc.shouldFlag {
				t.Errorf("pypi_test_token: matchesRule(%q) = %v, want %v",
					tc.payload, got, tc.shouldFlag)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Square OAuth Secret (square_oauth_secret)
// ---------------------------------------------------------------------------

func TestRule_SquareOAuthSecret(t *testing.T) {
	cases := []struct {
		payload    string
		shouldFlag bool
	}{
		// True positive — from detect-secrets fixtures (exactly 43 chars after sq0csp-)
		// ABCDEFGHIJK=11, _=1, LMNOPQRSTUVWXYZ=15, -=1, 0123456789=10, \=1, abcd=4 → 43 chars
		{"square_oauth = sq0csp-ABCDEFGHIJK_LMNOPQRSTUVWXYZ-0123456789\\abcd", true},
		// Same token, no surrounding context
		{"sq0csp-ABCDEFGHIJK_LMNOPQRSTUVWXYZ-0123456789\\abcd", true}, // 43 chars

		// Too short — 41 chars (only \ab, need \abcd)
		{"sq0csp-ABCDEFGHIJK_LMNOPQRSTUVWXYZ-0123456789\\ab", false},

		// Too short — 6 chars after prefix
		{"sq0csp-ABCDEFGHIJK_LMNOPQRSTUVWXYZ-012345", false},

		// Too long — 44 chars (but {43} matches exactly 43, so the first 43 are consumed and match)
		// The regex uses {43} which is exact, so a 44-char suffix would still match the first 43.
		// This is acceptable behaviour.

		// Wrong prefix
		{"sq0ctp-ABCDEFGHIJK_LMNOPQRSTUVWXYZ-0123456789\\ab", false},
		{"sq0csp_ABCDEFGHIJK_LMNOPQRSTUVWXYZ-0123456789\\ab", false}, // underscore instead of dash
	}

	for _, tc := range cases {
		t.Run(tc.payload, func(t *testing.T) {
			got := matchesRule(t, "square_oauth_secret", tc.payload)
			if got != tc.shouldFlag {
				t.Errorf("square_oauth_secret: matchesRule(%q) = %v, want %v",
					tc.payload, got, tc.shouldFlag)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Telegram Bot Token (telegram_bot_token)
// ---------------------------------------------------------------------------

func TestRule_TelegramBotToken(t *testing.T) {
	cases := []struct {
		payload    string
		shouldFlag bool
	}{
		// True positives — from detect-secrets fixtures
		{"110201543:AAHdqTcvCH1vGWJxfSe1ofSAs0K5PALDsaw", true},  // 9-digit ID
		{"7213808860:AAH1bjqpKKW3maRSPAxzIU-0v6xNuq2-NjM", true}, // 10-digit ID
		{" 110201543:AAHdqTcvCH1vGWJxfSe1ofSAs0K5PALDsaw", true}, // leading space

		// 'bot' prefix — MUST NOT flag (detect-secrets compat: leading alpha before digits)
		{"bot110201543:AAHdqTcvCH1vGWJxfSe1ofSAs0K5PALDsaw", false},

		// Non-numeric ID — MUST NOT flag
		{"foo:AAH1bjqpKKW3maRSPAxzIU-0v6xNuq2-NjM", false},

		// Unrelated
		{"foo", false},

		// AWS ARN false-positive guard — MUST NOT flag
		// The colon-separated segments in an ARN include non-35-char sequences.
		{"arn:aws:sns:aaa:111122223333:aaaaaaaaaaaaaaaaaaassssssddddddddddddd", false},

		// Too short — only 7 digits (min is 8)
		{"1234567:AAHdqTcvCH1vGWJxfSe1ofSAs0K5PALDsaw", false},

		// Token part too short — only 34 chars (min is 35)
		{"110201543:AAHdqTcvCH1vGWJxfSe1ofSAs0K5PALDs", false},
	}

	for _, tc := range cases {
		t.Run(tc.payload, func(t *testing.T) {
			got := matchesRule(t, "telegram_bot_token", tc.payload)
			if got != tc.shouldFlag {
				t.Errorf("telegram_bot_token: matchesRule(%q) = %v, want %v",
					tc.payload, got, tc.shouldFlag)
			}
		})
	}
}

func TestRule_AccessCode(t *testing.T) {
	cases := []struct {
		payload    string
		shouldFlag bool
	}{
		{"Access code: ABCD-1234", true},
		{"verification code is 8K3P2Q", true},
		{"otp code 123456", true},
		{"device code=Z9X8-C7V6", true},
		{"status code: 403", false},
		{"exit code 1", false},
		{"verification code: short", false},
	}

	for _, tc := range cases {
		t.Run(tc.payload, func(t *testing.T) {
			got := matchesRule(t, "access_code", tc.payload)
			if got != tc.shouldFlag {
				t.Errorf("access_code: matchesRule(%q) = %v, want %v", tc.payload, got, tc.shouldFlag)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestRules_AllIDsHaveTestCoverage — extended to include all 17 new rule IDs
// ---------------------------------------------------------------------------

// testCoverageForNewRules is a compile-time-visible list of all 17 new rule IDs.
// TestRules_AllIDsHaveTestCoverage below uses this to extend the coverage check.
var newRuleIDs = []string{
	"artifactory_api_token",
	"artifactory_password",
	"azure_storage_key",
	"discord_bot_token",
	"gitlab_pat",
	"gitlab_runner_registration",
	"gitlab_cicd",
	"gitlab_incoming_mail",
	"gitlab_trigger",
	"gitlab_agent",
	"gitlab_oauth_secret",
	"mailchimp_api_key",
	"npm_auth_token",
	"pypi_api_token",
	"pypi_test_token",
	"square_oauth_secret",
	"telegram_bot_token",
}

// TestRules_NewRuleIDsInTable verifies all 17 new rule IDs are present in the Rules table.
// This is the companion to TestRules_AllIDsHaveTestCoverage in redactor_test.go —
// that test handles the existing 21 rules; this one handles the 17 new rules.
func TestRules_NewRuleIDsInTable(t *testing.T) {
	ruleIDs := make(map[string]bool, len(Rules))
	for _, r := range Rules {
		ruleIDs[r.ID] = true
	}

	for _, id := range newRuleIDs {
		if !ruleIDs[id] {
			t.Errorf("new rule %q is not present in Rules table — was it added to rules.go?", id)
		}
	}
}

// TestRules_AllIDsHaveTestCoverageExtended extends the existing coverage check in
// redactor_test.go to include all 17 new rule IDs from this file.
func TestRules_AllIDsHaveTestCoverageExtended(t *testing.T) {
	ruleIDs := make(map[string]bool, len(Rules))
	for _, r := range Rules {
		ruleIDs[r.ID] = false
	}

	// Mark existing rules as covered (same as TestRules_AllIDsHaveTestCoverage).
	for _, id := range []string{
		"anthropic_key", "openai_key", "github_pat", "aws_access_key",
		"aws_secret_key", "stripe_key", "twilio_key", "twilio_auth_token",
		"sendgrid_key", "slack_token", "slack_webhook_url",
		"jwt_token", "private_key_block",
		"generic_api_key", "bearer_token", "basic_auth", "basic_auth_uri",
		"access_code",
		"email", "phone_us", "ssn", "credit_card", "ip_address",
		"unix_home_path", "unix_home_path_spaced", "windows_home_path", "windows_home_path_spaced",
		"claude_project_slug", "peasant_host_slug",
	} {
		ruleIDs[id] = true
	}

	// Mark new 17 rules as covered (each has a dedicated test func above).
	for _, id := range newRuleIDs {
		ruleIDs[id] = true
	}

	// Mark the 10 CategoryProject rules as covered (tested in project_rules_test.go).
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
// Residue rule positive-trigger tests for the 17 new residue rules
// ---------------------------------------------------------------------------

// TestResidueRules_NewPositiveTriggers verifies that each of the 17 new residue rules
// fires on a plausible near-miss input (broader/relaxed pattern of the primary rule).
// These are advisory-only rules that help catch patterns that slipped through primary redaction.
func TestResidueRules_NewPositiveTriggers(t *testing.T) {
	cases := []struct {
		ruleID string
		input  string
	}{
		{
			ruleID: "residue_artifactory_api_token",
			input:  "header: AKCshort1234567890",
		},
		{
			ruleID: "residue_artifactory_password",
			input:  "pass: AP6short12345",
		},
		{
			ruleID: "residue_azure_storage_key",
			input:  "AccountKey=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567",
		},
		{
			// Residue pattern: [MNO]{20+}.[5+].[20+} — use actual test fixture from detect-secrets
			ruleID: "residue_discord_bot_token",
			input:  "MTk4NjIyNDgzNDcxOTI1MjQ4.Cl2FMQ.ZnCjm1XVW7vRze4b7Cq4se7kKWs",
		},
		{
			ruleID: "residue_gitlab_pat",
			input:  "glpat-short1234567890short",
		},
		{
			ruleID: "residue_gitlab_runner_registration",
			input:  "GR1348941short1234567890",
		},
		{
			ruleID: "residue_gitlab_cicd",
			input:  "glcbt-shorttoken1234567890shortX",
		},
		{
			ruleID: "residue_gitlab_incoming_mail",
			input:  "glimt-shorttoken12345678901234",
		},
		{
			ruleID: "residue_gitlab_trigger",
			input:  "glptt-shorttoken12345678901234567890123456789012",
		},
		{
			ruleID: "residue_gitlab_agent",
			input:  "glagent-shortagenttoken123456789012345678901234567890X",
		},
		{
			ruleID: "residue_gitlab_oauth_secret",
			input:  "gloas-shortoauthsecrettoken123456789012345678901234567890ABCDE",
		},
		{
			// Residue mailchimp requires {28,} hex chars; use 28 chars (shorter than main rule's 32)
			ruleID: "residue_mailchimp_api_key",
			input:  "343ea4572192ed956e2b38c31234-us2",
		},
		{
			ruleID: "residue_npm_auth_token",
			input:  "/:_authToken=npm_shorttoken",
		},
		{
			ruleID: "residue_pypi_token",
			input:  "pypi-AgEIshortprefixtoken1234567890123456789012345678901234567890",
		},
		{
			ruleID: "residue_pypi_test_token",
			input:  "pypi-AgENshortprefixtoken1234567890123456789012345678901234567890",
		},
		{
			// Residue square requires {30,} chars after prefix; use 30 chars
			ruleID: "residue_square_oauth_secret",
			input:  "sq0csp-ABCDEFGHIJK_LMNOPQRSTUVWXYZ123",
		},
		{
			ruleID: "residue_telegram_bot_token",
			input:  "1102015:AAHdqTcvCH1vGWJxfSe1ofSAs0K5PA",
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
				t.Errorf("residue rule %q did not trigger on input %q; got warnings %v",
					tc.ruleID, tc.input, warnings)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// FilterFn + awsSecretKeyFilter
// ---------------------------------------------------------------------------

// detectsAWSSecretKey is a test helper that runs Detect on input and returns
// true if any Match with Rule == "aws_secret_key" is returned.
// It uses mustNewRedactor with Minimal level (secrets are active at all levels).
func detectsAWSSecretKey(t *testing.T, input string) bool {
	t.Helper()
	r := mustNewRedactor(t, Minimal, nil)
	for _, m := range r.Detect(input) {
		if m.Rule == "aws_secret_key" {
			return true
		}
	}
	return false
}

// TestAwsSecretKeyFilter_BDDCriteria covers the six documented AWS context
// filtering behaviors.
func TestAwsSecretKeyFilter_BDDCriteria(t *testing.T) {
	cases := []struct {
		name       string
		input      string
		wantDetect bool
	}{
		{
			// BDD-1: File path — no AWS keywords or AKIA prefix nearby → NOT matched.
			// "nttea/codebases/dayvidpham/bestiary/main." is a path-shaped string with
			// 4 slash-separated segments. The aws_secret_key regex may fire on a
			// base64-like substring, but the filter must reject it.
			name:       "file_path_no_context",
			input:      "nttea/codebases/dayvidpham/bestiary/main.",
			wantDetect: false,
		},
		{
			// BDD-2: Real AWS key with "/" chars in context → DOES match.
			// wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY is 40 chars of base64.
			// "aws_secret_access_key" is in the keyword list (contains "aws").
			name:       "real_aws_key_with_context",
			input:      `aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`,
			wantDetect: true,
		},
		{
			// BDD-3: AKIA access key ID nearby + 40-char base64 (no keywords) → DOES match.
			// The aws_access_key rule pattern matches "AKIAIOSFODNN7EXAMPLE...", which
			// triggers the AKIA context check.
			name:       "akia_nearby_no_keywords",
			input:      "AKIAIOSFODNN7EXAMPLE1234 wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			wantDetect: true,
		},
		{
			// BDD-4: Sequential string → NOT matched.
			// "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd" is 40 chars of sequential ASCII.
			name:       "sequential_string",
			input:      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd",
			wantDetect: false,
		},
		{
			// BDD-5: Bare base64, no AWS context → NOT matched.
			// "5Y9syZ8W5sLJHHGM7EqzeVBf37Sq/f4k1p0YAQAA" is 40 chars of random base64.
			// No keywords, no AKIA prefix within 200 chars.
			name:       "bare_base64_no_context",
			input:      "5Y9syZ8W5sLJHHGM7EqzeVBf37Sq/f4k1p0YAQAA",
			wantDetect: false,
		},
		{
			// BDD-6: Real AWS key at end of string (no trailing boundary char) → DOES match.
			// extractBase64Body must handle the zero-width group 2 case correctly.
			name:       "real_aws_key_end_of_string_with_context",
			input:      "aws_secret_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			wantDetect: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detectsAWSSecretKey(t, tc.input)
			if got != tc.wantDetect {
				t.Errorf("detectsAWSSecretKey(%q) = %v, want %v", tc.input, got, tc.wantDetect)
			}
		})
	}
}

// TestExtractBase64Body covers the helper function directly.
func TestExtractBase64Body(t *testing.T) {
	cases := []struct {
		matched string
		want    string
	}{
		// Trailing boundary char (non-base64): stripped.
		{"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY ", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
		{"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
		{"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY:", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
		// Trailing '=' (valid base64 padding): NOT stripped.
		{"5Y9syZ8W5sLJHHGM7EqzeVBf37Sq/f4k1p0YAQ==", "5Y9syZ8W5sLJHHGM7EqzeVBf37Sq/f4k1p0YAQ=="},
		// End-of-string (full base64 body, no boundary): returned unchanged.
		{"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
		// Empty string: returned unchanged.
		{"", ""},
	}

	for _, tc := range cases {
		t.Run(tc.matched, func(t *testing.T) {
			got := extractBase64Body(tc.matched)
			if got != tc.want {
				t.Errorf("extractBase64Body(%q) = %q, want %q", tc.matched, got, tc.want)
			}
		})
	}
}

// TestFindRuleByID verifies the helper finds and returns rules correctly.
func TestFindRuleByID(t *testing.T) {
	// Known rule: should be found.
	r := findRuleByID("aws_access_key")
	if r == nil {
		t.Fatal("findRuleByID(\"aws_access_key\") = nil, want non-nil")
	}
	if r.ID != "aws_access_key" {
		t.Errorf("findRuleByID(\"aws_access_key\").ID = %q, want \"aws_access_key\"", r.ID)
	}
	if r.Pattern == nil {
		t.Error("findRuleByID(\"aws_access_key\").Pattern = nil, want compiled regex")
	}

	// Unknown rule: should return nil.
	if got := findRuleByID("nonexistent_rule_xyz"); got != nil {
		t.Errorf("findRuleByID(\"nonexistent_rule_xyz\") = %v, want nil", got)
	}
}

// TestAwsSecretKeyRule_FilterFnWired verifies that the aws_secret_key rule has
// its FilterFn set after package init.
func TestAwsSecretKeyRule_FilterFnWired(t *testing.T) {
	rule := findRuleByID("aws_secret_key")
	if rule == nil {
		t.Fatal("aws_secret_key rule not found in Rules table")
	}
	if rule.FilterFn == nil {
		t.Error("aws_secret_key rule.FilterFn = nil — init() did not wire awsSecretKeyFilter")
	}
}

// TestHomePathSingleSegmentFilters verifies spaced-username prefix rejection and dual-path acceptance.
func TestHomePathSingleSegmentFilters(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		offset  int
		matched string
		want    bool
	}{
		{
			name:    "dual path keeps alice match",
			input:   "Loaded config from /home/alice and /home/bob/x",
			offset:  strings.Index("Loaded config from /home/alice and /home/bob/x", "/home/alice"),
			matched: "/home/alice",
			want:    true,
		},
		{
			name:    "spaced username rejects SFU prefix",
			input:   "/home/SFU CLASSES/project/file.go",
			offset:  strings.Index("/home/SFU CLASSES/project/file.go", "/home/SFU"),
			matched: "/home/SFU",
			want:    false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := unixHomeSingleSegmentFilter(tc.matched, tc.input, tc.offset)
			if got != tc.want {
				t.Errorf("unixHomeSingleSegmentFilter() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestRuleSetVersion_3_0_0 verifies the version bump to 3.0.0.
// 3.0.0 moves git_remote_https / git_remote_ssh / git_branch_output to Maximum-only.
func TestRuleSetVersion_3_0_0(t *testing.T) {
	if RuleSetVersion != "3.0.0" {
		t.Errorf("RuleSetVersion = %q, want \"3.0.0\"", RuleSetVersion)
	}
	if Version() != "3.0.0" {
		t.Errorf("Version() = %q, want \"3.0.0\"", Version())
	}
}

// TestAwsSecretKeyFilter_ContextWindow verifies that keywords outside the 200-char
// window do not cause a match, but keywords inside the window do.
func TestAwsSecretKeyFilter_ContextWindow(t *testing.T) {
	// A 40-char base64 key used to probe the context-window boundary.
	key := "5Y9syZ8W5sLJHHGM7EqzeVBf37Sq0f4k1p0YAQAA"

	// AWS keyword placed exactly 199 chars before the key (inside 200-char window).
	// "aws_secret " is 11 chars; 199 - 11 = 188 padding chars.
	prefix199 := "aws_secret " + strings.Repeat("x", 188)
	insideWindow := prefix199 + key
	if !detectsAWSSecretKey(t, insideWindow) {
		t.Errorf("expected aws_secret_key match when keyword is 199 chars before the match, got none")
	}

	// AWS keyword placed exactly 201 chars before the key (outside window).
	// "aws_secret " is 11 chars; 201 - 11 = 190 padding chars.
	prefix201 := "aws_secret " + strings.Repeat("x", 190)
	outsideWindow := prefix201 + key
	if detectsAWSSecretKey(t, outsideWindow) {
		t.Errorf("expected no aws_secret_key match when keyword is 201 chars before the match, got match")
	}
}
