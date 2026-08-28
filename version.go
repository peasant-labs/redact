package redact

// RuleSetVersion is the semantic version of the compiled rule set.
//
// Versioning conventions:
//   - Major bump: rule removal or replacement pattern narrowing (potential data-leak regression)
//   - Minor bump: new rules added (more patterns detected)
//   - Patch bump: regex refinement that does not remove or narrow existing coverage
//
// Version history:
//
//	1.0.0 — baseline: 40 rules (31 secrets + 5 PII + 4 paths) migrated from internal/redact
//	1.1.0 — +10 CategoryProject rules (git remotes, import paths, Docker refs, branch names, CI vars)
//	1.2.0 — FilterFn on Rule struct; awsSecretKeyFilter reduces false positives on aws_secret_key;
//	         creditCardFilter rejects UUID-fragment shaped matches; AWS keyword list tightened
//	         (removed bare "secret"/"password"/"aws") to reduce FPs in coding transcripts.
//	2.0.0 — Aligned with Yelp/detect-secrets canonical regexes (MAJOR — narrows coverage):
//	         openai_key requires T3BlbkFJ marker (was wrong "sk-(live|test|proj)-" Stripe-shaped format);
//	         github_pat requires exact {36} body (was {20,}); stripe_key requires exact {24} (was {20,})
//	         and adds rk_ restricted-key prefix; sendgrid_key requires exact {22}.{43} (was {22,}.{22,});
//	         slack_token requires numeric segments (was any alphanumeric); discord_bot_token third
//	         segment exact {27} (was {27,}); +twilio_auth_token (SK{32}); +private_key SSH2 ENCRYPTED
//	         + PuTTY-User-Key-File-2 sentinels. AWS access key prefix list intentionally remains
//	         broader than detect-secrets (covers AGPA/AIDA/AROA/AIPA/ANPA/ANVA in addition to
//	         AKIA/A3T/ASIA) — see rules.go comment for rationale.
//	2.1.0 — Added rules to close detect-secrets coverage gaps: +ABIA, +ACCA prefixes on
//	         aws_access_key (SSO user/role credentials we previously missed);
//	         +slack_webhook_url (incoming-webhook URL form); +basic_auth_uri (RFC 3986
//	         URI-form user:pass@host). JWT regex extended to accept unsigned (2-segment)
//	         JWTs. Imported 220+ verbatim test cases from detect-secrets/tests/plugins/
//	         into the YAML fixture corpus (317 total cases, 89% TP match rate vs
//	         detect-secrets; 11% are documented intentional broader-coverage deviations).
//	2.1.1 — Bugfix release: private_key_block adds dedicated PGP PRIVATE KEY BLOCK arm
//	         (was generating wrong "BEGIN PGP PRIVATE KEY" header without the BLOCK suffix);
//	         jwt_token tightens 2-segment lower bound to {10,} to reject doc-example shapes
//	         like "eyJa.eyJb" while keeping all real unsigned JWT formats; FP corpus runner
//	         now fail-closes on unknown rule IDs; added FP boundary cases for new v2.1.0
//	         rules (slack_webhook_url, basic_auth_uri, twilio_auth_token, jwt_token).
//	2.1.2 — gitlab_agent
//	         now bounds to detect-secrets' 50–1024 range via composed {50,1000}{0,24}
//	         (was open-ended {50,}; RE2 caps single repeats at 1000), rejecting 1025+
//	         char tokens; basic_auth_uri excludes template braces { } so
//	         "https://{user}:{pass}@host" no longer matches; removed dead looksLikeFilePath
//	         helper; rule-count comments replaced by TestRules_CountByCategory; misc test
//	         comment/fixture corrections (Discord {27} mechanism, fp_/tp_ naming, fixture
//	         organization). No new rules; two minor coverage narrowings (glagent upper
//	         bound, basic_auth_uri templates).
//	2.2.0 — Added access_code rule to redact short-lived login/verification/device
//	         codes that appear in transcript text (e.g. "Access code: ABCD-1234").
//	2.2.2 — Bugfix: restore correct redaction when two home paths appear on one line
//	         without Perl lookahead (unsupported by Go regexp). Uses single-segment
//	         rules plus spaced-username companion rules and FilterFn prefix rejection.
//	3.0.0 — git_remote_https / git_remote_ssh / git_branch_output moved to Maximum-only
//	         via per-rule minimum levels; Standard no longer redacts git URLs or branch names.
//	3.1.0 — a redacted path keeps its last folder and replaces everything above it
//	         with one <PATH> placeholder, in the slash, single-dash and double-dash
//	         forms; the prefixes come from every value the session records, the
//	         project and host slugs and Windows paths included, not from the
//	         working directory alone; a slug is read by the shape of its field;
//	         the fallback slug rules fire on a machine-name-prefixed slug; titles use the same form and stored
//	         two-placeholder values converge on it.
const RuleSetVersion = "3.1.0"

// Version returns the rule set version string.
// It can be called without instantiating a Redactor.
func Version() string { return RuleSetVersion }
