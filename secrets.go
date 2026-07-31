// Package redact provides privacy-preserving transcript redaction.
// SecretDetector identifies API keys, tokens, passwords, and other
// secrets in session transcripts using regex patterns.
package redact

// SecretDetector finds and redacts secret values in text.
type SecretDetector struct{}
