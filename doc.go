// Package redact detects and replaces sensitive content in session transcripts.
//
// # Input contract
//
// Every string passed to a redaction entry point must be valid UTF-8. The
// package does not validate or normalize input. Invalid UTF-8 is outside the
// contract: Go's regexp treats an invalid byte as U+FFFD, while go-re2 skips it,
// so an invalid byte can reduce the matches and leave content unredacted. The
// ingest boundary owns validation (peasant-labs/peasant#826). The divergence is
// pinned in testdata/engine_invalid_utf8.yaml.
package redact
