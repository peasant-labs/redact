package redact

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
)

const (
	// DefaultScannerInitBuf is the initial buffer size for the JSONL scanner.
	// Matches the previous internal/defaults.ScannerInitBuf value.
	DefaultScannerInitBuf = 64 * 1024 // 64 KiB

	// DefaultScannerMaxLine is the maximum line size for the JSONL scanner.
	// Matches the previous internal/defaults.ScannerMaxLine value.
	DefaultScannerMaxLine = 10 * 1024 * 1024 // 10 MiB
)

// JSONRedactor is the minimal interface for transcript redaction.
// Both redact.Redactor and ingest.TextRedactor satisfy this.
type JSONRedactor interface {
	RedactJSON(value any) any
}

// RedactJSONLBytes processes a JSONL byte slice line by line, applying RedactJSON
// to each decoded line and marshalling back. Unparseable lines pass through unchanged.
//
// Uses bufio.Scanner with ScannerMaxLine to handle large lines safely.
// If the scanner encounters a line exceeding the buffer (bufio.ErrTooLong),
// the function returns the original unmodified data as a fail-safe to prevent
// writing a truncated or partially-redacted transcript file.
func RedactJSONLBytes(r JSONRedactor, data []byte, opts ...RedactJSONLBytesOption) ([]byte, error) {
	cfg := scannerConfig{
		initBuf: DefaultScannerInitBuf,
		maxLine: DefaultScannerMaxLine,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, cfg.initBuf), cfg.maxLine)
	var buf bytes.Buffer
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			buf.WriteByte('\n')
			continue
		}
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.UseNumber()
		var v any
		if err := dec.Decode(&v); err != nil {
			buf.Write(line)
			buf.WriteByte('\n')
			continue
		}
		redacted := r.RedactJSON(v)
		encoded, err := json.Marshal(redacted)
		if err != nil {
			buf.Write(line)
		} else {
			buf.Write(encoded)
		}
		buf.WriteByte('\n')
	}
	if err := scanner.Err(); err != nil {
		return data, fmt.Errorf("scanner error: %w", err)
	}
	return buf.Bytes(), nil
}

// RedactJSONDocBytes processes an entire JSON document, applying RedactJSON to the
// decoded value and marshalling back. Returns the original data on any error.
func RedactJSONDocBytes(r JSONRedactor, data []byte) []byte {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return data
	}
	redacted := r.RedactJSON(v)
	encoded, err := json.Marshal(redacted)
	if err != nil {
		return data
	}
	return encoded
}
