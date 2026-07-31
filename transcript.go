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
// A DefaultRedactor's constructor scanner configuration is the base. Per-call
// options take precedence. Other JSONRedactor implementations use the exported
// defaults as their base.
// If the scanner encounters a line exceeding the buffer (bufio.ErrTooLong),
// the function returns the original unmodified data as a fail-safe to prevent
// writing a truncated or partially-redacted transcript file.
func RedactJSONLBytes(r JSONRedactor, data []byte, opts ...RedactJSONLBytesOption) ([]byte, error) {
	cfg := defaultScannerConfig()
	if provider, ok := r.(interface{ redactScannerConfig() scannerConfig }); ok {
		cfg = provider.redactScannerConfig()
	}
	for i, opt := range opts {
		if opt == nil {
			return data, scannerOptionError("RedactJSONLBytes", fmt.Sprintf("per-call option at index %d is nil", i), cfg, nil)
		}
		opt(&cfg)
	}
	if err := validateScannerConfig("RedactJSONLBytes", cfg); err != nil {
		return data, err
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
		return data, scannerOptionError("RedactJSONLBytes", fmt.Sprintf("JSONL scanner could not read a complete line within the configured maximum of %d bytes", cfg.maxLine), cfg, err)
	}
	return buf.Bytes(), nil
}

func defaultScannerConfig() scannerConfig {
	return scannerConfig{initBuf: DefaultScannerInitBuf, maxLine: DefaultScannerMaxLine}
}

func validateScannerConfig(operation string, cfg scannerConfig) error {
	var why string
	switch {
	case cfg.initBuf <= 0:
		why = "the initial scanner buffer must be positive"
	case cfg.maxLine <= 0:
		why = "the maximum scanner line size must be positive"
	case cfg.initBuf > cfg.maxLine:
		why = "the initial scanner buffer cannot exceed the maximum scanner line size"
	default:
		return nil
	}
	return scannerOptionError(operation, why, cfg, nil)
}

func scannerOptionError(operation, why string, cfg scannerConfig, cause error) error {
	return &actionableError{
		what:  fmt.Sprintf("invalid or insufficient JSONL scanner configuration (initial=%d bytes, maximum=%d bytes)", cfg.initBuf, cfg.maxLine),
		why:   why,
		where: "redact " + operation,
		when:  "configuring or running JSONL transcript redaction before returning transformed output",
		means: "the original input bytes were returned unchanged because partial or truncated redaction would be unsafe",
		fix:   "set both scanner sizes to positive values, keep the initial size at or below the maximum, and increase the maximum above the largest JSONL line",
		cause: cause,
	}
}

func (r *DefaultRedactor) redactScannerConfig() scannerConfig { return r.scannerConfig }

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
