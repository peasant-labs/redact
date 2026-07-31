package redact

import (
	"math"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// shannonEntropy computes the bits-per-character Shannon entropy of s.
// Uses the standard formula: -sum(p_i * log2(p_i)) over character frequencies.
// len(s) == 0 checks the byte length, which is correct for the empty-string fast path:
// an empty string has no bytes and no runes, so returning 0 immediately is safe.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int)
	total := 0
	for _, ch := range s {
		freq[ch]++
		total++
	}
	var entropy float64
	for _, count := range freq {
		p := float64(count) / float64(total)
		entropy -= p * math.Log2(p)
	}
	return entropy
}

const (
	entropyLengthThreshold = 20  // tokens must EXCEED this length to be checked (len > 20)
	entropyBitsThreshold   = 4.0 // minimum bits-per-character to flag (legacy fallback)

	b64Charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_="
	hexCharset = "0123456789abcdefABCDEF"

	b64Threshold = 4.5
	hexThreshold = 3.0
)

// uuidPattern matches the 8-4-4-4-12 UUID format as a substring.
var uuidPattern = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)

// isPotentialUUID returns true if s contains a UUID-shaped substring (8-4-4-4-12 hex).
// Embedded UUIDs (e.g. in URLs or longer tokens) are also matched.
func isPotentialUUID(s string) bool {
	return uuidPattern.MatchString(s)
}

// isSequentialString returns true if s (normalized to lowercase) is a permutation of
// a subset of a known sequential charset. This catches tokens like "ABCDEF", "0123456",
// or hex charset rotations that have high character variety but no real entropy.
//
// Known charsets checked: full lowercase alphabet, digits, lowercase hex, b64.
// The check compares sorted(lowercase(s)) against a sorted prefix of each charset.
func isSequentialString(s string) bool {
	normalized := strings.ToLower(s)
	runes := []rune(normalized)
	sort.Slice(runes, func(i, j int) bool { return runes[i] < runes[j] })
	sorted := string(runes)

	knownCharsets := []string{
		"abcdefghijklmnopqrstuvwxyz",
		"0123456789",
		strings.ToLower(hexCharset),
		strings.ToLower(b64Charset),
	}

	for _, charset := range knownCharsets {
		csRunes := []rune(charset)
		// Deduplicate charset runes.
		seen := make(map[rune]bool)
		deduped := make([]rune, 0, len(csRunes))
		for _, r := range csRunes {
			if !seen[r] {
				seen[r] = true
				deduped = append(deduped, r)
			}
		}
		sort.Slice(deduped, func(i, j int) bool { return deduped[i] < deduped[j] })
		sortedCharset := string(deduped)

		if strings.HasPrefix(sortedCharset, sorted) {
			return true
		}
	}
	return false
}

// isPrefixedWithDollarSign returns true if s starts with "$".
// Shell variable references ($TOKEN, $VAR) should not be flagged as high-entropy secrets.
func isPrefixedWithDollarSign(s string) bool {
	return strings.HasPrefix(s, "$")
}

// shannonEntropyOverCharset computes Shannon entropy over only the characters in data
// that appear in charset. Characters in data not found in charset are ignored.
// Returns 0.0 if no characters in data match charset.
func shannonEntropyOverCharset(data, charset string) float64 {
	charsetSet := make(map[rune]bool, len(charset))
	for _, ch := range charset {
		charsetSet[ch] = true
	}

	freq := make(map[rune]int)
	total := 0
	for _, ch := range data {
		if charsetSet[ch] {
			freq[ch]++
			total++
		}
	}
	if total == 0 {
		return 0.0
	}

	var entropy float64
	for _, count := range freq {
		p := float64(count) / float64(total)
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// isAllDigits returns true if every rune in s is an ASCII digit.
func isAllDigits(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

// detectEntropy returns "<HIGH_ENTROPY>" if s exceeds both the length and entropy
// thresholds, otherwise returns s unchanged.
//
// Detection order:
//  1. Pre-filter: skip if isPotentialUUID → UUIDs are structured identifiers, not secrets.
//  2. Pre-filter: skip if isSequentialString → alphabetic or numeric runs have no real entropy.
//  3. Pre-filter: skip if isPrefixedWithDollarSign → shell variable references.
//  4. Charset-aware hex path: shannonEntropyOverCharset(s, hexCharset) with all-digit penalty.
//  5. Charset-aware base64 path: shannonEntropyOverCharset(s, b64Charset).
func detectEntropy(s string) string {
	if len(s) <= entropyLengthThreshold {
		return s
	}

	// Pre-filters: skip structured / low-entropy token shapes.
	if isPotentialUUID(s) {
		return s
	}
	if isSequentialString(s) {
		return s
	}
	if isPrefixedWithDollarSign(s) {
		return s
	}

	// Charset-aware hex detection.
	hexEntropy := shannonEntropyOverCharset(s, hexCharset)
	if isAllDigits(s) && len(s) > 1 {
		// All-digit strings have inflated hex entropy because digits are in the hex charset.
		// Apply a penalty proportional to 1/log2(len) to discount purely numeric tokens.
		hexEntropy -= 1.2 / math.Log2(float64(len(s)))
	}
	if hexEntropy > hexThreshold {
		return "<HIGH_ENTROPY>"
	}

	// Charset-aware base64 detection.
	b64Entropy := shannonEntropyOverCharset(s, b64Charset)
	if b64Entropy > b64Threshold {
		return "<HIGH_ENTROPY>"
	}

	return s
}

// detectEntropyInWords applies entropy detection to each whitespace-delimited word in text.
// Only tokens consisting entirely of non-space, non-control characters are checked.
// Iteration uses rune-aware range to correctly handle multi-byte UTF-8 characters.
//
// TODO: accept FilePathFilter param when transcript schema provides per-turn source paths
// to suppress entropy scanning on lock files (go.sum, package-lock.json) and generated files.
func detectEntropyInWords(text string) string {
	if len(text) == 0 {
		return text
	}

	var result strings.Builder
	result.Grow(len(text))

	runes := []rune(text)
	i := 0
	for i < len(runes) {
		// Skip whitespace, writing each rune as UTF-8.
		if unicode.IsSpace(runes[i]) {
			result.WriteRune(runes[i])
			i++
			continue
		}
		// Find end of word (next whitespace or end of string).
		j := i
		for j < len(runes) && !unicode.IsSpace(runes[j]) {
			j++
		}
		word := string(runes[i:j])
		result.WriteString(detectEntropy(word))
		i = j
	}
	return result.String()
}
