package redact

import "sort"

// Match represents a single detected sensitive pattern in the input string.
//
// MatchedText is a zero-copy substring slice of the original input string
// (input[Offset:Offset+Length]). It shares the backing array of the input —
// do not hold a Match longer than the input string is alive.
//
// Match is in-memory only — it is never serialised to disk or the network.
type Match struct {
	// Rule is the rule ID that produced this match (e.g., "github_token", "email").
	Rule string
	// Offset is the byte offset of the match start in the input string.
	Offset int
	// Length is the byte length of the match.
	Length int
	// Category is the rule category that fired (e.g., CategorySecrets, CategoryPII).
	Category Category
	// MatchedText is input[Offset:Offset+Length] — zero-copy substring slice.
	MatchedText string
}

// Detect scans input for all sensitive patterns active at the receiver's redaction level.
// It returns a slice of Match values sorted by Offset (ascending).
//
// Detect does NOT modify the input string.
// The returned MatchedText fields share the backing array of input — callers that
// need to hold matches past the input's lifetime must copy MatchedText themselves.
//
// If no patterns match, Detect returns nil (not an empty slice).
func (r *DefaultRedactor) Detect(input string) []Match {
	if input == "" {
		return nil
	}

	var matches []Match

	// Scan built-in rules.
	for _, rule := range Rules {
		if !r.isActiveRule(rule) {
			continue
		}
		if rule.Pattern == nil {
			continue
		}
		locs := rule.Pattern.FindAllStringIndex(input, -1)
		for _, loc := range locs {
			start, end := loc[0], loc[1]
			m := Match{
				Rule:        rule.ID,
				Offset:      start,
				Length:      end - start,
				Category:    rule.Category,
				MatchedText: input[start:end],
			}
			// Apply optional post-match filter. A false return suppresses the match.
			if rule.FilterFn != nil && !rule.FilterFn(m.MatchedText, input, m.Offset) {
				continue
			}
			matches = append(matches, m)
		}
	}

	// Scan user-defined rules (read-only after construction — no mutex needed).
	for _, rule := range r.userRules {
		if !r.isActiveRule(rule) {
			continue
		}
		if rule.Pattern == nil {
			continue
		}
		locs := rule.Pattern.FindAllStringIndex(input, -1)
		for _, loc := range locs {
			start, end := loc[0], loc[1]
			matches = append(matches, Match{
				Rule:        rule.ID,
				Offset:      start,
				Length:      end - start,
				Category:    rule.Category,
				MatchedText: input[start:end],
			})
		}
	}

	if len(matches) == 0 {
		// Record nil as the last detect result (last-call-only semantics).
		r.mu.Lock()
		r.lastMatches = nil
		r.mu.Unlock()
		return nil
	}

	// Sort by offset ascending so callers can process matches left-to-right.
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].Offset < matches[j].Offset
	})

	// Store as last-detect result (last-call-only, not accumulated).
	r.mu.Lock()
	r.lastMatches = matches
	r.mu.Unlock()

	return matches
}

// Redact replaces the byte spans identified by matches in input with their rule
// replacements, then returns the resulting string. It does NOT re-scan — only
// the provided match spans are replaced.
//
// If matches is nil or empty, Redact returns input unchanged.
// Overlapping matches are skipped: if a span is already covered by a previously
// applied match, the overlapping match is silently ignored.
//
// The output string is built in a single pass from left to right.
func (r *DefaultRedactor) Redact(input string, matches []Match) string {
	if len(matches) == 0 {
		return input
	}

	// Build a lookup from rule ID to replacement string for O(1) access.
	// Populate from built-in rules and user rules.
	replacements := make(map[string]string, len(Rules)+len(r.userRules))
	for _, rule := range Rules {
		replacements[rule.ID] = rule.Replacement
	}
	for _, rule := range r.userRules {
		replacements[rule.ID] = rule.Replacement
	}

	var out []byte
	cursor := 0

	for _, m := range matches {
		// Skip matches that start before cursor (overlapping or out-of-order spans).
		if m.Offset < cursor {
			continue
		}
		// Validate span bounds.
		end := m.Offset + m.Length
		if end > len(input) {
			continue
		}

		// Append non-match text between cursor and this match.
		out = append(out, input[cursor:m.Offset]...)

		// Append the replacement for this rule, falling back to a generic placeholder
		// if the rule ID is not found (e.g., caller supplied synthetic Match values).
		replacement, ok := replacements[m.Rule]
		if !ok {
			replacement = "<REDACTED>"
		}

		// Handle back-reference syntax: rules using "${1}", "${2}" etc. need
		// ReplaceAllString. We detect this by looking for "$" in the replacement.
		// For simple literal replacements, write directly to avoid regex overhead.
		if replacement != "" && containsBackref(replacement) {
			// Find the compiled rule to use its Pattern for back-reference expansion.
			matched := false
			for _, rule := range Rules {
				if rule.ID == m.Rule && rule.Pattern != nil {
					expanded := rule.Pattern.ReplaceAllString(input[m.Offset:end], replacement)
					out = append(out, expanded...)
					matched = true
					break
				}
			}
			if !matched {
				for _, rule := range r.userRules {
					if rule.ID == m.Rule && rule.Pattern != nil {
						expanded := rule.Pattern.ReplaceAllString(input[m.Offset:end], replacement)
						out = append(out, expanded...)
						matched = true
						break
					}
				}
			}
			if !matched {
				// Fallback: write literal replacement.
				out = append(out, replacement...)
			}
		} else {
			out = append(out, replacement...)
		}

		cursor = end
	}

	// Append any remaining text after the last match.
	if cursor < len(input) {
		out = append(out, input[cursor:]...)
	}

	return string(out)
}

// containsBackref reports whether a replacement string contains a back-reference
// such as "${1}", "${2}", "$1", "$2", etc.
func containsBackref(s string) bool {
	for i := 0; i < len(s)-1; i++ {
		if s[i] == '$' {
			next := s[i+1]
			if next == '{' || (next >= '0' && next <= '9') {
				return true
			}
		}
	}
	return false
}
