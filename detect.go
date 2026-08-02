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

	activeRules := make([]Rule, 0, len(Rules)+len(r.userRules))
	for _, rule := range Rules {
		if r.isActiveRule(rule) {
			activeRules = append(activeRules, rule)
		}
	}
	for _, rule := range r.userRules {
		if r.isActiveRule(rule) {
			activeRules = append(activeRules, rule)
		}
	}
	matches := detectWithRules(input, activeRules)

	if len(matches) == 0 {
		// Record nil as the last detect result (last-call-only semantics).
		r.mu.Lock()
		r.lastMatches = nil
		r.mu.Unlock()
		return nil
	}

	// Store as last-detect result (last-call-only, not accumulated).
	r.mu.Lock()
	r.lastMatches = matches
	r.mu.Unlock()

	return matches
}

// detectWithRules is the pure canonical regex detector. Reporting and
// last-call state remain the responsibility of DefaultRedactor.Detect.
func detectWithRules(input string, rules []Rule) []Match {
	var matches []Match
	for _, rule := range rules {
		if rule.Pattern == nil {
			continue
		}
		for _, loc := range rule.Pattern.FindAllStringIndex(input, -1) {
			match := Match{Rule: rule.ID, Offset: loc[0], Length: loc[1] - loc[0], Category: rule.Category, MatchedText: input[loc[0]:loc[1]]}
			if rule.FilterFn == nil || rule.FilterFn(match.MatchedText, input, match.Offset) {
				matches = append(matches, match)
			}
		}
	}
	if len(matches) == 0 {
		return nil
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].Offset < matches[j].Offset })
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
	rules := make([]Rule, 0, len(Rules)+len(r.userRules))
	rules = append(rules, Rules...)
	rules = append(rules, r.userRules...)
	output, _ := redactWithRules(input, matches, rules)
	return output
}

// redactWithRules is the pure canonical overlap and replacement engine. The
// returned matches are exactly those whose non-overlapping spans were applied.
func redactWithRules(input string, matches []Match, rules []Rule) (string, []Match) {
	if len(matches) == 0 {
		return input, nil
	}
	replacements := make(map[string]Rule, len(rules))
	for _, rule := range rules {
		replacements[rule.ID] = rule
	}

	var out []byte
	cursor := 0
	var applied []Match

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
		rule, ok := replacements[m.Rule]
		replacement := rule.Replacement
		if !ok {
			replacement = "<REDACTED>"
		}

		appliedReplacement := replacement
		if replacement != "" && containsBackref(replacement) {
			if ok && rule.Pattern != nil {
				appliedReplacement = rule.Pattern.ReplaceAllString(input[m.Offset:end], replacement)
			}
		}
		out = append(out, appliedReplacement...)

		cursor = end
		if appliedReplacement != input[m.Offset:end] {
			applied = append(applied, m)
		}
	}

	// Append any remaining text after the last match.
	if cursor < len(input) {
		out = append(out, input[cursor:]...)
	}

	return string(out), applied
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
