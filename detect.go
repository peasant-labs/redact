package redact

import (
	"regexp"
	"sort"
)

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
// It returns a slice of Match values sorted by Offset (ascending); matches that
// start at one offset are ordered longest first, then by rule order.
//
// A match of a rule that reads the name of a key or the construct around a
// value (key_name_secret, url_query_secret, cookie_header, curl_user_password)
// spans the value alone, not the name or the option. Where such a match overlaps a match of
// another rule, it is dropped or shortened so that the other match is applied.
//
// Detect does NOT modify the input string.
// The returned MatchedText fields share the backing array of input — callers that
// need to hold matches past the input's lifetime must copy MatchedText themselves.
//
// If no patterns match, Detect returns nil (not an empty slice).
//
// input must be valid UTF-8; see the package input contract.
func (r *DefaultRedactor) Detect(input string) []Match {
	return r.detect(input, nil)
}

func (r *DefaultRedactor) detect(input string, call *observationCall) []Match {
	if input == "" {
		return nil
	}
	matches := r.scan(input, call)
	// Store as the last-detect result (last-call-only, not accumulated).
	r.mu.Lock()
	r.lastMatches = matches
	r.mu.Unlock()
	return matches
}

// scan returns the matches of every rule active at the configured level. It
// does not record them as the last Detect result.
func (r *DefaultRedactor) scan(input string, call *observationCall) []Match {
	if input == "" {
		return nil
	}

	activeRules := make([]Rule, 0, len(Rules)+len(r.userRules))
	for index, rule := range Rules {
		if r.isActiveRule(rule) {
			activeRules = append(activeRules, rule)
			if call != nil {
				call.record.Rules = append(call.record.Rules, RuleDetection{Rule: RuleIdentity{ID: rule.ID, Origin: RuleOriginBuiltin, Index: index}, Category: rule.Category})
			}
		}
	}
	for index, rule := range r.userRules {
		if r.isActiveRule(rule) {
			activeRules = append(activeRules, rule)
			if call != nil {
				origin, sourceIndex := RuleOriginConfigured, index
				if index >= r.configuredRuleCount {
					origin, sourceIndex = RuleOriginRuntimeXDG, index-r.configuredRuleCount
				}
				call.record.Rules = append(call.record.Rules, RuleDetection{Rule: RuleIdentity{ID: rule.ID, Origin: origin, Index: sourceIndex}, Category: rule.Category})
			}
		}
	}
	var accepted func(int)
	if call != nil {
		accepted = func(index int) { call.record.Rules[index].Count++; call.record.RegexDetected.Value++ }
	}
	return detectWithRulesInto(input, activeRules, r.patterns, accepted)
}

// valueSpan is a part of the input that a rule replaces: input[start:end].
// construct is where the construct the value was found in starts: the start of
// the name in "name=value".
type valueSpan struct{ start, end, construct int }

// valueFinder returns the parts of the input that a rule replaces for one match
// of its pattern, in ascending order and without overlap. matched is the
// pattern match and offset is its position in input, as for Rule.FilterFn. No
// span means the match holds nothing to redact.
//
// A span usually lies inside the match. It may end after it, when the pattern
// stops at a character that the value continues through.
//
// A finder reads the match with the standard library's regexp package,
// whichever engine found the match.
type valueFinder func(matched, input string, offset int) []valueSpan

// valueRule describes a rule that replaces only a part of what its pattern
// matches: the value after a key name, not the name. Detection reports one
// match for each span that find returns, in place of the pattern match, and
// Redact replaces each with placeholder.
//
// The rule's own Pattern and Replacement still describe the whole construct.
// They serve the recovery path, which applies a pattern without its filter.
type valueRule struct {
	find        valueFinder
	placeholder string
	// knowsFormat is set on a rule that recognises the text itself and uses
	// find only to say where in the pattern match it starts. Its matches are
	// left as they are when overlaps are settled, like those of any rule
	// without a finder. The other value rules know only where a value sits,
	// and resolveValueOverlaps makes them give way.
	knowsFormat bool
}

// valueRules holds the value rules by their pattern. The entry lives beside
// the rule table and not in Rule, whose field layout is public.
var valueRules = map[*regexp.Regexp]valueRule{
	keyNameSecretPattern:    {find: keyNameSecretValues, placeholder: keyNameSecretPlaceholder},
	urlQuerySecretPattern:   {find: urlQuerySecretValues, placeholder: keyNameSecretPlaceholder},
	cookieHeaderPattern:     {find: cookieHeaderValues, placeholder: cookieHeaderPlaceholder},
	curlUserPasswordPattern: {find: curlUserPasswordValues, placeholder: curlUserPasswordPlaceholder},
	// The rules built by prefixTokenRule add themselves.
}

// hasValue adapts a valueFinder to Rule.FilterFn, so a caller that applies a
// rule by hand makes the same decision as detection. Every value rule carries
// this filter.
func hasValue(find valueFinder) func(matched, input string, offset int) bool {
	return func(matched, input string, offset int) bool { return len(find(matched, input, offset)) > 0 }
}

// detectWithRules is the pure canonical regex detector. Reporting and
// last-call state remain the responsibility of DefaultRedactor.Detect.
func detectWithRules(input string, rules []Rule, patterns compiledPatterns) []Match {
	return detectWithRulesInto(input, rules, patterns, nil)
}

func detectWithRulesInto(input string, rules []Rule, patterns compiledPatterns, accepted func(ruleIndex int)) []Match {
	var found detectedMatches
	valueMatches := false
	for index, rule := range rules {
		pattern := patterns.lookup(rule.Pattern)
		if pattern == nil {
			continue
		}
		values := valueRules[rule.Pattern]
		for _, loc := range pattern.FindAllStringIndex(input, -1) {
			matched := input[loc[0]:loc[1]]
			if values.find != nil {
				for _, span := range values.find(matched, input, loc[0]) {
					found.add(Match{Rule: rule.ID, Offset: span.start, Length: span.end - span.start, Category: rule.Category, MatchedText: input[span.start:span.end]}, matchSource{rule: index, value: !values.knowsFormat, construct: span.construct})
					valueMatches = valueMatches || !values.knowsFormat
				}
				continue
			}
			if rule.FilterFn == nil || rule.FilterFn(matched, input, loc[0]) {
				found.add(Match{Rule: rule.ID, Offset: loc[0], Length: loc[1] - loc[0], Category: rule.Category, MatchedText: matched}, matchSource{rule: index})
			}
		}
	}
	if len(found.matches) == 0 {
		return nil
	}
	// Order by offset. Two matches that start at the same offset are ordered
	// longest first, so Redact, which keeps the first of two overlapping
	// matches, never prefers a rule that covers less of the same text. Two
	// matches of one span keep the order of the rule table.
	sort.Stable(&found)
	if valueMatches {
		found.resolveValueOverlaps(input)
	}
	if accepted != nil {
		for _, source := range found.sources {
			accepted(source.rule)
		}
	}
	if len(found.matches) == 0 {
		return nil
	}
	return found.matches
}

// detectedMatches holds the accepted matches of one scan and where each came
// from.
type detectedMatches struct {
	matches []Match
	sources []matchSource
}

// matchSource is the index of a match's rule in the scanned rule list. For a
// value that resolveValueOverlaps settles (see valueRule.knowsFormat) it also
// holds where the construct that the value was found in starts: the start of
// the name in "name=value", which for the second setting of
// "password=abc12345,token=def67890" is the start of "token".
type matchSource struct {
	rule      int
	value     bool
	construct int
}

func (d *detectedMatches) add(match Match, source matchSource) {
	d.matches = append(d.matches, match)
	d.sources = append(d.sources, source)
}

func (d *detectedMatches) Len() int { return len(d.matches) }

func (d *detectedMatches) Less(i, j int) bool {
	if d.matches[i].Offset != d.matches[j].Offset {
		return d.matches[i].Offset < d.matches[j].Offset
	}
	return d.matches[i].Length > d.matches[j].Length
}

func (d *detectedMatches) Swap(i, j int) {
	d.matches[i], d.matches[j] = d.matches[j], d.matches[i]
	d.sources[i], d.sources[j] = d.sources[j], d.sources[i]
}

// resolveValueOverlaps settles every overlap between a match of a value rule
// and the matches around it. A value rule knows only where a value sits, so a
// rule that knows what the text is goes first, and nothing another rule would
// redact is left in the output because a value match stood in its way.
//
// The matches are sorted, and Redact applies them in that order and skips a
// match that starts inside one it already applied. This pass walks them the
// same way and settles four cases:
//
//   - A match of another rule covers the whole value. The value match is
//     dropped: GITHUB_TOKEN=<GITHUB_PAT>, not GITHUB_TOKEN=<SECRET>.
//   - A match starts inside the construct the value was found in and stops
//     part of the way through the value: generic_api_key reads the name in
//     api_key="abc...+/x9" too and stops at the "+". That match is dropped
//     and the value match replaces the whole value. What the dropped match
//     covered outside the value is the name and the separator.
//   - Any other applied match covers the start of the value. The value match
//     keeps the rest, which Redact would otherwise skip and leave in the
//     output.
//   - A later match starts inside the value and ends more than one character
//     after it. The value match ends where that match starts, so both are
//     applied: the value of "password=abc12345,card=4111 1111 1111 1111" and
//     the card number.
//
// A match that lies inside the value is left to Redact, which skips it. So is
// one that ends a single character after the value: a pattern that takes the
// character after its token, as aws_secret_key does, covers no more of the
// input than the value.
//
// Apart from the second case no match of another rule is changed, so every
// part of the input that the other rules would replace without the value rules
// is still replaced.
func (d *detectedMatches) resolveValueOverlaps(input string) {
	end := func(i int) int { return d.matches[i].Offset + d.matches[i].Length }
	dropped := make([]bool, len(d.matches))
	for i, source := range d.sources {
		if !source.value {
			continue
		}
		for j := i - 1; j >= 0 && d.matches[j].Offset >= source.construct; j-- {
			if !d.sources[j].value && end(j) > d.matches[i].Offset && end(j) < end(i) {
				dropped[j] = true
			}
		}
	}
	kept := 0
	applied := 0 // end of the last match Redact applies
	moved := false
	for i, match := range d.matches {
		if dropped[i] {
			continue
		}
		start, stop := match.Offset, end(i)
		if !d.sources[i].value {
			if start >= applied {
				applied = stop
			}
		} else {
			start = max(start, applied)
			for j := i + 1; j < len(d.matches) && d.matches[j].Offset < stop; j++ {
				if dropped[j] || d.matches[j].Offset < start {
					continue
				}
				if covers := d.matches[j].Offset == start && end(j) == stop && !d.sources[j].value; covers || end(j) > stop+1 {
					stop = d.matches[j].Offset
					break
				}
			}
			if start >= stop {
				continue
			}
			moved = moved || start != match.Offset
			match.Offset, match.Length, match.MatchedText = start, stop-start, input[start:stop]
			applied = stop
		}
		d.matches[kept], d.sources[kept] = match, d.sources[i]
		kept++
	}
	d.matches, d.sources = d.matches[:kept], d.sources[:kept]
	if moved {
		// A value match that lost its start now begins after matches that lie
		// inside the match before it. Restore the order Detect promises.
		sort.Stable(d)
	}
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
//
// input must be valid UTF-8; see the package input contract.
func (r *DefaultRedactor) Redact(input string, matches []Match) string {
	rules := make([]Rule, 0, len(Rules)+len(r.userRules))
	rules = append(rules, Rules...)
	rules = append(rules, r.userRules...)
	output, _ := redactWithRules(input, matches, rules, r.patterns)
	return output
}

// redactWithRules is the pure canonical overlap and replacement engine. The
// returned matches are exactly those whose non-overlapping spans were applied.
func redactWithRules(input string, matches []Match, rules []Rule, patterns compiledPatterns) (string, []Match) {
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
		if value, isValue := valueRules[rule.Pattern]; ok && isValue {
			// The match is a value the rule found inside its pattern match.
			appliedReplacement = value.placeholder
		} else if replacement != "" && containsBackref(replacement) {
			if ok && rule.Pattern != nil {
				appliedReplacement = patterns.lookup(rule.Pattern).ReplaceAllString(input[m.Offset:end], replacement)
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
