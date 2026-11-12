package redact

import "strings"

// admits reports whether value can possibly match rule.
//
// The contract is one-directional: a false return means the value cannot match,
// so the detector skips the regex; a true return means the caller must run the
// pattern. admits may therefore never reject a value that could match.
//
// The gate is a byte-level prefilter. It runs before any regex call and never
// sees a match, so it cannot replace a post-match FilterFn.
func admits(rule Rule, value string) bool {
	if rule.MinMatchBytes > 0 && len(value) < rule.MinMatchBytes {
		return false
	}
	if len(rule.RequiredLiterals) == 0 {
		return true
	}
	fold := ruleHasFoldCase(rule)
	for _, literal := range rule.RequiredLiterals {
		if containsLiteral(value, literal, fold) {
			return true
		}
	}
	return false
}

// ruleHasFoldCase reports whether the rule's pattern is case-insensitive at its
// start. Rules that declare lowercase literals lean on this to compare
// case-insensitively; every other rule compares byte-exactly.
func ruleHasFoldCase(rule Rule) bool {
	return rule.Pattern != nil && strings.HasPrefix(rule.Pattern.String(), "(?i)")
}

// containsLiteral reports whether value holds literal, folding ASCII case when
// fold is set.
func containsLiteral(value, literal string, fold bool) bool {
	if !fold {
		return strings.Contains(value, literal)
	}
	return containsFoldASCII(value, literal)
}

// containsFoldASCII reports whether value holds literal under ASCII-only case
// folding. Every literal declared by a case-insensitive rule is ASCII, so this
// avoids the whole-value allocation strings.ToLower would cost.
func containsFoldASCII(value, literal string) bool {
	if literal == "" {
		return true
	}
	if len(literal) > len(value) {
		return false
	}
	first := lowerASCII(literal[0])
	for start := 0; start+len(literal) <= len(value); start++ {
		if lowerASCII(value[start]) != first {
			continue
		}
		matched := true
		for offset := 1; offset < len(literal); offset++ {
			if lowerASCII(value[start+offset]) != lowerASCII(literal[offset]) {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

// lowerASCII lowercases an ASCII letter and leaves every other byte alone.
func lowerASCII(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}
