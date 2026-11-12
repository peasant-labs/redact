package redact

import (
	"fmt"
	"regexp"
)

// engineName identifies the implementation, not the rule-set version.
type engineName string

const (
	engineGoRegexp engineName = "go-regexp"
	engineGoRE2    engineName = "go-re2"
)

// AllEngines returns the ordered engine identities. The returned slice is a copy.
func AllEngines() []engineName { return []engineName{engineGoRegexp, engineGoRE2} }

// NewEngineName refuses identities outside the closed engine registry.
func NewEngineName(value string) (engineName, error) {
	for _, name := range AllEngines() {
		if string(name) == value {
			return name, nil
		}
	}
	return "", &actionableError{
		what:  fmt.Sprintf("redaction engine identity %q is unknown", value),
		why:   "engine identities must name a registered implementation",
		where: "redact.NewEngineName", when: "validating an engine identity before use",
		means: "the identity cannot safely describe which engine produced an artifact",
		fix:   "use go-regexp or go-re2 from redact.AllEngines",
	}
}

// engine compiles patterns without exposing an implementation to callers.
type engine interface {
	Compile(pattern string) (compiled, error)
	Identity() engineName
}

type compiled interface {
	FindAllStringIndex(s string, n int) [][]int
	ReplaceAllString(s, repl string) string
	ReplaceAllLiteralString(s, repl string) string
	String() string
}

type goRegexpEngine struct{}

func (goRegexpEngine) Compile(pattern string) (compiled, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	return re, nil
}
func (goRegexpEngine) Identity() engineName { return engineGoRegexp }

// selectEngine selects the build's default without mutable process-wide state.
func selectEngine() engine { return selectDefaultEngine() }

// compiledPatterns pairs public regexp values with engine-specific patterns.
// The nil set uses the original stdlib patterns, preserving their configuration
// and avoiding recompilation on the stdlib fallback path. A constructed go-re2 set
// is immutable and shared by detection, replacement, and residue scanning.
type compiledPatterns map[*regexp.Regexp]compiled

// lookup returns the compiled pattern for the selected engine.
//
// A nil set means the stdlib build, so it returns the original pattern.
// A miss on a non-nil set is a programming error, so it panics.
func (patterns compiledPatterns) lookup(pattern *regexp.Regexp) compiled {
	if pattern == nil {
		return nil
	}
	if patterns == nil {
		return pattern
	}
	if compiled, ok := patterns[pattern]; ok {
		return compiled
	}
	panic(&actionableError{
		what:  fmt.Sprintf("a redaction rule pointer (%p) missed the compiled engine set", pattern),
		why:   "the rule pointer never went through compileRulePatterns",
		where: "redact.compiledPatterns.lookup",
		when:  "resolving a rule pattern to the selected engine before scanning content",
		means: "the scan cannot run; a stdlib fallback would silently change the engine",
		fix:   "compile the rule with compileRulePatterns before scanning, or keep a nil set for the stdlib build",
	})
}

func compileRulePatterns(e engine, rules []Rule, userRules []Rule, residueRules []ResidueRule) (compiledPatterns, error) {
	if _, stdlib := e.(goRegexpEngine); stdlib {
		return nil, nil
	}
	patterns := make(compiledPatterns)
	add := func(id string, pattern *regexp.Regexp) error {
		if pattern == nil {
			return nil
		}
		if _, exists := patterns[pattern]; exists {
			return nil
		}
		compiled, err := e.Compile(pattern.String())
		if err != nil {
			return &actionableError{
				what:  "a redaction rule could not be compiled by the selected engine",
				why:   "the selected engine rejected the rule's regular expression",
				where: "redact.compileRulePatterns", when: "constructing the selected rule set before scanning content",
				means: "no rule set was created; a partially compiled rule set must not scan content",
				fix:   "use a pattern supported by the selected engine for rule " + id, cause: err,
			}
		}
		patterns[pattern] = compiled
		return nil
	}
	for _, rule := range rules {
		if err := add(rule.ID, rule.Pattern); err != nil {
			return nil, err
		}
	}
	for _, rule := range userRules {
		if err := add(rule.ID, rule.Pattern); err != nil {
			return nil, err
		}
	}
	for _, rule := range residueRules {
		if err := add(rule.ID, rule.Pattern); err != nil {
			return nil, err
		}
	}
	return patterns, nil
}
