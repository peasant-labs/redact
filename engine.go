package redact

import (
	"errors"
	"fmt"
	"regexp"
)

// EngineName identifies the engine implementation, not the rule-set version.
type EngineName string

const (
	EngineGoRegexp EngineName = "go-regexp"
	EngineGoRE2    EngineName = "go-re2"

	// Internal aliases keep the package's existing call sites unchanged.
	engineGoRegexp = EngineGoRegexp
	engineGoRE2    = EngineGoRE2
)

// engineName is the internal alias used by the engine implementations.
type engineName = EngineName

// AllEngines returns the ordered engine identities. The returned slice is a copy.
func AllEngines() []EngineName { return []EngineName{EngineGoRegexp, EngineGoRE2} }

// EngineIdentity reports the engine this build selected. It is the value a
// projection row records with the redaction output.
func EngineIdentity() EngineName { return selectEngine().Identity() }

// NewEngineName refuses identities outside the closed engine registry.
func NewEngineName(value string) (EngineName, error) {
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
// and avoiding recompilation on the stdlib baseline path. A constructed go-re2 set
// is immutable and shared by detection, replacement, and residue scanning.
type compiledPatterns map[*regexp.Regexp]compiled

// ErrPatternNotCompiled identifies a constructor refusal when a rule has no
// compiled form for the selected engine. The actionable error wraps this
// sentinel and names the rule ID.
var ErrPatternNotCompiled = errors.New("a redaction rule has no compiled form for the selected engine")

// lookup returns the compiled pattern for the selected engine.
//
// A nil set means the stdlib build, so it returns the original pattern.
// A constructed go-re2 set never returns a stdlib pattern: a hit is the
// engine form, and a miss on a non-nil set is a programming error, so it panics.
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
			return patternNotCompiledError(id, nil)
		}
		if _, exists := patterns[pattern]; exists {
			return nil
		}
		compiled, err := e.Compile(pattern.String())
		if err != nil {
			return patternNotCompiledError(id, err)
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
	if err := verifyCompiledPatterns(patterns, rules, userRules, residueRules); err != nil {
		return nil, err
	}
	return patterns, nil
}

func patternNotCompiledError(id string, cause error) error {
	if id == "" {
		id = "unidentified"
	}
	if cause == nil {
		cause = ErrPatternNotCompiled
	} else {
		cause = errors.Join(ErrPatternNotCompiled, cause)
	}
	return &actionableError{
		what:  fmt.Sprintf("redaction rule %q has no compiled form for the selected engine", id),
		why:   "every rule used at scan time must have a compiled form under the selected engine",
		where: "redact.compileRulePatterns",
		when:  "constructing a redactor, title pipeline, or residue detector before scanning content",
		means: "no object was created; a missing compiled form would panic at lookup or silently change the engine",
		fix:   fmt.Sprintf("compile rule %q through the selected engine before construction, or remove the rule", id),
		cause: cause,
	}
}

// verifyCompiledPatterns refuses a non-nil set that is missing any live rule
// pointer, including a rule appended after the compile snapshot was taken.
// A nil set is the stdlib baseline and is not checked.
func verifyCompiledPatterns(patterns compiledPatterns, rules []Rule, userRules []Rule, residueRules []ResidueRule) error {
	if patterns == nil {
		return nil
	}
	check := func(id string, pattern *regexp.Regexp) error {
		if pattern == nil {
			return patternNotCompiledError(id, nil)
		}
		if _, ok := patterns[pattern]; !ok {
			return patternNotCompiledError(id, nil)
		}
		return nil
	}
	for _, rule := range rules {
		if err := check(rule.ID, rule.Pattern); err != nil {
			return err
		}
	}
	for _, rule := range userRules {
		if err := check(rule.ID, rule.Pattern); err != nil {
			return err
		}
	}
	for _, rule := range residueRules {
		if err := check(rule.ID, rule.Pattern); err != nil {
			return err
		}
	}
	return nil
}
