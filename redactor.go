package redact

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/peasant-labs/schema"
)

// Redactor applies privacy-preserving redaction to text, JSON values, and session metadata.
// All methods are safe for concurrent use.
type Redactor interface {
	// Detect scans input for sensitive patterns at the configured level.
	// Returns matches sorted by offset. Does NOT modify input.
	// Returns nil if no patterns match.
	Detect(input string) []Match

	// Redact replaces match spans in input with redaction placeholders.
	// Does NOT re-scan — operates only on the provided matches.
	// Returns input unchanged if matches is nil or empty.
	Redact(input string, matches []Match) string

	// RedactText is the single-step convenience API: equivalent to r.Redact(input, r.Detect(input)).
	// Applies regex rules and entropy detection to plain text.
	RedactText(input string) string
	// RedactJSON recursively applies RedactText to all string values in a JSON-decoded value.
	RedactJSON(value any) any
	// RedactMetadata applies RedactText to sensitive fields in a DEEP COPY of the metadata.
	// The original pointer is never mutated.
	RedactMetadata(meta *schema.UnifiedMetadata) *schema.UnifiedMetadata
	// Report returns an aggregate of all redactions performed so far.
	// The Matches field contains all matches from the last Detect() call only (not accumulated).
	Report() RedactionReport
	// Level returns the redaction level as a string (e.g. "minimal", "standard", "maximum").
	Level() string
	// RuleSetVersion returns the semantic version of the compiled rule set (e.g. "1.1.0").
	// Populated into RedactionInfo.RuleSetVersion on every redaction write.
	RuleSetVersion() string
}

// RedactionReport summarises what has been redacted across all calls on a single Redactor.
type RedactionReport struct {
	TotalRedactions int
	Counts          map[string]int // rule ID → redaction count
	Categories      []string       // categories that fired at least once
	Warnings        []string       // residue detection warnings (v2)
	// Matches contains all matches from the last Detect() call.
	// This is last-call-only (not accumulated across multiple Detect calls).
	// In-memory only — never serialised to disk or network.
	Matches []Match
}

// DefaultRedactor is the production implementation of Redactor.
// It is safe for concurrent use via an internal mutex.
type DefaultRedactor struct {
	level           RedactionLevel
	mu              sync.Mutex
	report          RedactionReport
	categories      map[string]bool // internal set for O(1) dedup; exported as []string via Report()
	astAnonymizer   ASTAnonymizer   // AST code anonymization (v2, Maximum only)
	residueDetector ResidueDetector // post-redaction advisory scanner (v2)
	userRules       []Rule          // v3: compiled from userPatterns at construction; read-only after init
	lastMatches     []Match         // matches from the last Detect() call (last-call-only, not accumulated)
}

// XDGPaths holds resolved XDG base directory paths for custom path redaction.
// Zero values mean "not configured" — no extra rules generated.
// These are injected at construction time to keep the redactor testable with no OS state.
type XDGPaths struct {
	DataHome   string // resolved $XDG_DATA_HOME (default: ~/.local/share)
	ConfigHome string // resolved $XDG_CONFIG_HOME (default: ~/.config)
	StateHome  string // resolved $XDG_STATE_HOME (default: ~/.local/state)
}

// NewRedactor returns a Redactor configured for the given level, user-defined patterns,
// and XDG path rules.
//
// userPatterns are compiled at construction time. An invalid regex in any pattern causes
// NewRedactor to return an error immediately (fail-closed: no partial redactor is returned).
// User pattern categories must be one of the known variants (CategorySecrets, CategoryPII,
// CategoryPaths, CategoryProject). User patterns inherit the category's default minimum:
// secrets and paths at Minimal, PII and project identity at Standard.
//
// xdg generates additional path redaction rules for non-standard XDG locations where
// the username may appear outside /home/ or /Users/ prefixes.
//
// At Maximum level, the ASTAnonymizer is a FallbackAnonymizer that uses
// TreeSitterAnonymizer as the primary and RegexAnonymizer as the fallback
// (see newMaximumAnonymizer in maximum_cgo.go). Because tree-sitter is a cgo
// dependency, Maximum is available ONLY in cgo builds: in a !cgo binary
// (redact.MaximumAvailable == false) NewRedactor(Maximum) returns an actionable
// error rather than silently degrading. At Standard/Minimal levels, the
// ASTAnonymizer is not used (v1 code block masking applies instead), but is
// initialized to RegexAnonymizer for forward compatibility.
func NewRedactor(level RedactionLevel, userPatterns []UserPattern, xdg XDGPaths, opts ...Option) (Redactor, error) {
	if !level.IsValid() {
		return nil, &actionableError{
			what:  fmt.Sprintf("redaction level %q is invalid", level),
			why:   "NewRedactor accepts only minimal, standard, or maximum",
			where: "pkg/redact NewRedactor",
			when:  "constructing a redactor before any content was scanned",
			means: "no redactor was created, so the caller cannot safely scan or redact content",
			fix:   "pass redact.Minimal, redact.Standard, or redact.Maximum",
		}
	}
	if err := validateRuleActivationMetadata(Rules); err != nil {
		return nil, err
	}

	userRules, err := compileUserPatterns(userPatterns)
	if err != nil {
		return nil, err
	}

	if err := validateMaximumAvailability(level, MaximumAvailable); err != nil {
		return nil, err
	}

	// Generate XDG path rules for non-standard XDG locations.
	xdgRules := buildXDGRules(xdg)
	userRules = append(userRules, xdgRules...)

	var anon ASTAnonymizer
	if level == Maximum {
		// Reachable only when MaximumAvailable == true (guarded above). The
		// factory is build-tag-gated: tree-sitter-backed in cgo builds
		// (maximum_cgo.go), unreachable dead-code in !cgo (maximum_nocgo.go).
		anon = newMaximumAnonymizer()
	} else {
		anon = NewRegexAnonymizer()
	}
	return &DefaultRedactor{
		level:           level,
		report:          RedactionReport{Counts: make(map[string]int)},
		categories:      make(map[string]bool),
		astAnonymizer:   anon,
		residueDetector: NewResidueDetector(),
		userRules:       userRules,
	}, nil
}

func compileUserPatterns(userPatterns []UserPattern) ([]Rule, error) {
	userRules := make([]Rule, 0, len(userPatterns))
	for i, p := range userPatterns {
		if p.ID == "" {
			return nil, &actionableError{
				what:  fmt.Sprintf("user redaction pattern at index %d has an empty ID", i),
				why:   "every configured pattern needs a stable non-empty identifier",
				where: "pkg/redact compileUserPatterns",
				when:  "NewRedactor compiled configured user patterns before scanning content",
				means: "the pattern cannot be reported or audited safely, so no redactor was created",
				fix:   "set a unique non-empty id for the configured pattern",
			}
		}
		if !p.Category.IsValid() {
			return nil, &actionableError{
				what:  fmt.Sprintf("user redaction pattern %q has invalid category %q", p.ID, p.Category),
				why:   "user patterns must use one of the canonical semantic categories",
				where: "pkg/redact compileUserPatterns",
				when:  "NewRedactor compiled configured user patterns before scanning content",
				means: "the pattern's default activation level cannot be determined, so no redactor was created",
				fix:   "set category to secrets, pii, paths, or project",
			}
		}
		re, err := regexp.Compile(p.Pattern)
		if err != nil {
			return nil, &actionableError{
				what:  fmt.Sprintf("user redaction pattern %q has an invalid regular expression", p.ID),
				why:   "the pattern is not a valid Go regular expression",
				where: "pkg/redact compileUserPatterns",
				when:  "NewRedactor compiled configured user patterns before scanning content",
				means: "the pattern cannot be matched safely, so no redactor was created",
				fix:   fmt.Sprintf("correct the regular expression for configured pattern %q", p.ID),
				cause: err,
			}
		}
		userRules = append(userRules, Rule{
			ID:          p.ID,
			Category:    p.Category,
			Pattern:     re,
			Replacement: p.Replacement,
		})
	}
	return userRules, nil
}

func validateMaximumAvailability(level RedactionLevel, maximumAvailable bool) error {
	// Maximum requires code-aware (tree-sitter) AST anonymization, which is a CGo
	// dependency. In a binary built without cgo (MaximumAvailable == false) it is
	// NOT linked, so fail fast at construction with an actionable error rather
	// than silently applying weaker redaction. This guard covers EVERY Maximum
	// entry point because NewRedactor is the single construction site: the
	// `--redaction maximum` CLI flag (cmd/peasant/cmd_redact.go, cmd_push.go) AND
	// the config-driven push/harvest/kickstart path (cfg.Redaction.Level).
	if level == Maximum && !maximumAvailable {
		return &actionableError{
			what:  "maximum redaction is unavailable in this binary",
			why:   "maximum redaction requires code-aware tree-sitter anonymization, but this binary was built without cgo",
			where: "pkg/redact validateMaximumAvailability",
			when:  "NewRedactor checked runtime capabilities before constructing a maximum-level redactor",
			means: "no redactor was created because silently falling back could leak code identifiers",
			fix:   "use standard redaction in a cgo-free build, or rebuild with cgo using nix develop or make build",
		}
	}
	return nil
}

// buildXDGRules generates path redaction rules for non-standard XDG base directories.
// For each non-empty XDG path that is NOT under /home/ or /Users/ (which are already
// covered by the built-in unix_home_path rule), a rule is generated to redact the
// username segment.
//
// Example: XDG_DATA_HOME=/data/alice/share → generates rule matching /data/{user}/
func buildXDGRules(xdg XDGPaths) []Rule {
	var rules []Rule
	for _, p := range []struct {
		path string
		id   string
	}{
		{xdg.DataHome, "xdg_data_home"},
		{xdg.ConfigHome, "xdg_config_home"},
		{xdg.StateHome, "xdg_state_home"},
	} {
		if p.path == "" {
			continue
		}
		// Skip paths under /home/ or /Users/ — already covered by built-in rules.
		if strings.HasPrefix(p.path, "/home/") || strings.HasPrefix(p.path, "/Users/") {
			continue
		}
		// Extract the username: for /data/alice/share, the username is "alice".
		// We find it by extracting the segment after the first / that looks like a user dir.
		username, prefix := extractXDGUsername(p.path)
		if username == "" || prefix == "" {
			continue
		}
		// Build a regex that matches the prefix + username.
		escapedPrefix := regexp.QuoteMeta(prefix)
		re, err := regexp.Compile(escapedPrefix + regexp.QuoteMeta(username))
		if err != nil {
			continue // skip malformed paths silently
		}
		rules = append(rules, Rule{
			ID:          p.id,
			Category:    CategoryPaths,
			Pattern:     re,
			Replacement: prefix + "<USER>",
		})
	}
	return rules
}

// extractXDGUsername extracts a username from a non-standard XDG path.
// For /data/alice/share, returns ("alice", "/data/").
// For /opt/users/alice/config, returns ("alice", "/opt/users/").
// Returns ("","") if no username segment can be identified.
func extractXDGUsername(path string) (username, prefix string) {
	// Clean the path and split into segments.
	clean := filepath.Clean(path)
	parts := strings.Split(clean, "/")
	// Skip empty first part (from leading /).
	// We need at least /base/user/something → 3+ non-empty segments.
	var nonEmpty []string
	for _, p := range parts {
		if p != "" {
			nonEmpty = append(nonEmpty, p)
		}
	}
	if len(nonEmpty) < 2 {
		return "", ""
	}
	// Heuristic: the second segment is the username.
	// /data/alice/share → segments = [data, alice, share] → user = alice
	username = nonEmpty[1]
	prefix = "/" + nonEmpty[0] + "/"
	return username, prefix
}

// Compile-time guard: DefaultRedactor must implement Redactor.
var _ Redactor = (*DefaultRedactor)(nil)

// isActiveRule reports whether a rule should be applied at the current level.
// A rule-specific minimum overrides the category default without changing the
// rule's semantic category.
func (r *DefaultRedactor) isActiveRule(rule Rule) bool {
	minimum, ok := effectiveMinimumLevel(rule)
	if !ok {
		return true
	}
	return r.level.Ord() >= minimum.Ord()
}

func effectiveMinimumLevel(rule Rule) (RedactionLevel, bool) {
	categoryMinimum, ok := categoryMinimumLevel(rule.Category)
	if !ok {
		return "", false
	}
	if rule.MinimumLevel == "" {
		return categoryMinimum, true
	}
	if !rule.MinimumLevel.IsValid() || rule.MinimumLevel.Ord() < categoryMinimum.Ord() {
		return "", false
	}
	return rule.MinimumLevel, true
}

func categoryMinimumLevel(category Category) (RedactionLevel, bool) {
	switch category {
	case CategorySecrets, CategoryPaths:
		return Minimal, true
	case CategoryPII, CategoryProject:
		return Standard, true
	default:
		return "", false
	}
}

func validateRuleActivationMetadata(rules []Rule) error {
	for _, rule := range rules {
		categoryMinimum, ok := categoryMinimumLevel(rule.Category)
		if !ok {
			return &actionableError{
				what:  fmt.Sprintf("built-in redaction rule %q has invalid category %q", rule.ID, rule.Category),
				why:   "rule activation requires one of the canonical semantic categories",
				where: "pkg/redact validateRuleActivationMetadata",
				when:  "NewRedactor validated built-in rule metadata before scanning content",
				means: "the rule cannot be classified safely, so no redactor was created",
				fix:   "assign the rule to secrets, pii, paths, or project",
			}
		}
		if rule.MinimumLevel == "" {
			continue
		}
		if !rule.MinimumLevel.IsValid() {
			return &actionableError{
				what:  fmt.Sprintf("built-in redaction rule %q has invalid minimum level %q", rule.ID, rule.MinimumLevel),
				why:   "MinimumLevel accepts only minimal, standard, maximum, or empty inheritance",
				where: "pkg/redact validateRuleActivationMetadata",
				when:  "NewRedactor validated built-in rule metadata before scanning content",
				means: "the rule might otherwise be silently disabled, so no redactor was created",
				fix:   fmt.Sprintf("set MinimumLevel to a valid RedactionLevel or leave it empty to inherit %q", categoryMinimum),
			}
		}
		if rule.MinimumLevel.Ord() < categoryMinimum.Ord() {
			return &actionableError{
				what:  fmt.Sprintf("built-in redaction rule %q sets minimum level %q below its %q category default %q", rule.ID, rule.MinimumLevel, rule.Category, categoryMinimum),
				why:   "a per-rule override may make activation stricter, but may not weaken the category default",
				where: "pkg/redact validateRuleActivationMetadata",
				when:  "NewRedactor validated built-in rule metadata before scanning content",
				means: "the override would weaken the category's privacy policy, so no redactor was created",
				fix:   fmt.Sprintf("remove MinimumLevel to inherit %q or choose a stricter level", categoryMinimum),
			}
		}
	}
	return nil
}

// recordRedaction updates the report under the mutex.
func (r *DefaultRedactor) recordRedaction(ruleID string, cat Category, count int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.report.TotalRedactions += count
	r.report.Counts[ruleID] += count

	// Track unique categories via map for O(1) membership test.
	catStr := string(cat)
	if !r.categories[catStr] {
		r.categories[catStr] = true
		r.report.Categories = append(r.report.Categories, catStr)
	}
}

// categoryForRule looks up the Category for a given rule ID.
// It searches built-in Rules first, then userRules.
// Returns CategorySecrets as a safe default if the rule ID is not found.
// This method reads r.userRules (set at construction, read-only after init) without locking,
// which is safe because userRules is never mutated after NewRedactor returns.
func (r *DefaultRedactor) categoryForRule(ruleID string) Category {
	for _, rule := range Rules {
		if rule.ID == ruleID {
			return rule.Category
		}
	}
	for _, rule := range r.userRules {
		if rule.ID == ruleID {
			return rule.Category
		}
	}
	return CategorySecrets // safe default: fail towards more redaction
}

// applyAllRules applies ALL rules (all categories) to text, used in fail-closed
// recovery. Rules that explicitly require Maximum run first so a narrow,
// high-protection match can consume its full span before a broader rule matches
// a prefix. In particular, an SCP-style git remote must become <PROJECT_URL>,
// not <EMAIL> followed by its unredacted repository path.
//
// FilterFn is intentionally not called here. This function is the panic
// recovery path, and the filter itself may have caused the panic.
func applyAllRules(input string) string {
	out := input
	for _, rule := range Rules {
		if rule.MinimumLevel != Maximum {
			continue
		}
		out = applyRule(rule, out)
	}
	for _, rule := range Rules {
		if rule.MinimumLevel == Maximum {
			continue
		}
		out = applyRule(rule, out)
	}
	return out
}

// applyRule replaces all matches of rule.Pattern with rule.Replacement.
// It handles back-reference syntax (${1}, ${2}, etc.) used by path and sentinel-preserving rules.
// Rules with nil Pattern are silently skipped.
func applyRule(rule Rule, s string) string {
	if rule.Pattern == nil {
		return s
	}
	if strings.Contains(rule.Replacement, "$") {
		// Use ReplaceAllString which supports $1 / ${1} / ${2} back-references.
		return rule.Pattern.ReplaceAllString(s, rule.Replacement)
	}
	return rule.Pattern.ReplaceAllLiteralString(s, rule.Replacement)
}

// maskCodeBlocks replaces fenced code blocks with <CODE_BLOCK>.
// The pattern handles:
//   - Standard fences (```)
//   - Indented fences (leading spaces or tabs before backticks)
//   - Longer fences (4+ backticks) used to nest inner fences
//
// Note: Go's regexp (RE2) does not support backreferences, so the closing fence
// is matched by the same minimum-backtick class (`{3,}) rather than by exact
// repetition count. This correctly handles the common cases and does not produce
// false positives for prose text.
//
// The leading newline (before the opening fence) is included in the match so
// that surrounding text is joined cleanly after replacement.
//
// This prevents false positives from code samples in the redaction pipeline.
var codeBlockPattern = regexp.MustCompile("(?s)\\n[ \\t]*`{3,}[^\\n]*\\n.*?\\n[ \\t]*`{3,}[ \\t]*(?:\\n|$)")

func maskCodeBlocks(s string) string {
	return codeBlockPattern.ReplaceAllLiteralString(s, "<CODE_BLOCK>")
}

// RedactText applies the redaction pipeline to plain text:
//  1. Code block masking (v1; replaced by AST anonymization at Maximum in v2)
//  2. Level-gated regex rules: built-ins use category defaults plus optional
//     per-rule minimums; user-defined rules inherit their category default
//  3. Entropy detection (Maximum only)
//  4. Residue scan (advisory — appends to Report().Warnings, never modifies content)
//
// Thread-safe. Fail-closed: panics are recovered and maximum-level rules are applied.
func (r *DefaultRedactor) RedactText(input string) (output string) {
	defer func() {
		if rec := recover(); rec != nil {
			// Fail-closed: apply maximum redaction as fallback.
			// Redaction counts are intentionally NOT tracked here: the panic may
			// have occurred while r.mu was held (e.g. inside recordRedaction),
			// so acquiring the mutex again would deadlock. Accepting the count
			// gap is safer than risking a second panic or deadlock.
			fallback := maskCodeBlocks(input)
			fallback = applyAllRules(fallback)
			// Apply user rules in fail-closed path. userRules is set at construction
			// and never mutated, so reading it without the mutex is safe.
			for _, rule := range r.userRules {
				fallback = applyRule(rule, fallback)
			}
			fallback = detectEntropyInWords(fallback)
			output = fallback
		}
	}()

	// Step 1: Code block handling.
	// At Maximum: AST anonymization (replaces identifiers, preserves structure).
	// At Standard/Minimal: v1 code block masking (replaces entire block with <CODE_BLOCK>).
	var out string
	if r.level == Maximum && r.astAnonymizer != nil {
		out = anonymizeCodeBlocks(r.astAnonymizer, input)
	} else {
		out = maskCodeBlocks(input)
	}

	// Step 2: Level-gated regex rules with post-match filtering.
	// Uses Detect→Redact pipeline. Detect() applies FilterFn per-rule.
	// Note: Detect() also stores matches in r.lastMatches (last-call-only semantics),
	// so after RedactText returns, Report().Matches contains the filtered matches.
	// This is a documented behavioral change from v3: previously Report().Matches
	// was only populated by explicit Detect() calls; now RedactText also records
	// the filtered matches it used.
	stepMatches := r.Detect(out)
	if len(stepMatches) > 0 {
		out = r.Redact(out, stepMatches)
		// Record redaction counts per rule.
		counts := make(map[string]int)
		for _, m := range stepMatches {
			counts[m.Rule]++
		}
		for ruleID, count := range counts {
			cat := r.categoryForRule(ruleID)
			r.recordRedaction(ruleID, cat, count)
		}
	}

	if r.level == Maximum {
		out = detectEntropyInWords(out)
	}

	// Residue scan: advisory, appends warnings to report. Never modifies content.
	if r.residueDetector != nil {
		warnings := r.residueDetector.Scan(out)
		if len(warnings) > 0 {
			// defer is intentionally not used here: the lock covers only the
			// append loop, and we want to release as soon as the loop exits
			// rather than holding it until RedactText returns. Using a named
			// func(){...}() scope with defer would work but adds indentation
			// with no benefit over the explicit Unlock below.
			r.mu.Lock()
			for _, w := range warnings {
				r.report.Warnings = append(r.report.Warnings,
					fmt.Sprintf("[residue:%s at %d] %s", w.RuleID, w.Location, w.Preview))
			}
			r.mu.Unlock()
		}
	}

	return out
}

// RedactJSON recursively descends through a JSON-decoded value and redacts strings.
// Supported types: string, []any, map[string]any, json.Number. Other types pass through unchanged.
// json.Number is returned as-is: integers > 2^53 decoded via UseNumber() retain full precision.
func (r *DefaultRedactor) RedactJSON(value any) any {
	switch v := value.(type) {
	case string:
		return r.RedactText(v)
	case json.Number:
		return value
	case []any:
		result := make([]any, len(v))
		for i, elem := range v {
			result[i] = r.RedactJSON(elem)
		}
		return result
	case map[string]any:
		result := make(map[string]any, len(v))
		for key, val := range v {
			result[key] = r.RedactJSON(val)
		}
		return result
	default:
		return value
	}
}

// privateMetadata holds private identifiers extracted from session metadata.
// Used by the metadata redaction pipeline to build context-aware replacers.
type privateMetadata struct {
	username string // OS username (e.g., "alice")
	prefix   string // home directory prefix with trailing slash (e.g., "/home/alice/")
	cwd      string // working directory from the original metadata
}

// extractPrivateMetadata extracts private identifiers from metadata.
// The username and prefix are parsed from Source.FilePath using /home/{user}/
// or /Users/{user}/ conventions. CWD is copied verbatim.
// Pure function — no receiver needed.
func extractPrivateMetadata(meta *schema.UnifiedMetadata) privateMetadata {
	username, prefix := parseUsername(meta.Source.FilePath)
	return privateMetadata{
		username: username,
		prefix:   prefix,
		cwd:      meta.CWD,
	}
}

// parseUsername extracts the OS username from a literal path prefix.
// Returns ("alice", "/home/alice/") for "/home/alice/.claude/projects/..."
// Returns ("jean-luc", "/home/jean-luc/") for "/home/jean-luc/dev/..."
// Returns ("", "") if the path doesn't match /home/{user}/ or /Users/{user}/.
func parseUsername(path string) (username string, prefix string) {
	for _, base := range []string{"/home/", "/Users/"} {
		if strings.HasPrefix(path, base) {
			rest := path[len(base):]
			idx := strings.Index(rest, "/")
			if idx > 0 {
				return rest[:idx], base + rest[:idx] + "/"
			}
		}
	}
	return "", ""
}

// buildPrivateReplacer creates a strings.Replacer that replaces username and
// intermediate path components across all three separator formats: literal
// path separator (/), Claude single-dash (-), and Peasant double-dash (--).
//
// All three formats use the same logic:
//
//	{sep}home{sep}{username}{sep}{intermediate}{sep} → {sep}home{sep}<USER>{sep}<PATH>{sep}
//	{sep}home{sep}{username}{sep}                    → {sep}home{sep}<USER>{sep}
//
// Given username="alice", cwd="/home/alice/dev/myproject":
//
//	"/home/alice/dev/"        → "/home/<USER>/<PATH>/"
//	"-home-alice-dev-"        → "-home-<USER>-<PATH>-"
//	"--home--alice--dev--"    → "--home--<USER>--<PATH>--"
//
// When there is no intermediate path (project directly under home):
//
//	"/home/alice/"            → "/home/<USER>/"
//	"-home-alice-"            → "-home-<USER>-"
//	"--home--alice--"         → "--home--<USER>--"
func buildPrivateReplacer(id privateMetadata) *strings.Replacer {
	if id.username == "" || id.prefix == "" {
		return strings.NewReplacer() // no-op
	}

	// Determine the OS prefix base (either "home" or "Users").
	osBase := "home"
	if strings.HasPrefix(id.prefix, "/Users/") {
		osBase = "Users"
	}

	var oldNew []string

	// Determine intermediate path from CWD if available.
	// CWD like "/home/alice/dev/project" → rest = "dev/project" → intermediate = "dev"
	var intermediate string
	if id.cwd != "" {
		_, cwdPrefix := parseUsername(id.cwd)
		if cwdPrefix != "" {
			rest := strings.TrimSuffix(id.cwd[len(cwdPrefix):], "/")
			if rest != "" {
				parts := strings.Split(rest, "/")
				if len(parts) > 1 {
					intermediate = strings.Join(parts[:len(parts)-1], "/")
				}
			}
		}
	}

	// Generate replacements for all three separator formats.
	separators := []string{"/", "-", "--"}
	for _, sep := range separators {
		if intermediate != "" {
			// With intermediate: {sep}home{sep}user{sep}intermediate{sep} → {sep}home{sep}<USER>{sep}<PATH>{sep}
			intermediateSep := strings.ReplaceAll(intermediate, "/", sep)
			oldNew = append(oldNew,
				sep+osBase+sep+id.username+sep+intermediateSep+sep,
				sep+osBase+sep+"<USER>"+sep+"<PATH>"+sep,
			)
		}
		// Username-only: {sep}home{sep}user{sep} → {sep}home{sep}<USER>{sep}
		// This handles: no intermediate, partial matches, and direct home paths.
		oldNew = append(oldNew,
			sep+osBase+sep+id.username+sep,
			sep+osBase+sep+"<USER>"+sep,
		)
	}

	return strings.NewReplacer(oldNew...)
}

// RedactMetadata returns a deep copy of meta with sensitive fields redacted.
// The original meta pointer is never mutated.
//
// Redaction is applied in two stages:
//  1. redactPrivatePaths — context-aware slug/path replacement using extracted identifiers
//  2. redactAllFields — standard RedactText on all sensitive fields (secrets, PII, remaining paths)
//
// Fields redacted: Source.FilePath, CWD, HostSlug, Git.Remote/Branch/Worktree/Tracking,
// Project.FilePath/Name, Diagnostics.Warnings[i].Location/Message.
func (r *DefaultRedactor) RedactMetadata(meta *schema.UnifiedMetadata) *schema.UnifiedMetadata {
	if meta == nil {
		return nil
	}

	// Deep copy: start with a struct copy (value semantics for non-pointer fields).
	redacted := *meta

	identifiers := extractPrivateMetadata(meta)
	redactPrivatePaths(&redacted, identifiers)
	r.redactAllFields(&redacted, meta)

	return &redacted
}

// redactPrivatePaths applies context-aware path and slug redaction to the metadata copy.
// If no username was extracted, this is a no-op. Otherwise it builds a unified replacer
// that handles all three separator formats (/, -, --) and applies it to path-bearing fields.
// Free function — no receiver needed.
func redactPrivatePaths(redacted *schema.UnifiedMetadata, id privateMetadata) {
	if id.username == "" {
		return
	}
	replacer := buildPrivateReplacer(id)
	redacted.Source.FilePath = replacer.Replace(redacted.Source.FilePath)
	redacted.Project.FilePath = replacer.Replace(redacted.Project.FilePath)
	redacted.Project.Name = replacer.Replace(redacted.Project.Name)
	redacted.HostSlug = schema.HostSlug(replacer.Replace(string(redacted.HostSlug)))
	redacted.CWD = replacer.Replace(redacted.CWD)
}

// redactAllFields applies r.RedactText() to all sensitive fields of the metadata copy.
// Deep-copies pointer fields (Git) and slice fields (Diagnostics, Subagents) from
// the original to avoid aliasing.
func (r *DefaultRedactor) redactAllFields(redacted *schema.UnifiedMetadata, original *schema.UnifiedMetadata) {
	// Source and CWD.
	redacted.Source.FilePath = r.RedactText(redacted.Source.FilePath)
	redacted.CWD = r.RedactText(redacted.CWD)

	// HostSlug — RedactText for any remaining patterns.
	redacted.HostSlug = schema.HostSlug(r.RedactText(string(redacted.HostSlug)))

	// Git (nullable pointer fields — copy the pointed-to string if non-nil).
	if original.Git.Remote != nil {
		v := r.RedactText(*original.Git.Remote)
		redacted.Git.Remote = &v
	}
	if original.Git.Branch != nil {
		v := r.RedactText(*original.Git.Branch)
		redacted.Git.Branch = &v
	}
	if original.Git.Worktree != nil {
		v := r.RedactText(*original.Git.Worktree)
		redacted.Git.Worktree = &v
	}
	if original.Git.Tracking != nil {
		v := r.RedactText(*original.Git.Tracking)
		redacted.Git.Tracking = &v
	}

	// Project.
	redacted.Project.FilePath = r.RedactText(redacted.Project.FilePath)
	redacted.Project.Name = r.RedactText(redacted.Project.Name)

	// Diagnostics — copy the slice so we don't alias the original.
	if len(original.Diagnostics.Warnings) > 0 {
		warnings := make([]schema.DiagnosticEntry, len(original.Diagnostics.Warnings))
		for i, w := range original.Diagnostics.Warnings {
			warnings[i] = schema.DiagnosticEntry{
				ErrorType:   w.ErrorType,
				Location:    r.RedactText(w.Location),
				Message:     r.RedactText(w.Message),
				Remediation: w.Remediation,
			}
		}
		redacted.Diagnostics.Warnings = warnings
	}

	// Subagents slice — shallow copy is fine (no sensitive fields in SubagentRef).
	redacted.Subagents = slices.Clone(original.Subagents)
}

// Level returns the redaction level as a string.
func (r *DefaultRedactor) Level() string {
	return r.level.String()
}

// RuleSetVersion returns the semantic version of the compiled rule set.
// Delegates to the package-level Version() function.
func (r *DefaultRedactor) RuleSetVersion() string {
	return Version()
}

// Report returns a copy of the current RedactionReport.
// The Matches field contains the matches from the last Detect() call (last-call-only).
func (r *DefaultRedactor) Report() RedactionReport {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Return a copy so callers cannot mutate the internal state.
	counts := make(map[string]int, len(r.report.Counts))
	for k, v := range r.report.Counts {
		counts[k] = v
	}
	categories := make([]string, len(r.report.Categories))
	copy(categories, r.report.Categories)
	warnings := make([]string, len(r.report.Warnings))
	copy(warnings, r.report.Warnings)

	// Copy lastMatches for the caller.
	var matchesCopy []Match
	if len(r.lastMatches) > 0 {
		matchesCopy = make([]Match, len(r.lastMatches))
		copy(matchesCopy, r.lastMatches)
	}

	return RedactionReport{
		TotalRedactions: r.report.TotalRedactions,
		Counts:          counts,
		Categories:      categories,
		Warnings:        warnings,
		Matches:         matchesCopy,
	}
}

// Option configures the redactor. Options are applied in order and only affect
// the specific parameter they override; all other parameters use their defaults.
type Option func(*redactorConfig)

type redactorConfig struct {
	scannerInitBuf int
	scannerMaxLine int
}

// WithScannerBufSize overrides the default scanner buffer sizes.
// Default: DefaultScannerInitBuf (64 KiB) and DefaultScannerMaxLine (10 MiB).
func WithScannerBufSize(initBuf, maxLine int) Option {
	return func(c *redactorConfig) {
		c.scannerInitBuf = initBuf
		c.scannerMaxLine = maxLine
	}
}

// RedactJSONLBytesOption configures the standalone RedactJSONLBytes function.
type RedactJSONLBytesOption func(*scannerConfig)

type scannerConfig struct {
	initBuf int
	maxLine int
}

// WithRedactScannerBufSize overrides the default buffer sizes for RedactJSONLBytes.
// Default: DefaultScannerInitBuf (64 KiB) and DefaultScannerMaxLine (10 MiB).
func WithRedactScannerBufSize(initBuf, maxLine int) RedactJSONLBytesOption {
	return func(c *scannerConfig) {
		c.initBuf = initBuf
		c.maxLine = maxLine
	}
}
