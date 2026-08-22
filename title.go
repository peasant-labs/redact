package redact

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"github.com/peasant-labs/schema"
)

const titleCodePointLimit = 80

// TitleContext identifies the harness and exact project root for title
// cleanup and context-aware path normalization.
type TitleContext struct {
	Harness     schema.Harness
	ProjectPath string
}

// TitleResult contains canonical title text and the ordered categories whose
// sensitive content was replaced during this call.
type TitleResult struct {
	Text       string
	Categories []CategoryString
}

// HasSensitiveContent reports whether this call replaced sensitive content.
func (r TitleResult) HasSensitiveContent() bool { return len(r.Categories) != 0 }

// TitlePipeline is an immutable, concurrency-safe baseline-Standard title
// pipeline. Runtime redactor configuration cannot extend its fixed policy.
type TitlePipeline struct {
	rules []Rule
}

// NewTitlePipeline constructs the fixed baseline-Standard title policy.
func NewTitlePipeline() (*TitlePipeline, error) {
	if err := validateRuleActivationMetadata(Rules); err != nil {
		return nil, &actionableError{what: "the transcript title pipeline could not be constructed", why: "the compiled baseline Standard rule metadata is invalid", where: "redact.NewTitlePipeline", when: "constructing the title pipeline before any title was processed", means: "no title can be generated or validated safely", fix: "restore valid built-in rule categories and activation levels, then construct the pipeline again", cause: err}
	}
	rules := make([]Rule, 0, len(Rules))
	for _, rule := range Rules {
		minimum, ok := effectiveMinimumLevel(rule)
		if ok && Standard.Ord() >= minimum.Ord() {
			rules = append(rules, rule)
		}
	}
	return &TitlePipeline{rules: rules}, nil
}

// Generate cleans markup owned by the supplied harness, sanitizes the result,
// and always applies generated-title whitespace trimming and length capping.
//
// Two results tell the caller to move on to the next user turn:
//
//   - An empty Text means the turn held no user prose once harness-owned markup
//     was removed. The caller must not store an empty title; it tries the next
//     user turn.
//   - An error means the turn is unusable because its recognized markup is
//     unbalanced, crossed, or nested, so cleaning cannot be proven complete. The
//     caller must not expose the raw turn text; it tries the next user turn, or
//     falls back to a generic title.
//
// GenerateFromTurns applies both rules for the caller.
func (p *TitlePipeline) Generate(firstTurn string, context TitleContext) (TitleResult, error) {
	if p == nil {
		return TitleResult{}, nilTitlePipelineError("Generate", "generating a title from the first user turn")
	}
	if firstTurn == "" {
		return TitleResult{Text: ""}, nil
	}
	cleaned, err := cleanHarnessTitle(firstTurn, context.Harness)
	if err != nil {
		return TitleResult{}, err
	}
	return p.process(cleaned, context), nil
}

// Sanitize never interprets harness markup. It preserves exact input bytes when
// no sensitive rewrite occurs and the title is within the length limit; a
// sensitive or over-limit title returns its canonical rewritten or capped text.
func (p *TitlePipeline) Sanitize(title string, context TitleContext) (TitleResult, error) {
	if p == nil {
		return TitleResult{}, nilTitlePipelineError("Sanitize", "sanitizing a supplied title")
	}
	if title == "" {
		return TitleResult{Text: ""}, nil
	}
	result := p.process(title, context)
	if !result.HasSensitiveContent() && len([]rune(title)) <= titleCodePointLimit {
		result.Text = title
	}
	return result, nil
}

// SimpleTitle cleans harness-owned markup and caps length WITHOUT redaction.
// It does NOT remove secrets, PII, paths, or user identifiers. Its output is
// for local, trusted display only (e.g. a first-time-setup selection list) and
// MUST NOT be stored or published as a transcript title. Use Generate for any
// published title.
//
// It reports the same two "try the next user turn" outcomes as Generate: an
// empty string means the turn held no user prose once harness-owned markup was
// removed, and an error means the turn is unusable and its raw text must not be
// exposed.
func (p *TitlePipeline) SimpleTitle(firstTurn string, harness schema.Harness) (string, error) {
	if p == nil {
		return "", nilTitlePipelineError("SimpleTitle", "cleaning a first user turn for local trusted display without redaction")
	}
	if firstTurn == "" {
		return "", nil
	}
	cleaned, err := cleanHarnessTitle(firstTurn, harness)
	if err != nil {
		return "", err
	}
	return capTitle(cleaned), nil
}

// GenerateFromTurns returns the first usable generated title in turn order.
//
// It defines the turn-selection contract once, so every caller skips the same
// turns: a turn that cleans to empty text carries no user prose, and a turn that
// fails to clean is unusable. Both are skipped, and each per-turn error is
// collected in skipped so a caller can log or count it. The errors never contain
// raw turn text.
//
// It returns the first usable result with the index of the turn that produced
// it, or an empty result and index -1 when no turn is usable. A nil receiver
// returns index -1 and the shared nil-receiver diagnostic in skipped.
func (p *TitlePipeline) GenerateFromTurns(turns []string, context TitleContext) (TitleResult, int, []error) {
	if p == nil {
		return TitleResult{}, -1, []error{nilTitlePipelineError("GenerateFromTurns", "selecting the first usable title from the ordered user turns")}
	}
	var skipped []error
	for index, turn := range turns {
		result, err := p.Generate(turn, context)
		if err != nil {
			skipped = append(skipped, err)
			continue
		}
		if result.Text == "" {
			continue
		}
		return result, index, skipped
	}
	return TitleResult{}, -1, skipped
}

func nilTitlePipelineError(method, operation string) error {
	return &actionableError{what: "the transcript title pipeline receiver is nil", why: "the title method was called before NewTitlePipeline returned a usable pipeline", where: "redact.(*TitlePipeline)." + method, when: operation, means: "the title was not processed and must not be stored as safe", fix: "construct one pipeline with redact.NewTitlePipeline and inject that non-nil value before processing titles"}
}

func (p *TitlePipeline) process(input string, context TitleContext) TitleResult {
	pathNormalized, pathChanged := normalizeTitlePaths(input, context.ProjectPath)
	text, detected := redactTitleRules(pathNormalized, p.rules)
	if pathChanged {
		detected[CategoryStringPath] = struct{}{}
	}
	return TitleResult{Text: capTitle(text), Categories: orderedTitleCategories(detected)}
}

// Harness-owned markup wrapper names. A harness injects these blocks into a
// recorded user turn: they carry command scaffolding, tool output, or system
// context, never user prose. They are exported so every consumer of a recorded
// transcript names the same markup as this package instead of repeating string
// literals.
const (
	WrapperSystemReminder     = "system-reminder"
	WrapperUserQuery          = "user_query"
	WrapperCommandName        = "command-name"
	WrapperCommandMessage     = "command-message"
	WrapperCommandArgs        = "command-args"
	WrapperLocalCommandCaveat = "local-command-caveat"
	WrapperLocalCommandStdout = "local-command-stdout"
	WrapperLocalCommandStderr = "local-command-stderr"
	WrapperTaskNotification   = "task-notification"
	WrapperTeammateMessage    = "teammate-message"
	WrapperEnvironmentContext = "environment_context"
	WrapperSystemContext      = "system-context"
)

// SkillBodyPrefix opens a skill body that a harness injects as a complete user
// turn. A turn whose trimmed text starts with this prefix carries no user prose.
const SkillBodyPrefix = "Base directory for this skill:"

// titleWrapperAction is the closed set of cleanup actions for one recognized
// wrapper.
type titleWrapperAction uint8

const (
	// titleWrapperDrop removes the wrapper and everything inside it.
	titleWrapperDrop titleWrapperAction = iota
	// titleWrapperUnwrap removes the wrapper tags and keeps the inner text.
	titleWrapperUnwrap
)

// titleWrapperRule pairs one recognized wrapper name with its cleanup action.
type titleWrapperRule struct {
	name   string
	action titleWrapperAction
}

// titleWrapperRules is the closed, per-harness table of wrappers the title
// pipeline cleans, in cleanup order. A harness absent from this table keeps its
// first turn verbatim, and a wrapper absent from a listed harness stays literal
// in that harness's titles.
var titleWrapperRules = map[schema.Harness][]titleWrapperRule{
	schema.HarnessClaudeCode: {
		{name: WrapperSystemReminder, action: titleWrapperDrop},
		{name: WrapperLocalCommandCaveat, action: titleWrapperDrop},
		{name: WrapperLocalCommandStdout, action: titleWrapperDrop},
		{name: WrapperLocalCommandStderr, action: titleWrapperDrop},
		{name: WrapperCommandName, action: titleWrapperDrop},
		{name: WrapperCommandMessage, action: titleWrapperDrop},
		{name: WrapperTaskNotification, action: titleWrapperDrop},
		{name: WrapperTeammateMessage, action: titleWrapperDrop},
		{name: WrapperEnvironmentContext, action: titleWrapperDrop},
		{name: WrapperUserQuery, action: titleWrapperUnwrap},
		{name: WrapperCommandArgs, action: titleWrapperUnwrap},
	},
	schema.HarnessCodex: {
		{name: WrapperEnvironmentContext, action: titleWrapperDrop},
	},
	schema.HarnessOpenCode: {
		{name: WrapperSystemContext, action: titleWrapperDrop},
	},
}

// titleWholeTurnPrefixRules is the closed, per-harness table of prefixes that
// mark a whole injected turn. A turn whose trimmed text starts with one of them
// cleans to the empty string, whatever else the turn contains.
var titleWholeTurnPrefixRules = map[schema.Harness][]string{
	schema.HarnessClaudeCode: {SkillBodyPrefix},
}

// titleWrapperNames returns the recognized wrapper names for one harness, in
// cleanup order. The returned slice is a copy, so a caller cannot widen or
// narrow the compiled policy.
func titleWrapperNames(harness schema.Harness) []string {
	rules := titleWrapperRules[harness]
	names := make([]string, 0, len(rules))
	for _, rule := range rules {
		names = append(names, rule.name)
	}
	return names
}

// titleWholeTurnPrefixes returns the whole-turn injection prefixes for one
// harness. The returned slice is a copy.
func titleWholeTurnPrefixes(harness schema.Harness) []string {
	return append([]string(nil), titleWholeTurnPrefixRules[harness]...)
}

// titleTagTail matches the end of an opening or closing wrapper tag. It accepts
// attributes (real data carries them, for example
// <system-context source="bd-prime.md">) but requires whitespace before them, so
// a longer unlisted tag name can never match a listed one.
const titleTagTail = `(?:\s[^>]*)?>`

// titleWrapper is one compiled wrapper: the whole block, plus its opening and
// closing tags for the balance and residue fail-safes.
type titleWrapper struct {
	name   string
	action titleWrapperAction
	block  *regexp.Regexp
	open   *regexp.Regexp
	closes *regexp.Regexp
}

// titleCleanPolicy is the compiled cleanup policy for one harness. The
// structural token pattern is derived from the same names as the wrappers, so
// the table is the single source of truth for what the validator recognizes.
type titleCleanPolicy struct {
	wrappers []titleWrapper
	tokens   *regexp.Regexp
	prefixes []string
}

var titleCleanPolicies = compileTitleCleanPolicies()

func compileTitleCleanPolicies() map[schema.Harness]titleCleanPolicy {
	policies := make(map[schema.Harness]titleCleanPolicy, len(titleWrapperRules))
	for harness, rules := range titleWrapperRules {
		policy := titleCleanPolicy{
			wrappers: make([]titleWrapper, 0, len(rules)),
			prefixes: titleWholeTurnPrefixes(harness),
		}
		names := make([]string, 0, len(rules))
		for _, rule := range rules {
			quoted := regexp.QuoteMeta(rule.name)
			policy.wrappers = append(policy.wrappers, titleWrapper{
				name:   rule.name,
				action: rule.action,
				block:  regexp.MustCompile(`(?s)<` + quoted + titleTagTail + `(.*?)</` + quoted + titleTagTail),
				open:   regexp.MustCompile(`<` + quoted + titleTagTail),
				closes: regexp.MustCompile(`</` + quoted + titleTagTail),
			})
			names = append(names, quoted)
		}
		policy.tokens = regexp.MustCompile(`</?(?:` + strings.Join(names, "|") + `)` + titleTagTail)
		policies[harness] = policy
	}
	return policies
}

func cleanHarnessTitle(input string, harness schema.Harness) (string, error) {
	policy, recognized := titleCleanPolicies[harness]
	if !recognized {
		return input, nil
	}
	trimmed := strings.TrimSpace(input)
	for _, prefix := range policy.prefixes {
		if strings.HasPrefix(trimmed, prefix) {
			return "", nil
		}
	}
	if err := validateTitleWrapperStructure(input, policy.tokens); err != nil {
		return "", err
	}
	out := input
	for _, wrapper := range policy.wrappers {
		if len(wrapper.open.FindAllStringIndex(out, -1)) != len(wrapper.closes.FindAllStringIndex(out, -1)) {
			return "", &actionableError{what: fmt.Sprintf("recognized transcript wrapper %q is unbalanced", wrapper.name), why: "the indexed first-turn content contains an opening or closing wrapper without its matching pair", where: "redact.(*TitlePipeline).Generate", when: "cleaning harness markup before title redaction", means: "no title was generated because partial wrapper content could contain system-injected text", fix: "supply the complete first user turn or use the caller's safe generic-title fallback"}
		}
		for wrapper.block.MatchString(out) {
			if wrapper.action == titleWrapperDrop {
				out = wrapper.block.ReplaceAllString(out, "")
			} else {
				out = wrapper.block.ReplaceAllString(out, "$1")
			}
		}
		if wrapper.open.MatchString(out) || wrapper.closes.MatchString(out) {
			return "", &actionableError{what: fmt.Sprintf("recognized transcript wrapper %q is malformed", wrapper.name), why: "the wrapper boundaries are crossed or nested in a form that cannot be cleaned deterministically", where: "redact.(*TitlePipeline).Generate", when: "cleaning harness markup before title redaction", means: "no title was generated because unchecked wrapper content could contain system-injected text", fix: "supply a complete non-nested first user turn or use the caller's safe generic-title fallback"}
		}
	}
	return strings.TrimSpace(out), nil
}

func validateTitleWrapperStructure(input string, tokens *regexp.Regexp) error {
	var stack []string
	nested := ""
	for _, location := range tokens.FindAllStringIndex(input, -1) {
		token := input[location[0]:location[1]]
		closing := strings.HasPrefix(token, "</")
		name := titleWrapperTokenName(token)
		if !closing {
			if len(stack) != 0 && nested == "" {
				nested = name
			}
			stack = append(stack, name)
			continue
		}
		if len(stack) == 0 || stack[len(stack)-1] != name {
			return malformedTitleWrapperError(name, "crossed")
		}
		stack = stack[:len(stack)-1]
	}
	if len(stack) != 0 {
		return malformedTitleWrapperError(stack[len(stack)-1], "unbalanced")
	}
	if nested != "" {
		return malformedTitleWrapperError(nested, "nested")
	}
	return nil
}

// titleWrapperTokenName returns the wrapper name inside one opening or closing
// tag, discarding any attributes.
func titleWrapperTokenName(token string) string {
	name := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(token, "</"), "<"), ">")
	if cut := strings.IndexFunc(name, unicode.IsSpace); cut >= 0 {
		name = name[:cut]
	}
	return name
}

func malformedTitleWrapperError(name, shape string) error {
	return &actionableError{what: fmt.Sprintf("recognized transcript wrapper %q is %s", name, shape), why: "the wrapper boundaries cannot be cleaned deterministically", where: "redact.(*TitlePipeline).Generate", when: "cleaning harness markup before title redaction", means: "no title was generated because unchecked wrapper content could contain system-injected text", fix: "supply a complete non-nested first user turn or use the caller's safe generic-title fallback"}
}

var (
	unixSpacedTitlePathPattern    = regexp.MustCompile(`/(?:Users|home)/[^/\s]+ [^/\s]+/[^\s]+`)
	windowsSpacedTitlePathPattern = regexp.MustCompile(`(?i)[A-Z]:\\Users\\[^\\\s]+ [^\\\s]+\\[^\s]+`)
	unixTitlePathPattern          = regexp.MustCompile(`/(?:Users|home)/[^/\s]+(?:/[^\s]+)*`)
	windowsTitlePathPattern       = regexp.MustCompile(`(?i)[A-Z]:\\Users\\[^\\\s]+(?:\\[^\s]+)*`)
)

func normalizeTitlePaths(input, projectPath string) (string, bool) {
	changed := false
	if replacement, ok := normalizedProjectRoot(projectPath); ok {
		input = replaceExactProjectPaths(input, projectPath, replacement, &changed)
	}
	normalize := func(candidate string, windows bool) string {
		replacement := normalizeOneTitlePath(candidate, projectPath, windows)
		if replacement != candidate {
			changed = true
		}
		return replacement
	}
	out := unixSpacedTitlePathPattern.ReplaceAllStringFunc(input, func(path string) string { return normalize(path, false) })
	out = windowsSpacedTitlePathPattern.ReplaceAllStringFunc(out, func(path string) string { return normalize(path, true) })
	out = unixTitlePathPattern.ReplaceAllStringFunc(out, func(path string) string { return normalize(path, false) })
	out = windowsTitlePathPattern.ReplaceAllStringFunc(out, func(path string) string { return normalize(path, true) })
	return out, changed
}

func normalizedProjectRoot(projectPath string) (string, bool) {
	if strings.HasPrefix(projectPath, "/Users/") || strings.HasPrefix(projectPath, "/home/") {
		prefix := "/Users/"
		if strings.HasPrefix(projectPath, "/home/") {
			prefix = "/home/"
		}
		rest := strings.TrimPrefix(strings.TrimSuffix(projectPath, "/"), prefix)
		separator := strings.Index(rest, "/")
		if separator < 1 {
			return "", false
		}
		project := filepath.Base(projectPath)
		return prefix + "<USER>/<PATH>/" + project, true
	}
	slash := strings.ReplaceAll(projectPath, `\`, "/")
	if len(slash) >= 10 && slash[1] == ':' && strings.EqualFold(slash[2:9], "/Users/") {
		rest := strings.TrimSuffix(slash[9:], "/")
		separator := strings.Index(rest, "/")
		if separator < 1 {
			return "", false
		}
		parts := strings.Split(rest, "/")
		return slash[:3] + "Users/<USER>/<PATH>/" + parts[len(parts)-1], true
	}
	return "", false
}

func replaceExactProjectPaths(input, projectPath, normalizedRoot string, changed *bool) string {
	if projectPath == "" {
		return input
	}
	windows := strings.Contains(projectPath, `\`)
	searchInput, searchProject := input, strings.TrimSuffix(projectPath, `/\`)
	if windows {
		searchInput, searchProject = strings.ToLower(input), strings.ToLower(searchProject)
	}
	var output strings.Builder
	for {
		index := strings.Index(searchInput, searchProject)
		if index < 0 {
			output.WriteString(input)
			break
		}
		end := index + len(searchProject)
		if end < len(input) && input[end] != '/' && input[end] != '\\' && !isTitlePathTerminator(rune(input[end])) {
			output.WriteString(input[:index+1])
			input, searchInput = input[index+1:], searchInput[index+1:]
			continue
		}
		for end < len(input) && !isTitlePathTerminator(rune(input[end])) {
			end++
		}
		suffix := input[index+len(searchProject) : end]
		output.WriteString(input[:index])
		if windows {
			normalizedRoot = strings.ReplaceAll(normalizedRoot, "/", `\`)
			suffix = strings.ReplaceAll(suffix, `\`, "/")
			suffix = strings.ReplaceAll(suffix, "/", `\`)
		}
		output.WriteString(normalizedRoot)
		output.WriteString(suffix)
		*changed = true
		input, searchInput = input[end:], searchInput[end:]
	}
	return output.String()
}

func isTitlePathTerminator(r rune) bool {
	return unicode.IsSpace(r) || strings.ContainsRune(`"'<>),;]}`, r)
}

func normalizeOneTitlePath(candidate, projectPath string, windows bool) string {
	separator, volume, path, project := "/", "", candidate, projectPath
	if windows {
		separator, volume = `\`, candidate[:3]
		path, project = strings.ReplaceAll(candidate, `\`, "/"), strings.ReplaceAll(projectPath, `\`, "/")
	}
	if strings.Contains(path, "/<USER>/<PATH>") {
		return candidate
	}
	parts := strings.Split(path, "/")
	if len(parts) < 4 {
		return candidate
	}
	base := strings.Join(parts[:2], "/") + "/<USER>/<PATH>"
	project = strings.TrimSuffix(filepath.ToSlash(project), "/")
	if project != "" && (path == project || strings.HasPrefix(path, project+"/")) {
		projectParts := strings.Split(project, "/")
		base += "/" + projectParts[len(projectParts)-1]
		if relative := strings.TrimPrefix(path[len(project):], "/"); relative != "" {
			base += "/" + relative
		}
	}
	if windows {
		volumeSlash := strings.ReplaceAll(volume, `\`, "/")
		base = volume + strings.TrimPrefix(base, volumeSlash)
		return strings.ReplaceAll(base, "/", separator)
	}
	return base
}

func redactTitleRules(input string, rules []Rule) (string, map[CategoryString]struct{}) {
	categories := make(map[CategoryString]struct{})
	matches := detectWithRules(input, rules)
	output, applied := redactWithRules(input, matches, rules)
	for _, match := range applied {
		if category := match.Category.String(); category != "" {
			categories[category] = struct{}{}
		}
	}
	return output, categories
}

func orderedTitleCategories(set map[CategoryString]struct{}) []CategoryString {
	order := [...]CategoryString{CategoryStringCredential, CategoryStringPII, CategoryStringPath, CategoryStringInternal}
	result := make([]CategoryString, 0, len(set))
	for _, category := range order {
		if _, ok := set[category]; ok {
			result = append(result, category)
		}
	}
	return result
}

func capTitle(input string) string {
	runes := []rune(input)
	if len(runes) <= titleCodePointLimit {
		return strings.TrimRightFunc(input, unicode.IsSpace)
	}
	cut := titleCodePointLimit
	for i := titleCodePointLimit - 1; i >= 0; i-- {
		if unicode.IsSpace(runes[i]) {
			cut = i
			break
		}
	}
	return strings.TrimRightFunc(string(runes[:cut]), unicode.IsSpace)
}
