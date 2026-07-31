// Package redact provides regex-based code anonymization.
// ASTAnonymizer uses regex-based identifier detection to locate identifiers in
// code blocks and replace them with deterministic anonymous names while
// preserving structure.
//
// AST anonymization only activates at RedactionLevelMaximum. At Standard
// and Minimal levels, the v1 code block masking (maskCodeBlocks) still applies.
package redact

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// SupportedLang represents a language for which AST anonymization is available.
type SupportedLang string

const (
	LangGo         SupportedLang = "go"
	LangPython     SupportedLang = "python"
	LangTypeScript SupportedLang = "typescript"
	LangJavaScript SupportedLang = "javascript"
	LangBash       SupportedLang = "bash"
	LangUnknown    SupportedLang = ""
)

func (l SupportedLang) String() string {
	if l == LangUnknown {
		return "unknown"
	}
	return string(l)
}

// IsSupported returns true if the language has regex-based identifier detection available.
func (l SupportedLang) IsSupported() bool {
	switch l {
	case LangGo, LangPython, LangTypeScript, LangJavaScript, LangBash:
		return true
	}
	return false
}

// ParseLangHint maps a markdown fence language hint (e.g., "go", "py", "ts")
// to a SupportedLang. Unrecognized hints return LangUnknown.
func ParseLangHint(hint string) SupportedLang {
	switch hint {
	case "go", "golang":
		return LangGo
	case "python", "py", "python3":
		return LangPython
	case "typescript", "ts":
		return LangTypeScript
	case "javascript", "js":
		return LangJavaScript
	case "bash", "sh", "shell", "zsh":
		return LangBash
	default:
		return LangUnknown
	}
}

// ASTAnonymizer rewrites code blocks to replace identifiers while preserving
// structure. Replacement is deterministic: same identifier → same anonymous
// name within a single anonymizer instance (session-scoped).
//
// Cross-instance determinism is guaranteed only when both instances process
// identical code: the mapping is derived from the set of identifiers found,
// not from a global registry.
type ASTAnonymizer interface {
	// AnonymizeCode rewrites the code string for the given language.
	// If lang is unsupported, returns code unchanged and nil error.
	// Replacement is deterministic: same identifier → same anonymous name.
	AnonymizeCode(lang SupportedLang, code string) (string, error)
}

// CodeBlock represents a fenced code block extracted from markdown text.
type CodeBlock struct {
	Lang    SupportedLang
	Content string
	Start   int // byte offset in source text where the full fence starts
	End     int // byte offset in source text where the full fence ends
}

// codeBlockExtractPattern matches markdown fenced code blocks.
// Group 1: language hint (optional), Group 2: content between fences.
// The (?s) flag allows '.' to match newlines so content can span lines.
// The pattern requires a newline after the opening fence and before the closing
// fence, so single-line fences (```code```) are not matched.
var codeBlockExtractPattern = regexp.MustCompile("(?s)```([a-zA-Z0-9_]*)\n(.*?)\n```")

// ExtractCodeBlocks finds all fenced code blocks (```lang ... ```) in text.
// Returns extracted blocks with their language hints and byte offsets.
func ExtractCodeBlocks(text string) []CodeBlock {
	matches := codeBlockExtractPattern.FindAllStringSubmatchIndex(text, -1)
	if len(matches) == 0 {
		return nil
	}

	blocks := make([]CodeBlock, 0, len(matches))
	for _, loc := range matches {
		// loc[0:2] = full match, loc[2:4] = group 1 (lang), loc[4:6] = group 2 (content)
		langHint := text[loc[2]:loc[3]]
		content := text[loc[4]:loc[5]]
		blocks = append(blocks, CodeBlock{
			Lang:    ParseLangHint(langHint),
			Content: content,
			Start:   loc[0],
			End:     loc[1],
		})
	}
	return blocks
}

// RegexAnonymizer replaces identifiers in code blocks with deterministic
// anonymous names while preserving language syntax structure.
//
// Implementation note: Uses regex-based identifier detection rather than
// tree-sitter CGo bindings. This avoids CGo build complexity and is sufficient
// for the anonymization use case where we need to replace user-chosen names,
// not perform semantic analysis. The approach matches the spec's documented
// fallback strategy.
//
// Determinism: same identifier → same anonymous name within an instance.
// Cross-instance determinism is achieved by sorting identifiers alphabetically
// before assigning names, so the mapping is input-dependent, not order-dependent.
// Cross-instance determinism only holds when both instances process identical code.
type RegexAnonymizer struct {
	mu         sync.Mutex
	nameMap    map[string]string
	regexCache map[string]*regexp.Regexp
	counter    int
}

// Compile-time guard: RegexAnonymizer must implement ASTAnonymizer.
var _ ASTAnonymizer = (*RegexAnonymizer)(nil)

// NewRegexAnonymizer returns a new ASTAnonymizer backed by regex-based identifier
// detection. The anonymizer maintains a session-scoped identifier map for
// determinism: same identifier → same anonymous name within the instance.
func NewRegexAnonymizer() ASTAnonymizer {
	return &RegexAnonymizer{
		nameMap:    make(map[string]string),
		regexCache: make(map[string]*regexp.Regexp),
	}
}

// identifierPattern matches programming language identifiers that are
// likely user-defined names (not keywords, not single chars, not all-caps
// constants from standard libraries).
var identifierPattern = regexp.MustCompile(`\b[a-zA-Z_][a-zA-Z0-9_]{2,}\b`)

// Language keyword sets — identifiers matching these are NOT replaced.
//
// Sources:
//   - Go: https://go.dev/ref/spec#Keywords (Go 1.21 spec), built-ins from
//     https://pkg.go.dev/builtin
//   - Python: https://docs.python.org/3/reference/lexical_analysis.html#keywords
//     and https://docs.python.org/3/library/functions.html (Python 3.12 built-ins)
//   - TypeScript/JavaScript: https://tc39.es/ecma262/ (ES2023) keywords plus
//     TypeScript-specific modifiers from https://www.typescriptlang.org/docs/handbook/
//   - Bash: POSIX shell reserved words (https://pubs.opengroup.org/onlinepubs/9699919799/)
//     and bash(1) builtins (GNU Bash 5.x)
var langKeywords = map[SupportedLang]map[string]bool{
	LangGo: {
		"break": true, "case": true, "chan": true, "const": true, "continue": true,
		"default": true, "defer": true, "else": true, "fallthrough": true, "for": true,
		"func": true, "goto": true, "if": true, "import": true, "interface": true,
		"map": true, "package": true, "range": true, "return": true, "select": true,
		"struct": true, "switch": true, "type": true, "var": true,
		// Built-in types.
		"bool": true, "byte": true, "complex64": true, "complex128": true,
		"error": true, "float32": true, "float64": true, "int": true,
		"int8": true, "int16": true, "int32": true, "int64": true,
		"rune": true, "string": true, "uint": true, "uint8": true,
		"uint16": true, "uint32": true, "uint64": true, "uintptr": true,
		// Built-in functions.
		"append": true, "cap": true, "close": true, "complex": true, "copy": true,
		"delete": true, "imag": true, "len": true, "make": true, "new": true,
		"panic": true, "print": true, "println": true, "real": true, "recover": true,
		// Common identifiers preserved for readability.
		"nil": true, "true": true, "false": true, "iota": true,
		"any": true, "comparable": true,
	},
	LangPython: {
		"False": true, "None": true, "True": true, "and": true, "as": true,
		"assert": true, "async": true, "await": true, "break": true, "class": true,
		"continue": true, "def": true, "del": true, "elif": true, "else": true,
		"except": true, "finally": true, "for": true, "from": true, "global": true,
		"if": true, "import": true, "in": true, "is": true, "lambda": true,
		"nonlocal": true, "not": true, "or": true, "pass": true, "raise": true,
		"return": true, "try": true, "while": true, "with": true, "yield": true,
		// Built-in functions.
		"abs": true, "all": true, "any": true, "bin": true, "bool": true,
		"bytes": true, "chr": true, "dict": true, "dir": true, "enumerate": true,
		"eval": true, "exec": true, "filter": true, "float": true, "format": true,
		"getattr": true, "hasattr": true, "hash": true, "hex": true, "input": true,
		"int": true, "isinstance": true, "issubclass": true, "iter": true, "len": true,
		"list": true, "map": true, "max": true, "min": true, "next": true,
		"object": true, "oct": true, "open": true, "ord": true, "pow": true,
		"print": true, "property": true, "range": true, "repr": true, "reversed": true,
		"round": true, "set": true, "setattr": true, "slice": true, "sorted": true,
		"staticmethod": true, "str": true, "sum": true, "super": true, "tuple": true,
		"type": true, "vars": true, "zip": true,
		// Common methods preserved for readability.
		"self": true, "cls": true, "strip": true, "split": true, "join": true,
		"replace": true, "encode": true, "decode": true,
		"append": true, "extend": true, "insert": true, "remove": true, "pop": true,
		"keys": true, "values": true, "items": true, "update": true, "get": true,
	},
	LangTypeScript: {
		"abstract": true, "any": true, "as": true, "async": true, "await": true,
		"boolean": true, "break": true, "case": true, "catch": true, "class": true,
		"const": true, "continue": true, "debugger": true, "declare": true, "default": true,
		"delete": true, "do": true, "else": true, "enum": true, "export": true,
		"extends": true, "false": true, "finally": true, "for": true, "from": true,
		"function": true, "get": true, "if": true, "implements": true, "import": true,
		"in": true, "instanceof": true, "interface": true, "let": true, "module": true,
		"namespace": true, "new": true, "null": true, "number": true, "of": true,
		"package": true, "private": true, "protected": true, "public": true, "readonly": true,
		"require": true, "return": true, "set": true, "static": true, "string": true,
		"super": true, "switch": true, "symbol": true, "this": true, "throw": true,
		"true": true, "try": true, "type": true, "typeof": true, "undefined": true,
		"var": true, "void": true, "while": true, "with": true, "yield": true,
		// Common globals/builtins.
		"console": true, "document": true, "window": true, "process": true,
		"JSON": true, "Math": true, "Object": true, "Array": true, "Promise": true,
		"Error": true, "Map": true, "Set": true, "RegExp": true, "Date": true,
		"parseInt": true, "parseFloat": true, "setTimeout": true, "setInterval": true,
		"clearTimeout": true, "clearInterval": true,
		// Common methods.
		"log": true, "warn": true, "error": true, "info": true,
		"toString": true, "valueOf": true, "toUpperCase": true, "toLowerCase": true,
		"indexOf": true, "includes": true, "map": true, "filter": true, "reduce": true,
		"forEach": true, "push": true, "pop": true, "shift": true, "unshift": true,
		"slice": true, "splice": true, "concat": true, "join": true, "split": true,
	},
	LangJavaScript: nil, // uses same keywords as TypeScript (resolved at lookup)
	LangBash: {
		"echo": true, "exit": true, "export": true, "source": true, "alias": true,
		"unalias": true, "set": true, "unset": true, "readonly": true, "shift": true,
		"function": true, "return": true, "local": true, "declare": true, "typeset": true,
		"if": true, "then": true, "else": true, "elif": true, "fi": true,
		"case": true, "esac": true, "for": true, "while": true, "until": true,
		"do": true, "done": true, "in": true, "select": true, "time": true,
		// Common commands preserved.
		"cd": true, "pwd": true, "ls": true, "cat": true, "grep": true,
		"sed": true, "awk": true, "find": true, "sort": true, "uniq": true,
		"head": true, "tail": true, "wc": true, "cut": true, "tr": true,
		"mkdir": true, "rmdir": true, "rm": true, "cp": true, "mv": true,
		"chmod": true, "chown": true, "curl": true, "wget": true, "ssh": true,
		"git": true, "docker": true, "make": true, "npm": true, "pip": true,
		"sudo": true, "apt": true, "brew": true, "nix": true,
		"true": true, "false": true, "test": true, "read": true, "eval": true,
		"exec": true, "trap": true, "wait": true, "kill": true, "jobs": true,
		"bin": true, "bash": true, "usr": true,
	},
}

// getKeywords returns the keyword set for a language.
// JavaScript falls back to TypeScript keywords.
func getKeywords(lang SupportedLang) map[string]bool {
	if lang == LangJavaScript {
		return langKeywords[LangTypeScript]
	}
	return langKeywords[lang]
}

// AnonymizeCode replaces user-defined identifiers in code with deterministic
// anonymous names while preserving language keywords, built-in types, and syntax.
//
// Unknown languages are returned unchanged with nil error.
// Parse errors are not possible with regex-based approach; invalid code is
// processed best-effort.
func (a *RegexAnonymizer) AnonymizeCode(lang SupportedLang, code string) (string, error) {
	if !lang.IsSupported() {
		return code, nil
	}

	keywords := getKeywords(lang)

	// Find all unique identifiers (excluding keywords).
	allMatches := identifierPattern.FindAllString(code, -1)
	uniqueIDs := make(map[string]bool)
	for _, id := range allMatches {
		if !keywords[id] {
			uniqueIDs[id] = true
		}
	}
	if len(uniqueIDs) == 0 {
		return code, nil
	}

	// Build deterministic mapping: sort identifiers alphabetically so the
	// same set of identifiers always produces the same mapping regardless
	// of occurrence order in the code.
	sorted := make([]string, 0, len(uniqueIDs))
	for id := range uniqueIDs {
		sorted = append(sorted, id)
	}
	sort.Strings(sorted)

	// Lock only for nameMap/regexCache population: assign anonymous names and
	// compile/cache regex patterns, then snapshot into locals before unlocking.
	// Sorting by length and string replacement happen outside the lock so that
	// the critical section covers only shared-map writes, not the O(n·m) replacement.
	a.mu.Lock()
	for _, id := range sorted {
		if _, exists := a.nameMap[id]; !exists {
			a.counter++
			a.nameMap[id] = fmt.Sprintf("id%d", a.counter)
		}
		if _, cached := a.regexCache[id]; !cached {
			a.regexCache[id] = regexp.MustCompile(`\b` + regexp.QuoteMeta(id) + `\b`)
		}
	}
	// Snapshot into locals so replacement runs without holding the lock.
	anonNames := make(map[string]string, len(sorted))
	patterns := make(map[string]*regexp.Regexp, len(sorted))
	for _, id := range sorted {
		anonNames[id] = a.nameMap[id]
		patterns[id] = a.regexCache[id]
	}
	a.mu.Unlock()

	// Replace identifiers from longest to shortest to avoid partial replacements.
	// E.g., "processUserData" should not be partially replaced by "processUser".
	sort.Slice(sorted, func(i, j int) bool {
		return len(sorted[i]) > len(sorted[j])
	})

	result := code
	for _, id := range sorted {
		result = patterns[id].ReplaceAllLiteralString(result, anonNames[id])
	}

	return result, nil
}

// anonymizeCodeBlocks replaces code blocks in text with AST-anonymized versions.
// Only used at Maximum level. Returns the modified text.
// On error from the anonymizer, the original block is preserved verbatim.
func anonymizeCodeBlocks(anon ASTAnonymizer, text string) string {
	blocks := ExtractCodeBlocks(text)
	if len(blocks) == 0 {
		return text
	}

	// Build result front-to-back using a Builder; byte offsets into text remain
	// valid since we read from text, never modify it.
	var result strings.Builder
	result.Grow(len(text))

	lastEnd := 0
	// Build result by interleaving unchanged text and anonymized blocks.
	for _, block := range blocks {
		// Write text before this block.
		result.WriteString(text[lastEnd:block.Start])

		// Anonymize the block content.
		anonymized, err := anon.AnonymizeCode(block.Lang, block.Content)
		if err != nil || !block.Lang.IsSupported() || anonymized == block.Content {
			// On error, unsupported language, or unchanged content: write the
			// original fence verbatim to preserve language hints and avoid
			// needlessly reconstructing fences.
			result.WriteString(text[block.Start:block.End])
		} else {
			// Write the fence with anonymized content.
			// Note: reconstructed fences use canonical lang names (e.g. "python" not "python3").
			result.WriteString("```")
			result.WriteString(string(block.Lang))
			result.WriteString("\n")
			result.WriteString(anonymized)
			result.WriteString("\n```")
		}
		lastEnd = block.End
	}
	// Write remaining text after last block.
	result.WriteString(text[lastEnd:])

	return result.String()
}
