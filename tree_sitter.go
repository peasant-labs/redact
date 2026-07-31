//go:build cgo

// This file is compiled ONLY in cgo builds. The tree-sitter bindings below are
// CGo wrappers around the C parsing library, so they cannot compile (or run)
// without cgo. Maximum-level redaction depends on these types; in !cgo builds
// the Maximum level is rejected at construction time (see redactor.go +
// maximum_nocgo.go) rather than silently degraded.

package redact

// TreeSitterAnonymizer uses the tree-sitter parsing library to perform
// accurate AST-based identifier extraction and replacement.
//
// Unlike RegexAnonymizer (which uses word-boundary regex), TreeSitterAnonymizer
// parses code into a proper AST and uses language-specific query patterns to
// find only true identifiers (not words that happen to match a regex).
//
// Parser objects are NOT thread-safe and are created per AnonymizeCode call.
// Language objects are thread-safe and are initialized once at package level.
// The nameMap (identifier → anonymous name) is session-scoped and protected
// by a mutex, matching the determinism contract of RegexAnonymizer.
//
// Memory management: All tree-sitter C objects (Parser, Tree, Query, QueryCursor)
// must call Close(). Failure to do so leaks C memory since Go's runtime.SetFinalizer
// is unreliable with CGo allocations.

import (
	"fmt"
	"sort"
	"sync"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tree_sitter_bash "github.com/tree-sitter/tree-sitter-bash/bindings/go"
	tree_sitter_go "github.com/tree-sitter/tree-sitter-go/bindings/go"
	tree_sitter_js "github.com/tree-sitter/tree-sitter-javascript/bindings/go"
	tree_sitter_python "github.com/tree-sitter/tree-sitter-python/bindings/go"
	tree_sitter_ts "github.com/tree-sitter/tree-sitter-typescript/bindings/go"
)

// Package-level Language objects. These are thread-safe and expensive to
// initialize, so they are created once at package init time.
var (
	tsGoLanguage         = tree_sitter.NewLanguage(tree_sitter_go.Language())
	tsPythonLanguage     = tree_sitter.NewLanguage(tree_sitter_python.Language())
	tsTypeScriptLanguage = tree_sitter.NewLanguage(tree_sitter_ts.LanguageTypescript())
	tsJavaScriptLanguage = tree_sitter.NewLanguage(tree_sitter_js.Language())
	tsBashLanguage       = tree_sitter.NewLanguage(tree_sitter_bash.Language())
)

// langQueryPatterns defines the tree-sitter query string for extracting
// identifiers from each supported language.
//
// Go, Python, TypeScript, JavaScript: (identifier) captures named identifier
// nodes — the tree-sitter grammar for these languages marks keywords and
// built-in operators as separate node types, so (identifier) already excludes
// keywords.
//
// Bash: The bash grammar uses three node types for user-defined names:
//   - (function_definition name: (word)) — function names
//   - (variable_assignment name: (variable_name)) — LHS of assignments
//   - (expansion (variable_name)) — ${varname} and $varname usages
//
// This combined query avoids capturing command words (echo, docker, etc.)
// that would be captured by the plain (word) pattern.
var langQueryPatterns = map[SupportedLang]string{
	LangGo:         `(identifier) @id`,
	LangPython:     `(identifier) @id`,
	LangTypeScript: `(identifier) @id`,
	LangJavaScript: `(identifier) @id`,
	LangBash: `(function_definition name: (word) @id)
(variable_assignment name: (variable_name) @id)
(expansion (variable_name) @id)`,
}

// langObjects maps SupportedLang to the corresponding tree-sitter Language object.
var langObjects = map[SupportedLang]*tree_sitter.Language{
	LangGo:         tsGoLanguage,
	LangPython:     tsPythonLanguage,
	LangTypeScript: tsTypeScriptLanguage,
	LangJavaScript: tsJavaScriptLanguage,
	LangBash:       tsBashLanguage,
}

// TreeSitterAnonymizer replaces identifiers in code blocks with deterministic
// anonymous names using tree-sitter AST parsing for accurate identifier detection.
//
// Determinism: same identifier → same anonymous name within an instance.
// Cross-instance determinism holds when both instances process identical code
// (names are assigned in alphabetical order of the identifier set, not occurrence order).
//
// Thread safety: safe for concurrent use. Parsers are created per-call.
// The nameMap is protected by a mutex.
type TreeSitterAnonymizer struct {
	mu      sync.Mutex
	nameMap map[string]string
	counter int
}

// Compile-time guard: TreeSitterAnonymizer must implement ASTAnonymizer.
var _ ASTAnonymizer = (*TreeSitterAnonymizer)(nil)

// NewTreeSitterAnonymizer returns a new TreeSitterAnonymizer.
// The anonymizer maintains a session-scoped identifier map for determinism.
func NewTreeSitterAnonymizer() *TreeSitterAnonymizer {
	return &TreeSitterAnonymizer{
		nameMap: make(map[string]string),
	}
}

// AnonymizeCode rewrites the code string for the given language using
// tree-sitter AST parsing to find and replace identifiers.
//
// If lang is unsupported or LangUnknown, returns code unchanged with nil error.
// Returns an error if tree-sitter parsing or query execution fails.
// On error, the caller should fall back to RegexAnonymizer.
func (a *TreeSitterAnonymizer) AnonymizeCode(lang SupportedLang, code string) (string, error) {
	if !lang.IsSupported() {
		return code, nil
	}

	tsLang, ok := langObjects[lang]
	if !ok {
		return code, nil
	}

	queryStr, ok := langQueryPatterns[lang]
	if !ok {
		return code, nil
	}

	src := []byte(code)

	// Parser is NOT thread-safe: create a new one per call.
	parser := tree_sitter.NewParser()
	defer parser.Close()

	if err := parser.SetLanguage(tsLang); err != nil {
		return "", fmt.Errorf("tree-sitter: SetLanguage(%s): %w", lang, err)
	}

	tree := parser.Parse(src, nil)
	if tree == nil {
		return "", fmt.Errorf("tree-sitter: Parse returned nil tree for lang %s", lang)
	}
	defer tree.Close()

	query, qErr := tree_sitter.NewQuery(tsLang, queryStr)
	if qErr != nil {
		return "", fmt.Errorf("tree-sitter: NewQuery for %s: %s", lang, qErr.Error())
	}
	defer query.Close()

	qc := tree_sitter.NewQueryCursor()
	defer qc.Close()

	keywords := getKeywords(lang)

	// Single-pass: collect all identifier nodes with name and byte offsets.
	// We record every occurrence so we can replace by offset later, and also
	// build the unique-name set for deterministic name assignment.
	type identNode struct {
		name  string
		start uint
		end   uint
	}

	var nodes []identNode
	uniqueIDs := make(map[string]bool)

	matches := qc.Matches(query, tree.RootNode(), src)
	for {
		m := matches.Next()
		if m == nil {
			break
		}
		for _, node := range m.NodesForCaptureIndex(0) {
			name := string(node.Utf8Text(src))
			if name != "" && !keywords[name] {
				nodes = append(nodes, identNode{
					name:  name,
					start: node.StartByte(),
					end:   node.EndByte(),
				})
				uniqueIDs[name] = true
			}
		}
	}

	if len(uniqueIDs) == 0 {
		return code, nil
	}

	// Sort identifiers alphabetically: deterministic name assignment regardless
	// of occurrence order in the source code.
	sorted := make([]string, 0, len(uniqueIDs))
	for id := range uniqueIDs {
		sorted = append(sorted, id)
	}
	sort.Strings(sorted)

	// Assign anonymous names under the mutex so concurrent calls on the same
	// anonymizer instance get consistent mappings.
	a.mu.Lock()
	for _, id := range sorted {
		if _, exists := a.nameMap[id]; !exists {
			a.counter++
			a.nameMap[id] = fmt.Sprintf("id%d", a.counter)
		}
	}

	// Build a copy of the relevant nameMap entries while still holding the lock.
	nameMapCopy := make(map[string]string, len(sorted))
	for _, id := range sorted {
		nameMapCopy[id] = a.nameMap[id]
	}
	a.mu.Unlock()

	// Sort collected nodes in reverse byte-offset order so that applying a
	// replacement does not invalidate the offsets of earlier nodes.
	// This sort operates on local data and runs outside the mutex.
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].start > nodes[j].start
	})

	// Apply replacements using the already-collected offsets.
	result := make([]byte, len(src))
	copy(result, src)
	for _, n := range nodes {
		anonName, ok := nameMapCopy[n.name]
		if !ok {
			continue
		}
		result = append(result[:n.start], append([]byte(anonName), result[n.end:]...)...)
	}

	return string(result), nil
}

// FallbackAnonymizer tries the primary ASTAnonymizer first. If it returns an
// error, it falls back to the secondary. If the secondary also fails, returns
// the secondary's error.
//
// This wraps TreeSitterAnonymizer (primary) with RegexAnonymizer (fallback)
// so that Maximum-level redaction degrades gracefully when tree-sitter fails
// (e.g., for malformed code snippets).
type FallbackAnonymizer struct {
	primary  ASTAnonymizer
	fallback ASTAnonymizer
}

// Compile-time guard: FallbackAnonymizer must implement ASTAnonymizer.
var _ ASTAnonymizer = (*FallbackAnonymizer)(nil)

// NewFallbackAnonymizer returns an ASTAnonymizer that tries primary first,
// falling back to fallback on error. Panics if either argument is nil.
func NewFallbackAnonymizer(primary, fallback ASTAnonymizer) *FallbackAnonymizer {
	if primary == nil || fallback == nil {
		panic("NewFallbackAnonymizer: primary and fallback must not be nil")
	}
	return &FallbackAnonymizer{primary: primary, fallback: fallback}
}

// AnonymizeCode tries the primary anonymizer. If it returns an error, the
// fallback is used instead. Returns nil error if either succeeds.
func (f *FallbackAnonymizer) AnonymizeCode(lang SupportedLang, code string) (string, error) {
	result, err := f.primary.AnonymizeCode(lang, code)
	if err == nil {
		return result, nil
	}
	return f.fallback.AnonymizeCode(lang, code)
}
