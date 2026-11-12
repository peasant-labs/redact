package redact

import (
	"errors"
	"fmt"
	"regexp"
	"regexp/syntax"
	"sync"
	"unicode/utf8"
)

// MaxInputBytesPolicy bounds the input and the core of each engine window.
// Windows also read at most engineOverlapBytes of context on either side.
type MaxInputBytesPolicy struct {
	ChunkBytes   int
	CeilingBytes int
}

// DefaultMaxInputBytesPolicy is the production policy. Constructors copy it.
var DefaultMaxInputBytesPolicy = MaxInputBytesPolicy{ChunkBytes: 64 << 20, CeilingBytes: 2047 << 20}

const (
	engineOverlapBytes = 64 << 10
	inputRefusalRule   = "engine_input_refused"
)

var (
	// ErrInputAboveEngineCeiling identifies a refusal before engine memory is used.
	ErrInputAboveEngineCeiling = errors.New("the redaction input is at or above the engine safe ceiling")
	// ErrInputCannotChunkSafely identifies a pattern whose unfinished match cannot
	// be contained by the bounded overlap. No partial output is safe to publish.
	ErrInputCannotChunkSafely = errors.New("the redaction input cannot be split without changing match semantics")
)

// Validate rejects policies that could exceed the measured WASM32 limit.
func (p MaxInputBytesPolicy) Validate() error {
	if p.ChunkBytes > 0 && p.ChunkBytes <= p.CeilingBytes && p.CeilingBytes > 0 && int64(p.CeilingBytes) < int64(2048)<<20 {
		return nil
	}
	return &actionableError{
		what:  fmt.Sprintf("invalid redaction input policy (chunk=%d bytes, ceiling=%d bytes)", p.ChunkBytes, p.CeilingBytes),
		why:   "chunk and ceiling must be positive, chunk must not exceed ceiling, and ceiling must be below 2048 MiB",
		where: "redact.MaxInputBytesPolicy.Validate", when: "constructing a redactor before scanning content",
		means: "no redactor was constructed", fix: "use the production 64 MiB chunk and 2047 MiB ceiling, or smaller positive limits",
	}
}

// WithMaxInputBytes overrides the size policy without changing other options.
func WithMaxInputBytes(policy MaxInputBytesPolicy) Option {
	return func(c *redactorConfig) { c.inputPolicy = policy }
}

// MaxInputBytes returns the immutable policy copied at construction.
func (r *DefaultRedactor) MaxInputBytes() MaxInputBytesPolicy { return r.scannerConfig.inputPolicy }

func (r *DefaultRedactor) inputPolicy() MaxInputBytesPolicy {
	if r.scans != nil {
		return r.scans.policy
	}
	return DefaultMaxInputBytesPolicy
}

func (r *DefaultRedactor) recordInputRefusal(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastMatches = nil
	r.report.Warnings = append(r.report.Warnings, err.Error())
}

type patternScanner struct {
	policy MaxInputBytesPolicy
	engine engine
	plans  map[*regexp.Regexp]*scanPlan
}

func newPatternScanner(policy MaxInputBytesPolicy, e engine, rules, userRules []Rule, residue []ResidueRule) *patternScanner {
	s := &patternScanner{policy: policy, engine: e, plans: make(map[*regexp.Regexp]*scanPlan)}
	for _, rule := range rules {
		s.plans[rule.Pattern] = &scanPlan{}
	}
	for _, rule := range userRules {
		s.plans[rule.Pattern] = &scanPlan{}
	}
	for _, rule := range residue {
		s.plans[rule.Pattern] = &scanPlan{}
	}
	return s
}

func (s *patternScanner) scan(input string, original *regexp.Regexp, pattern compiled) ([][]int, error) {
	if s == nil {
		// Zero-value detectors retain stdlib execution, with the same policy.
		return scanPattern(input, pattern, DefaultMaxInputBytesPolicy, goRegexpEngine{}, &scanPlan{})
	}
	plan := s.plans[original]
	if plan == nil {
		plan = &scanPlan{}
	}
	return scanPattern(input, pattern, s.policy, s.engine, plan)
}

func (p MaxInputBytesPolicy) check(n int) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if n < p.CeilingBytes {
		return nil
	}
	return p.refusal(ErrInputAboveEngineCeiling, n)
}

func (p MaxInputBytesPolicy) refusal(cause error, n int) error {
	return &actionableError{
		what:  fmt.Sprintf("redaction input refused (%d bytes; chunk=%d bytes, ceiling=%d bytes)", n, p.ChunkBytes, p.CeilingBytes),
		why:   cause.Error() + "; a single WASM32 engine buffer at 2048 MiB can crash the process",
		where: "redact engine input wrapper", when: "checking input or a split before returning redacted content",
		means: "no successful redaction result is available; do not publish the original or partial output",
		fix:   "split the source at document boundaries or lower the producing document cap; for an ambiguous pattern, use independently bounded source records",
		cause: cause,
	}
}

// scanPlan is compiled lazily: ordinary inputs pay no extra compilation cost.
// The prefix recognizer is an over-approximation (assertions are ignored). It
// can refuse conservatively, but cannot declare an unfinished match safe.
type scanPlan struct {
	once   sync.Once
	err    error
	prefix compiled
	window [2][2]compiled // [has left context][has real EOF]
}

func (p *scanPlan) init(e engine, expression string) {
	p.once.Do(func() {
		ast, err := syntax.Parse(expression, syntax.Perl)
		if err != nil {
			p.err = err
			return
		}
		if minimumRunes(ast) == 0 {
			p.err = ErrInputCannotChunkSafely
			return
		}
		p.prefix, p.err = e.Compile("(?:" + prefixLanguage(ast).String() + ")\\z")
		if p.err != nil {
			return
		}
		for left := range 2 {
			for eof := range 2 {
				window := windowExpression(ast, left != 0, eof != 0).String()
				if left != 0 {
					// Consume exactly the context rune first. This prevents a
					// fabricated match at the slice's beginning from suppressing
					// the first real match, while preserving \b and multiline ^.
					window = `\A(?s:.)|(?:` + window + `)`
				}
				p.window[left][eof], p.err = e.Compile(window)
				if p.err != nil {
					return
				}
			}
		}
	})
}

func scanPattern(input string, pattern compiled, policy MaxInputBytesPolicy, e engine, plan *scanPlan) ([][]int, error) {
	if err := policy.check(len(input)); err != nil {
		return nil, err
	}
	if len(input) <= policy.ChunkBytes {
		return pattern.FindAllStringIndex(input, -1), nil
	}
	plan.init(e, pattern.String())
	if plan.err != nil {
		return nil, policy.refusal(errors.Join(ErrInputCannotChunkSafely, plan.err), len(input))
	}
	var spans [][]int
	for start := 0; start < len(input); {
		coreEnd := runeBoundaryBefore(input, start+min(policy.ChunkBytes, len(input)-start))
		if coreEnd <= start {
			return nil, policy.refusal(ErrInputCannotChunkSafely, len(input))
		}
		end := runeBoundaryBefore(input, coreEnd+min(engineOverlapBytes, len(input)-coreEnd))
		safeEnd := end
		if end < len(input) {
			// The earliest suffix which is a regex prefix may continue in
			// the next window, even if this window has no complete match.
			pending := plan.prefix.FindAllStringIndex(input[start:end], 1)
			if len(pending) > 0 {
				safeEnd = start + pending[0][0]
			}
		}
		cut := min(coreEnd, safeEnd)
		left, eof, base := 0, 0, start
		if start != 0 {
			_, width := utf8.DecodeLastRuneInString(input[:start])
			base -= width
			left = 1
		}
		if end == len(input) {
			eof = 1
		}
		locations := plan.window[left][eof].FindAllStringIndex(input[base:end], -1)
		for _, loc := range locations {
			a, b := base+loc[0], base+loc[1]
			if a < start { // the consumed context rune
				continue
			}
			if a < cut && b > cut {
				// Never restart in a match: that changes FindAll's
				// non-overlapping selection. Commit a whole known match,
				// or defer it to the next window.
				if b <= safeEnd {
					cut = b
				} else {
					cut = a
				}
			}
		}
		if cut <= start {
			return nil, policy.refusal(ErrInputCannotChunkSafely, len(input))
		}
		for _, loc := range locations {
			a, b := base+loc[0], base+loc[1]
			if a >= start && a < cut && b <= cut {
				spans = append(spans, []int{a, b})
			}
		}
		start = cut
	}
	return spans, nil
}

func runeBoundaryBefore(input string, offset int) int {
	for offset < len(input) && offset > 0 && !utf8.RuneStart(input[offset]) {
		offset--
	}
	return offset
}

func emptyExpression() *syntax.Regexp { return &syntax.Regexp{Op: syntax.OpEmptyMatch} }
func concatExpressions(parts ...*syntax.Regexp) *syntax.Regexp {
	return &syntax.Regexp{Op: syntax.OpConcat, Sub: parts}
}

// relaxedExpression drops zero-width assertions and captures only in the safety
// recognizer, never in the pattern that detects or replaces sensitive content.
func relaxedExpression(r *syntax.Regexp) *syntax.Regexp {
	if r.Op >= syntax.OpBeginLine && r.Op <= syntax.OpNoWordBoundary {
		return emptyExpression()
	}
	if r.Op == syntax.OpCapture {
		return relaxedExpression(r.Sub[0])
	}
	copy := *r
	copy.Sub = make([]*syntax.Regexp, len(r.Sub))
	for i, child := range r.Sub {
		copy.Sub[i] = relaxedExpression(child)
	}
	return &copy
}

// prefixLanguage recognizes every prefix of every word accepted by r. Including
// complete words is deliberately conservative at an artificial window EOF.
func prefixLanguage(r *syntax.Regexp) *syntax.Regexp {
	switch r.Op {
	case syntax.OpLiteral:
		parts := []*syntax.Regexp{emptyExpression()}
		for n := 1; n <= len(r.Rune); n++ {
			copy := *r
			copy.Rune = r.Rune[:n]
			parts = append(parts, &copy)
		}
		return &syntax.Regexp{Op: syntax.OpAlternate, Sub: parts}
	case syntax.OpConcat:
		parts := []*syntax.Regexp{emptyExpression()}
		var preceding []*syntax.Regexp
		for _, child := range r.Sub {
			term := append([]*syntax.Regexp{}, preceding...)
			term = append(term, prefixLanguage(child))
			parts = append(parts, concatExpressions(term...))
			preceding = append(preceding, relaxedExpression(child))
		}
		return &syntax.Regexp{Op: syntax.OpAlternate, Sub: parts}
	case syntax.OpAlternate:
		parts := make([]*syntax.Regexp, len(r.Sub))
		for i, child := range r.Sub {
			parts[i] = prefixLanguage(child)
		}
		return &syntax.Regexp{Op: syntax.OpAlternate, Sub: parts}
	case syntax.OpCapture:
		return prefixLanguage(r.Sub[0])
	case syntax.OpStar, syntax.OpPlus, syntax.OpRepeat:
		// Zero or more complete repetitions, followed by one partial
		// repetition. Ignoring the upper bound only makes refusal stricter.
		return concatExpressions(&syntax.Regexp{Op: syntax.OpStar, Sub: []*syntax.Regexp{relaxedExpression(r.Sub[0])}}, prefixLanguage(r.Sub[0]))
	case syntax.OpQuest:
		return prefixLanguage(r.Sub[0])
	default:
		return &syntax.Regexp{Op: syntax.OpAlternate, Sub: []*syntax.Regexp{emptyExpression(), relaxedExpression(r)}}
	}
}

func minimumRunes(r *syntax.Regexp) int {
	switch r.Op {
	case syntax.OpLiteral:
		return len(r.Rune)
	case syntax.OpCharClass, syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return 1
	case syntax.OpCapture, syntax.OpPlus:
		return minimumRunes(r.Sub[0])
	case syntax.OpRepeat:
		return r.Min * minimumRunes(r.Sub[0])
	case syntax.OpConcat:
		n := 0
		for _, child := range r.Sub {
			n += minimumRunes(child)
		}
		return n
	case syntax.OpAlternate:
		n := minimumRunes(r.Sub[0])
		for _, child := range r.Sub[1:] {
			n = min(n, minimumRunes(child))
		}
		return n
	default:
		return 0
	}
}

func windowExpression(r *syntax.Regexp, hasLeft, hasEOF bool) *syntax.Regexp {
	if (hasLeft && r.Op == syntax.OpBeginText) || (!hasEOF && r.Op == syntax.OpEndText) {
		return &syntax.Regexp{Op: syntax.OpNoMatch}
	}
	copy := *r
	copy.Sub = make([]*syntax.Regexp, len(r.Sub))
	for i, child := range r.Sub {
		copy.Sub[i] = windowExpression(child, hasLeft, hasEOF)
	}
	return &copy
}
