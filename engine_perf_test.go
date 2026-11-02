package redact

import (
	_ "embed"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

//go:embed testdata/engine_perf_corpus.yaml
var enginePerfCorpusData []byte

type enginePerfPlant struct {
	Offset   int    `yaml:"offset"`
	Text     string `yaml:"text"`
	Redacted string `yaml:"redacted"`
	Rule     string `yaml:"rule"`
}

type enginePerfCorpus struct {
	Name   string            `yaml:"name"`
	Bytes  int               `yaml:"bytes"`
	Filler string            `yaml:"filler"`
	Plants []enginePerfPlant `yaml:"plants"`
}

type enginePerfFixtures struct {
	RequiredNames []string           `yaml:"required_names"`
	Corpora       []enginePerfCorpus `yaml:"corpora"`
}

func loadEnginePerfFixtures(tb testing.TB) enginePerfFixtures {
	tb.Helper()
	var f enginePerfFixtures
	if err := yaml.Unmarshal(enginePerfCorpusData, &f); err != nil {
		tb.Fatal(err)
	}
	if err := requireFixtureNames("testdata/engine_perf_corpus.yaml", "required_names", f.RequiredNames, fixtureNames(f.Corpora, func(c enginePerfCorpus) string { return c.Name })); err != nil {
		tb.Fatal(err)
	}
	for _, c := range f.Corpora {
		if c.Bytes <= 0 || c.Filler == "" || len(c.Plants) == 0 {
			tb.Fatalf("%s: restore positive bytes, filler and planted values", c.Name)
		}
		end := 0
		for _, p := range c.Plants {
			if p.Offset < end || p.Offset+len(p.Text) > c.Bytes || p.Text == "" || p.Redacted == "" || findRuleByID(p.Rule) == nil {
				tb.Fatalf("%s: invalid/overlapping plant at %d; restore ordered, bounded plants with a known rule and expected replacement", c.Name, p.Offset)
			}
			end = p.Offset + len(p.Text)
		}
	}
	return f
}

// build constructs input and a literal golden from the reviewed fixture. It
// never calls the engine to derive expected output and never reads local data.
func (c enginePerfCorpus) build() (string, string) {
	data := []byte(strings.Repeat(c.Filler, c.Bytes/len(c.Filler)+1)[:c.Bytes])
	for _, p := range c.Plants {
		copy(data[p.Offset:], p.Text)
	}
	input := string(data)
	var golden strings.Builder
	golden.Grow(c.Bytes)
	cursor := 0
	for _, p := range c.Plants {
		golden.WriteString(input[cursor:p.Offset])
		golden.WriteString(p.Redacted)
		cursor = p.Offset + len(p.Text)
	}
	golden.WriteString(input[cursor:])
	return input, golden.String()
}

func TestEnginePerfCorpusParity(t *testing.T) {
	if os.Getenv("REDACT_PERF") == "1" && selectEngine().Identity() != engineGoRE2 {
		t.Fatal("make perf prices go-re2; remove no_re2 from GOFLAGS before comparing its baseline")
	}
	for _, c := range loadEnginePerfFixtures(t).Corpora {
		t.Run(c.Name, func(t *testing.T) {
			if c.Bytes > 64<<20 && os.Getenv("REDACT_PERF") != "1" {
				t.Skip("large corpus parity runs in make perf, outside the ordinary race suite")
			}
			input, want := c.build()
			r := mustNewRedactor(t, Standard, nil)
			if got := r.RedactText(input); got != want {
				t.Fatalf("%s: redacted bytes differ from literal golden; input=%d output=%d expected=%d bytes (content intentionally omitted)", c.Name, len(input), len(got), len(want))
			}
			counts := make(map[string]int)
			for _, p := range c.Plants {
				counts[p.Rule]++
			}
			if got := r.Report().Counts; !reflect.DeepEqual(got, counts) {
				t.Fatalf("%s: counts=%v, planted=%v; a faster scan must not redact less", c.Name, got, counts)
			}
			// All 56 rules, including those not active at Standard, are priced.
			all := detectWithRules(input, Rules, r.(*DefaultRedactor).patterns)
			allCounts := make(map[string]int)
			for _, m := range all {
				allCounts[m.Rule]++
			}
			if !reflect.DeepEqual(allCounts, counts) {
				t.Fatalf("%s: whole-table counts=%v, planted=%v", c.Name, allCounts, counts)
			}
		})
	}
}

//go:embed testdata/engine_perf_budget.yaml
var enginePerfBudgetData []byte

type enginePerfBudget struct {
	Engine           string                        `yaml:"engine"`
	TimeFactor       float64                       `yaml:"time_factor"`
	AllocationFactor float64                       `yaml:"allocation_factor"`
	AllocationSlack  map[string]float64            `yaml:"allocation_slack"`
	RequiredNames    []string                      `yaml:"required_names"`
	Baselines        map[string]map[string]float64 `yaml:"baselines"`
}

func TestEnginePerfBudgetCoverage(t *testing.T) {
	var budget enginePerfBudget
	if err := yaml.Unmarshal(enginePerfBudgetData, &budget); err != nil {
		t.Fatal(err)
	}
	if budget.Engine != string(engineGoRE2) || budget.TimeFactor < 1 || budget.AllocationFactor < 1 {
		t.Fatal("restore the reviewed go-re2 budget identity and relative factors >= 1")
	}
	expected := enginePerfBenchmarkNames(loadEnginePerfFixtures(t))
	if err := requireFixtureNames("testdata/engine_perf_budget.yaml", "required_names", budget.RequiredNames, expected); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(budget.Baselines))
	for name, metrics := range budget.Baselines {
		names = append(names, name)
		units := []string{"ns/op", "B/op", "allocs/op"}
		if !strings.HasPrefix(name, "RuleCompile/") && name != "Construction" {
			units = append(units, "ns/byte")
		}
		for _, unit := range units {
			value, ok := metrics[unit]
			if !ok || value < 0 || math.IsNaN(value) || math.IsInf(value, 0) || (strings.HasPrefix(unit, "ns/") && value == 0) {
				t.Errorf("%s: missing/invalid %s; record a measured baseline before shipping this rule", name, unit)
			}
		}
		if len(metrics) != len(units) {
			t.Errorf("%s: unexpected budget units; keep only ns/op, ns/byte for scans, B/op and allocs/op", name)
		}
	}
	if err := requireFixtureNames("testdata/engine_perf_budget.yaml", "baselines", expected, names); err != nil {
		t.Fatal(err)
	}
}

// TestEngineBudgetRealCorpus is an explicit, bounded diagnostic, not a portable
// budget oracle. Never print file names, input, output, matches or warnings.
func TestEngineBudgetRealCorpus(t *testing.T) {
	dir := os.Getenv("PEASANT_REDACT_CORPUS_DIR")
	if dir == "" {
		t.Skip("real corpus is opt-in; set PEASANT_REDACT_CORPUS_DIR only for an approved local corpus")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal("cannot enumerate the explicitly selected local corpus; verify its directory permissions")
	}
	r := mustNewRedactor(t, Standard, nil)
	const perFile = 64 << 20
	const totalLimit = 128 << 20
	var total, files int
	var elapsed time.Duration
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue // no recursion and no symlink traversal
		}
		if files == 16 || total >= totalLimit {
			break
		}
		f, err := os.Open(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal("cannot open an approved corpus file; verify local read permissions")
		}
		limit := min(perFile, totalLimit-total)
		data, readErr := io.ReadAll(io.LimitReader(f, int64(limit)+1))
		closeErr := f.Close()
		if readErr != nil || closeErr != nil {
			t.Fatal("cannot read/close an approved corpus file; repair local storage and retry")
		}
		if len(data) > limit {
			t.Fatal("approved corpus exceeds the diagnostic bound; prepare files <=64 MiB and <=128 MiB in total without truncating UTF-8")
		}
		input := string(data)
		start := time.Now()
		_ = r.RedactText(input)
		elapsed += time.Since(start)
		total += len(data)
		files++
	}
	if total == 0 {
		t.Fatal("approved corpus has no nonempty regular files; select a bounded directory with valid UTF-8 text")
	}
	t.Logf("approved local corpus: files=%d bytes=%d wall=%s ns/byte=%.4f (diagnostic only; no private content logged)", files, total, elapsed, float64(elapsed.Nanoseconds())/float64(total))
}

var (
	perfText     string
	perfMatches  []Match
	perfWarnings []ResidueWarning
	perfRedactor Redactor
	perfPattern  compiled
)

// BenchmarkEnginePerf exercises the selected production engine. Construction is
// excluded from warm scans; Full includes the real advisory residue path.
func BenchmarkEnginePerf(b *testing.B) {
	f := loadEnginePerfFixtures(b)
	b.Run("Construction", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			var err error
			perfRedactor, err = NewRedactor(Standard, nil, XDGPaths{})
			if err != nil {
				b.Fatal(err)
			}
		}
	})
	for _, c := range f.Corpora {
		input, golden := c.build()
		r := mustNewRedactor(b, Standard, nil).(*DefaultRedactor)
		b.Run(c.Name, func(b *testing.B) {
			b.Run("WholeSet", func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(input)))
				for b.Loop() {
					perfMatches = detectWithRules(input, Rules, r.patterns)
				}
				b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(len(input)), "ns/byte")
			})
			b.Run("Full", func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(input)))
				for b.Loop() {
					perfText = r.RedactText(input)
				}
				b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(len(input)), "ns/byte")
			})
			b.Run("Residue", func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(input))) // original bytes for comparable stage shares
				for b.Loop() {
					perfWarnings = r.residueDetector.Scan(golden)
				}
				b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(len(input)), "ns/byte")
			})
		})
		if c.Name == "tool_8kib" {
			b.Run("Rule", func(b *testing.B) {
				for _, rule := range Rules {
					b.Run(rule.ID, func(b *testing.B) {
						b.ReportAllocs()
						b.SetBytes(int64(len(input)))
						for b.Loop() {
							perfMatches = detectWithRules(input, []Rule{rule}, r.patterns)
						}
						b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(len(input)), "ns/byte")
					})
				}
			})
		}
	}
	b.Run("RuleCompile", func(b *testing.B) {
		for _, rule := range Rules {
			b.Run(rule.ID, func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					var err error
					perfPattern, err = selectEngine().Compile(rule.Pattern.String())
					if err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	})
	// Keep benchmark identity visible in logs even when the fallback is selected.
	b.Logf("selected engine: %s; built-in rule table: %d", selectEngine().Identity(), len(Rules))
}

func enginePerfBenchmarkNames(f enginePerfFixtures) []string {
	names := []string{"Construction"}
	for _, c := range f.Corpora {
		for _, stage := range []string{"WholeSet", "Full", "Residue"} {
			names = append(names, fmt.Sprintf("%s/%s", c.Name, stage))
		}
	}
	for _, rule := range Rules {
		names = append(names, "Rule/"+rule.ID)
		names = append(names, "RuleCompile/"+rule.ID)
	}
	return names
}
