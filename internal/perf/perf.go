// Package perf parses benchmark results and compares them with reviewed
// medians. It holds no engine knowledge: the benchmark, the corpus and the
// budget live with the redaction package.
package perf

import (
	"fmt"
	"math"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Benchmark units. Scans report a per-byte cost; construction and compilation
// cover no input bytes.
const (
	UnitNsPerOp     = "ns/op"
	UnitNsPerByte   = "ns/byte"
	UnitBytesPerOp  = "B/op"
	UnitAllocsPerOp = "allocs/op"
)

// Samples is the number of benchmark runs each row must report. A median of an
// even count is ambiguous, so the gate requires an odd count and never fewer.
const Samples = 5

// Row holds one median per benchmark unit.
type Row map[string]float64

// Rows maps benchmark names to their medians.
type Rows map[string]Row

// Budget is the reviewed cost envelope a run is compared against.
type Budget struct {
	Engine           string             `yaml:"engine"`
	TimeFactor       float64            `yaml:"time_factor"`
	AllocationFactor float64            `yaml:"allocation_factor"`
	AllocationSlack  map[string]float64 `yaml:"allocation_slack"`
	RequiredNames    []string           `yaml:"required_names"`
	Baselines        map[string]Row     `yaml:"baselines"`
}

var benchmarkLine = regexp.MustCompile(`^BenchmarkEnginePerf/(\S+?)(?:-\d+)?\s+\d+\s+(.*)$`)

// Parse reads `go test -bench` output into median rows. Every benchmark name
// must appear exactly Samples times with the units its stage reports.
func Parse(output string) (Rows, error) {
	samples := make(map[string][]Row)
	var order []string
	for _, line := range strings.Split(output, "\n") {
		match := benchmarkLine.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		name := match[1]
		fields := strings.Fields(match[2])
		values := make(Row, len(fields)/2)
		for i := 0; i+1 < len(fields); i += 2 {
			value, err := strconv.ParseFloat(fields[i], 64)
			if err != nil {
				return nil, fmt.Errorf("%s: unreadable benchmark value %q; rerun the complete command", name, fields[i])
			}
			values[fields[i+1]] = value
		}
		if _, seen := samples[name]; !seen {
			order = append(order, name)
		}
		samples[name] = append(samples[name], values)
	}
	if len(samples) == 0 {
		return nil, fmt.Errorf("no engine benchmarks found; restore BenchmarkEnginePerf before running the gate")
	}
	rows := make(Rows, len(samples))
	for _, name := range order {
		got := samples[name]
		if len(got) != Samples {
			return nil, fmt.Errorf("%s: got %d samples, require %d; rerun the complete command", name, len(got), Samples)
		}
		for _, sample := range got {
			if err := requireUnits(name, sample); err != nil {
				return nil, err
			}
		}
		row := make(Row, len(got[0]))
		for unit := range got[0] {
			row[unit] = median(got, unit)
		}
		rows[name] = row
	}
	return rows, nil
}

func requireUnits(name string, sample Row) error {
	for _, unit := range sortedNames(UnitsFor(name)) {
		value, ok := sample[unit]
		if !ok {
			return fmt.Errorf("%s: missing %s; rerun with -benchmem", name, unit)
		}
		if !finite(value) || value < 0 {
			return fmt.Errorf("%s: invalid %s value %v; rerun with -benchmem", name, unit, value)
		}
	}
	return nil
}

// UnitsFor returns the units a benchmark name must report.
func UnitsFor(name string) map[string]struct{} {
	units := map[string]struct{}{UnitNsPerOp: {}, UnitBytesPerOp: {}, UnitAllocsPerOp: {}}
	if !strings.HasPrefix(name, "Construction") && !strings.HasPrefix(name, "RuleCompile/") {
		units[UnitNsPerByte] = struct{}{}
	}
	return units
}

// Compare returns one message per regression. A malformed budget or a changed
// benchmark membership is an error rather than a regression.
func Compare(rows Rows, budget Budget, timing bool) ([]string, error) {
	if !finite(budget.TimeFactor) || budget.TimeFactor < 1 {
		return nil, fmt.Errorf("time_factor: restore a reviewed finite relative factor >= 1")
	}
	if !finite(budget.AllocationFactor) || budget.AllocationFactor < 1 {
		return nil, fmt.Errorf("allocation_factor: restore a reviewed finite relative factor >= 1")
	}
	if len(budget.AllocationSlack) != 2 {
		return nil, fmt.Errorf("allocation_slack: restore finite nonnegative B/op and allocs/op tolerances")
	}
	for _, unit := range []string{UnitBytesPerOp, UnitAllocsPerOp} {
		value, ok := budget.AllocationSlack[unit]
		if !ok || !finite(value) || value < 0 {
			return nil, fmt.Errorf("allocation_slack: restore finite nonnegative B/op and allocs/op tolerances")
		}
	}

	expected := make(map[string]struct{}, len(budget.RequiredNames))
	for _, name := range budget.RequiredNames {
		if _, duplicate := expected[name]; duplicate {
			return nil, fmt.Errorf("benchmark membership changed; required_names lists %q twice; rebaseline explicitly", name)
		}
		expected[name] = struct{}{}
	}
	for name := range budget.Baselines {
		if _, ok := expected[name]; !ok {
			return nil, fmt.Errorf("benchmark membership changed; %q is priced but not required; rebaseline explicitly", name)
		}
	}
	var missing, unpriced []string
	for name := range expected {
		if _, ok := rows[name]; !ok {
			missing = append(missing, name)
		}
	}
	for name := range rows {
		if _, ok := expected[name]; !ok {
			unpriced = append(unpriced, name)
		}
	}
	if len(missing) > 0 || len(unpriced) > 0 {
		sort.Strings(missing)
		sort.Strings(unpriced)
		return nil, fmt.Errorf("benchmark membership changed; missing=%v, unpriced=%v; review corpus/rule coverage and rebaseline explicitly", missing, unpriced)
	}

	var failures []string
	for _, name := range sortedNames(budget.Baselines) {
		baseline := budget.Baselines[name]
		units := UnitsFor(name)
		if len(baseline) != len(units) {
			return nil, fmt.Errorf("%s: baseline metrics differ from %v; restore measured costs", name, sortedNames(units))
		}
		for _, unit := range sortedNames(units) {
			value, ok := baseline[unit]
			if !ok {
				return nil, fmt.Errorf("%s: missing %s baseline; restore reviewed finite costs", name, unit)
			}
			if !finite(value) || value < 0 || (strings.HasPrefix(unit, "ns/") && value == 0) {
				return nil, fmt.Errorf("%s: invalid %s baseline; restore reviewed finite costs", name, unit)
			}
			if strings.HasPrefix(unit, "ns/") && !timing {
				continue
			}
			factor, slack := budget.TimeFactor, 0.0
			if !strings.HasPrefix(unit, "ns/") {
				factor, slack = budget.AllocationFactor, budget.AllocationSlack[unit]
			}
			limit := value*factor + slack
			measured := rows[name][unit]
			if !finite(measured) || measured > limit {
				failures = append(failures, fmt.Sprintf(
					"%s %s: median=%g, baseline=%g, budget=%g; investigate regression before approving a new baseline",
					name, unit, measured, value, limit))
			}
		}
	}
	return failures, nil
}

// Record replaces every baseline with a measured row. Callers gate this behind
// an explicit flag so normal runs never write the budget.
func Record(budget *Budget, rows Rows) {
	budget.RequiredNames = sortedNames(rows)
	budget.Baselines = make(map[string]Row, len(rows))
	for name, row := range rows {
		budget.Baselines[name] = row
	}
}

// Load reads a reviewed budget from disk.
func Load(path string) (Budget, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Budget{}, fmt.Errorf("read budget %s: %w", path, err)
	}
	var budget Budget
	if err := yaml.Unmarshal(data, &budget); err != nil {
		return Budget{}, fmt.Errorf("parse budget %s: %w", path, err)
	}
	return budget, nil
}

// Write stores a budget so a recorded baseline stays reviewable in the diff.
func Write(path string, budget Budget) error {
	data, err := yaml.Marshal(budget)
	if err != nil {
		return fmt.Errorf("encode budget: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write budget %s: %w", path, err)
	}
	return nil
}

// Report explains what the medians mean beyond pass or fail: the residue share
// of a full pass and how many strings a construction has to cover to amortize.
func Report(rows Rows, elapsed time.Duration) string {
	var b strings.Builder
	b.WriteString("\nmedian of five samples: name | ns/op | ns/byte | B/op | allocs/op\n")
	for _, name := range sortedNames(rows) {
		row := rows[name]
		fmt.Fprintf(&b, "%s | %.2f | %.4f | %.0f | %.0f\n",
			name, row[UnitNsPerOp], row[UnitNsPerByte], row[UnitBytesPerOp], row[UnitAllocsPerOp])
	}
	construction := rows["Construction"][UnitNsPerOp]
	var corpusNS, residueNS float64
	for _, name := range sortedNames(rows) {
		if !strings.HasSuffix(name, "/Full") {
			continue
		}
		corpusNS += rows[name][UnitNsPerOp]
		residueNS += rows[strings.TrimSuffix(name, "/Full")+"/Residue"][UnitNsPerOp]
	}
	fmt.Fprintf(&b, "corpus wall time (one warm Full pass, sum of medians): %.6fs\n", corpusNS/1e9)
	if corpusNS > 0 {
		fmt.Fprintf(&b, "residue scan share of Full wall time: %.2f%% (separately measured stages; not a CPU profile)\n",
			100*residueNS/corpusNS)
		fmt.Fprintf(&b, "construction: %.3fms; %.3f%% of one constructed corpus run\n",
			construction/1e6, 100*construction/(construction+corpusNS))
	}
	for _, name := range sortedNames(rows) {
		if !strings.HasSuffix(name, "/Full") || rows[name][UnitNsPerOp] == 0 {
			continue
		}
		fmt.Fprintf(&b, "%s: construction amortizes below 1%% after %.0f strings\n",
			name, math.Ceil(99*construction/rows[name][UnitNsPerOp]))
	}
	fmt.Fprintf(&b, "gate subprocess wall time (parity + benchmarks): %.3fs\n", elapsed.Seconds())
	return b.String()
}

func median(samples []Row, unit string) float64 {
	values := make([]float64, 0, len(samples))
	for _, sample := range samples {
		values = append(values, sample[unit])
	}
	sort.Float64s(values)
	return values[len(values)/2]
}

func finite(value float64) bool { return !math.IsNaN(value) && !math.IsInf(value, 0) }

func sortedNames[V any](m map[string]V) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
