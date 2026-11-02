package perf

import (
	"os"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// gateCaseName identifies a reviewed comparator case in the fixture.
type gateCaseName string

const (
	gateWithinBudget         gateCaseName = "within_budget"
	gateTimeRegression       gateCaseName = "time_regression"
	gateAllocationRegression gateCaseName = "allocation_regression"
	gateMissingRow           gateCaseName = "missing_row"
	gateUnpricedRule         gateCaseName = "unpriced_rule"
	gateCIAllocation         gateCaseName = "ci_retains_allocation_gate"
	gateCITimeOnly           gateCaseName = "ci_reports_time_only"
)

var gateCaseNames = []gateCaseName{
	gateWithinBudget,
	gateTimeRegression,
	gateAllocationRegression,
	gateMissingRow,
	gateUnpricedRule,
	gateCIAllocation,
	gateCITimeOnly,
}

func parseGateCaseName(value string) (gateCaseName, error) {
	for _, name := range gateCaseNames {
		if string(name) == value {
			return name, nil
		}
	}
	return "", &fixtureNameError{family: "gate case", value: value}
}

// parseCaseName identifies a reviewed benchmark-output parse case.
type parseCaseName string

const (
	parseComplete           parseCaseName = "complete"
	parseEmpty              parseCaseName = "empty"
	parsePartial            parseCaseName = "partial"
	parseMissingAllocations parseCaseName = "missing_allocations"
	parseNonFinite          parseCaseName = "non_finite"
	parseSingleCPUSuffix    parseCaseName = "single_cpu_suffix"
)

var parseCaseNames = []parseCaseName{
	parseComplete,
	parseEmpty,
	parsePartial,
	parseMissingAllocations,
	parseNonFinite,
	parseSingleCPUSuffix,
}

func parseOutputCaseName(value string) (parseCaseName, error) {
	for _, name := range parseCaseNames {
		if string(name) == value {
			return name, nil
		}
	}
	return "", &fixtureNameError{family: "parse case", value: value}
}

// gateUnit names the priced unit a case perturbs. The empty value leaves every
// unit untouched.
type gateUnit string

const (
	gateNoUnit      gateUnit = ""
	gateNsPerOp     gateUnit = UnitNsPerOp
	gateBytesPerOp  gateUnit = UnitBytesPerOp
	gateAllocsPerOp gateUnit = UnitAllocsPerOp
)

type fixtureNameError struct {
	family string
	value  string
}

func (e *fixtureNameError) Error() string {
	return "engine performance gate fixture has an unreviewed " + e.family + " " + e.value
}

type gateCase struct {
	Name   string  `yaml:"name"`
	Factor float64 `yaml:"factor"`
	Unit   string  `yaml:"unit"`
	Timing bool    `yaml:"timing"`
	Fails  bool    `yaml:"fails"`
	Remove bool    `yaml:"remove"`
	Extra  bool    `yaml:"extra"`
	Error  bool    `yaml:"error"`
}

type parseCase struct {
	Name    string `yaml:"name"`
	Line    string `yaml:"line"`
	Samples int    `yaml:"samples"`
	Error   bool   `yaml:"error"`
}

type gateFixture struct {
	RequiredNames      []string    `yaml:"required_names"`
	Cases              []gateCase  `yaml:"cases"`
	Baseline           Budget      `yaml:"baseline"`
	RequiredParseNames []string    `yaml:"required_parse_names"`
	ParseCases         []parseCase `yaml:"parse_cases"`
}

func loadGateFixture(t *testing.T) gateFixture {
	t.Helper()
	data, err := os.ReadFile("testdata/engine_perf_gate_cases.yaml")
	if err != nil {
		t.Fatalf("read gate fixture: %v", err)
	}
	var fixture gateFixture
	if err := yaml.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("parse gate fixture: %v", err)
	}
	return fixture
}

func requireReviewedNames(t *testing.T, family string, listed []string, reviewed []string, parse func(string) (string, error)) {
	t.Helper()
	names := make([]string, 0, len(listed))
	for _, value := range listed {
		name, err := parse(value)
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}
	slices.Sort(names)
	sorted := slices.Clone(reviewed)
	slices.Sort(sorted)
	if !slices.Equal(names, sorted) {
		t.Fatalf("%s manifest is %v but the reviewed set is %v; name every reviewed case exactly once", family, names, sorted)
	}
}

func TestGateFixtureCases(t *testing.T) {
	fixture := loadGateFixture(t)
	requireReviewedNames(t, "gate case", fixture.RequiredNames, gateNameStrings(), func(value string) (string, error) {
		name, err := parseGateCaseName(value)
		return string(name), err
	})
	for _, row := range fixture.Cases {
		name, err := parseGateCaseName(row.Name)
		if err != nil {
			t.Fatal(err)
		}
		t.Run(string(name), func(t *testing.T) {
			baseline := cloneBudget(fixture.Baseline)
			measured := cloneRows(baseline.Baselines)
			unit := gateUnit(row.Unit)
			if unit != gateNoUnit {
				measured["Construction"][string(unit)] *= row.Factor
			}
			if row.Remove {
				delete(measured, "Construction")
			}
			if row.Extra {
				measured["Rule/new_rule"] = cloneRow(measured["Construction"])
			}
			failures, err := Compare(measured, baseline, row.Timing)
			if row.Error {
				if err == nil {
					t.Fatal("a changed benchmark membership must fail closed")
				}
				return
			}
			if err != nil {
				t.Fatalf("compare: %v", err)
			}
			if got := len(failures) > 0; got != row.Fails {
				t.Fatalf("failures=%v; want fails=%v", failures, row.Fails)
			}
			if len(failures) > 0 {
				if !strings.Contains(failures[0], "Construction") || !strings.Contains(failures[0], string(unit)) || !strings.Contains(failures[0], "baseline=") {
					t.Fatalf("failure %q must name the benchmark, the unit and the baseline", failures[0])
				}
			}
		})
	}
}

func TestParseFixtureCases(t *testing.T) {
	fixture := loadGateFixture(t)
	requireReviewedNames(t, "parse case", fixture.RequiredParseNames, parseNameStrings(), func(value string) (string, error) {
		name, err := parseOutputCaseName(value)
		return string(name), err
	})
	for _, row := range fixture.ParseCases {
		name, err := parseOutputCaseName(row.Name)
		if err != nil {
			t.Fatal(err)
		}
		t.Run(string(name), func(t *testing.T) {
			output := ""
			for i := 0; i < row.Samples; i++ {
				if i > 0 {
					output += "\n"
				}
				output += row.Line
			}
			rows, err := Parse(output)
			if row.Error {
				if err == nil {
					t.Fatal("unreadable benchmark output must fail closed")
				}
				return
			}
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(rows) != len(fixture.Baseline.Baselines) {
				t.Fatalf("rows=%v; want %v", rows, fixture.Baseline.Baselines)
			}
			for name, want := range fixture.Baseline.Baselines {
				got, ok := rows[name]
				if !ok {
					t.Fatalf("missing row %q", name)
				}
				for unit, wantValue := range want {
					if got[unit] != wantValue {
						t.Fatalf("%s %s = %v; want %v", name, unit, got[unit], wantValue)
					}
				}
			}
		})
	}
}

func gateNameStrings() []string {
	names := make([]string, 0, len(gateCaseNames))
	for _, name := range gateCaseNames {
		names = append(names, string(name))
	}
	return names
}

func parseNameStrings() []string {
	names := make([]string, 0, len(parseCaseNames))
	for _, name := range parseCaseNames {
		names = append(names, string(name))
	}
	return names
}

func cloneBudget(budget Budget) Budget {
	cloned := budget
	cloned.AllocationSlack = make(map[string]float64, len(budget.AllocationSlack))
	for unit, value := range budget.AllocationSlack {
		cloned.AllocationSlack[unit] = value
	}
	cloned.RequiredNames = slices.Clone(budget.RequiredNames)
	cloned.Baselines = cloneRows(budget.Baselines)
	return cloned
}

func cloneRows(rows map[string]Row) map[string]Row {
	cloned := make(map[string]Row, len(rows))
	for name, row := range rows {
		cloned[name] = cloneRow(row)
	}
	return cloned
}

func cloneRow(row Row) Row {
	cloned := make(Row, len(row))
	for unit, value := range row {
		cloned[unit] = value
	}
	return cloned
}
