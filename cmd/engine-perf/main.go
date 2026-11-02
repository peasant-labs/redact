// Command engine-perf runs the redaction engine benchmarks and compares their
// medians with the reviewed budget. It is the local release gate behind
// `make perf`; CI passes --ci to enforce allocation budgets only.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/peasant-labs/redact/internal/perf"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	flags := flag.NewFlagSet("engine-perf", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	record := flags.Bool("record", false, "explicitly replace the baseline after review; never used by make or CI")
	ci := flags.Bool("ci", false, "enforce allocation budgets only; retain the timing report")
	budgetPath := flags.String("budget", "testdata/engine_perf_budget.yaml", "reviewed budget to compare against")
	dir := flags.String("dir", ".", "directory holding the redaction package")
	timeout := flags.Duration("timeout", 11*time.Minute, "cap on the benchmark subprocess")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	benchArgs := []string{
		"test",
		"-run", "^TestEngine.*Parity$",
		"-bench", "^BenchmarkEnginePerf$",
		"-benchmem",
		"-benchtime=100ms",
		fmt.Sprintf("-count=%d", perf.Samples),
		"-cpu=1",
		"-timeout=10m",
		".",
	}
	fmt.Fprintln(os.Stderr, "command: go "+strings.Join(benchArgs, " "))
	start := time.Now()
	cmd := exec.CommandContext(ctx, "go", benchArgs...)
	cmd.Dir = *dir
	cmd.Env = append(os.Environ(), "REDACT_PERF=1")
	output, err := cmd.CombinedOutput()
	fmt.Print(string(output))
	if ctx.Err() != nil {
		fmt.Fprintf(os.Stderr, "engine performance gate failed: the benchmark subprocess exceeded %s; shrink the priced corpus or lower the sample count\n", *timeout)
		return 1
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "engine performance gate failed: benchmarks did not pass (%v); the benchmark output above names the failing test\n", err)
		return 1
	}

	rows, err := perf.Parse(string(output))
	if err != nil {
		fmt.Fprintf(os.Stderr, "engine performance gate failed: %v\n", err)
		return 1
	}
	fmt.Print(perf.Report(rows, time.Since(start)))

	budget, err := perf.Load(*budgetPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "engine performance gate failed: %v\n", err)
		return 1
	}
	if *record {
		perf.Record(&budget, rows)
		if err := perf.Write(*budgetPath, budget); err != nil {
			fmt.Fprintf(os.Stderr, "engine performance gate failed: %v\n", err)
			return 1
		}
		fmt.Println("baseline replaced explicitly; inspect the diff and rerun make perf before committing")
		return 0
	}

	failures, err := perf.Compare(rows, budget, !*ci)
	if err != nil {
		fmt.Fprintf(os.Stderr, "engine performance gate failed: %v\n", err)
		return 1
	}
	if len(failures) > 0 {
		for _, failure := range failures {
			fmt.Fprintln(os.Stderr, failure)
		}
		return 1
	}
	if *ci {
		fmt.Println("PASS: relative median budgets (allocation-only CI; timing is a required local release gate)")
		return 0
	}
	fmt.Println("PASS: relative median budgets")
	return 0
}
