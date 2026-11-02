# Engine performance release gate

Before a release, run on a quiet machine with Go 1.26.0:

```sh
GOTOOLCHAIN=go1.26.0 make check
GOTOOLCHAIN=go1.26.0 make perf
GOTOOLCHAIN=go1.26.0 make bench
```

`make perf` needs Go and Python 3's standard library only. The exact measurement
command is printed before execution:

```sh
REDACT_PERF=1 go test -run '^TestEngine.*Parity$' \
  -bench '^BenchmarkEnginePerf$' -benchmem -benchtime=100ms \
  -count=5 -cpu=1 -timeout=10m .
```

No network, database, developer home, transcript files, or service is used by
the corpus. As with any Go build, provision the toolchain and module cache first
when running offline. The corpus is deterministic byte repetition and explicit
plants, not sampled user text. Its reviewed YAML specifies 192-byte metadata,
8-KiB tool output, and a 64-MiB-plus-1-KiB string. Sparse plants keep the large
case bounded without generating millions of Match objects. This is a scan-cost
baseline, not a model of every transcript's match density.

## What is measured

- `Construction`: the public Standard constructor, including all engine-specific
  built-in and residue compilation; one construction per operation.
- `WholeSet`: all built-in rules (including rules inactive at Standard), using
  the canonical detector with filters and offsets. Every rule has a separate
  8-KiB scan budget and compile budget. Rule membership is checked in `make check`,
  so a new rule cannot ship without being priced.
- `Full`: the public Standard `RedactText`, including reporting and residue scan.
  It is not falsely described as activating Maximum-only rules.
- `Residue`: the real redactor's advisory scanner on the literal expected
  redacted output, normalized to original input bytes. Its time divided by Full
  time is a separately measured wall-time share, not a CPU profile. Warnings
  remain enabled in production; this change adds no opt-out.

Every scan reports `ns/byte`, `B/op`, and `allocs/op`. The report includes medians
of five samples, the sum of median Full times for one corpus pass, construction
cost/share, the number of strings needed to amortize construction below 1%, and
the wall time of the entire parity/benchmark subprocess. Construction is outside
warm scans; it is measured independently, not hidden. `make bench` retains the
cross-engine construction/first-detection comparison.

Use the amortization lines to decide reuse for the actual workload: one
constructor per run pays a fixed millisecond-scale startup cost, while repeated
construction for short strings can dominate useful scanning. Reuse a redactor
within a run; these measurements do not change caller lifetimes or promise that
per-session construction is free. `B/op` measures Go heap allocation, not peak
resident memory or all engine-managed memory.

Before timing, the same input must produce exact planted counts and byte-identical
output against a literal golden built from the fixture's replacement strings.
The oracle does not call the engine. The ordinary test suite checks the small
cases and budget coverage; `make perf` also checks the large case. The existing
differential engine fixtures run in the same command, so dropping any rule's
reviewed behavior fails before its timing is accepted. The fallback also remains
mandatory via `make check`.

## Budgets and CI

`testdata/engine_perf_budget.yaml` uses JSON syntax (valid YAML) to avoid a Python
YAML dependency. It records medians, not machine-independent promises. The initial
reference machine is Linux/amd64, AMD Ryzen 9 7950X3D, Go 1.26.0, one benchmark
CPU. A timing regression above **2x** the recorded median fails the local gate.
Allocations above **1.25x plus 512 bytes / 8 allocations per operation** also fail;
the small slack permits runtime/pool rounding without making zero-allocation rows
unpriced. All per-rule scans, per-rule compiles, stages, and construction have
explicit rows. Errors identify the measurement, unit, median, baseline and limit.

CI runs `make perf PERF_ARGS=--ci`: it requires the same large/small golden parity,
exact benchmark membership, complete five-sample reports and allocation budgets.
It prints timing but does not enforce host-specific timing budgets. The runner
router chooses either shared self-hosted containers or GitHub-hosted runners;
CPU generation, contention and scheduling are not stable between runs. Even a
relative comparison with a committed wall-time baseline is not portable across
those hosts. Therefore **the full timing gate is a required local release gate**;
attach its report to release review. Do not substitute the allocation-only CI
pass for that evidence. No release workflow silently records a new baseline.

For an approved intentional cost change, use the explicit maintainer command:

```sh
GOTOOLCHAIN=go1.26.0 python3 scripts/engine-perf.py --record
GOTOOLCHAIN=go1.26.0 make perf
```

Review every changed baseline and relative factor as data. Normal gate execution
never writes the budget. Never use `--record` merely to silence a regression.

## Still required before integration

The large input is measured without assuming an unreleased chunk-policy API.
After the chunking implementation lands, compare chunked and unchunked scans on
the **same** fixture: identical bytes, absolute match offsets/counts, no duplicate
or missed matches, measured overhead. Re-review affected baselines after rebasing;
do not attribute an output difference to timing noise. This gate alone does not
claim to prove chunk-boundary behavior.

## Optional approved local corpus

```sh
PEASANT_REDACT_CORPUS_DIR=/explicit/approved/directory \
  GOTOOLCHAIN=go1.26.0 go test -run '^TestEngineBudgetRealCorpus$' -v .
```

Unset means skip; this is never read by `make perf`. The diagnostic reads regular
top-level files only, at most 16 files, 64 MiB per file and 128 MiB total. Supply
valid UTF-8 (the API precondition); it does not normalize or validate text. It logs
only aggregate bytes/time, never names, contents, matches or warnings. Its timing
does not replace the synthetic budget or parity proof. Do not commit its data.

## Test cost and ownership

Parity executes the public library path; benchmark stages execute the existing
detector and residue scanner directly, not copied implementations. A direct
fixture test catches lost redactions, and small direct Python fixture tests catch
budget/parser regressions. Only timing needs the Go benchmark process. There are
no shared temporary files, services, or screenshot scans. Python launches one
`go test` command, which builds/runs the test binary. The binary has Go's
10-minute timeout and the launcher has Python's 11-minute timeout. If the launcher
is killed, the test binary still has its own timeout; the corpus is in memory
only and dies with that process. Expected runtime is minutes, not a default-suite
tax. Simplify the timing harness if Go gains a portable cross-host cost metric;
retain the literal parity and allocation checks.
