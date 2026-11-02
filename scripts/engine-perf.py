#!/usr/bin/env python3
"""Run and compare the selected engine against reviewed median costs (no deps)."""
import argparse
import json
import math
import os
from pathlib import Path
import re
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
BASELINE = ROOT / "testdata/engine_perf_budget.yaml"
SAMPLES = 5


def parse(output):
    rows = {}
    for line in output.splitlines():
        match = re.match(r"^BenchmarkEnginePerf/(\S+?)(?:-\d+)?\s+\d+\s+(.*)$", line)
        if not match:
            continue
        fields = match[2].split()
        values = {fields[i + 1]: float(fields[i]) for i in range(0, len(fields), 2)}
        rows.setdefault(match[1], []).append(values)
    if not rows:
        raise ValueError("no engine benchmarks found; restore BenchmarkEnginePerf before running the gate")
    for name, samples in rows.items():
        if len(samples) != SAMPLES:
            raise ValueError(f"{name}: got {len(samples)} samples, require {SAMPLES}; rerun the complete command")
        required = {"ns/op", "B/op", "allocs/op"}
        if not name.startswith(("Construction", "RuleCompile/")):
            required.add("ns/byte")
        for sample in samples:
            if not required <= sample.keys() or any(not math.isfinite(v) or v < 0 for v in sample.values()):
                raise ValueError(f"{name}: missing/invalid benchmark metrics; rerun with -benchmem")
    return {name: {unit: statistics.median(s[unit] for s in samples) for unit in samples[0]}
            for name, samples in rows.items()}


def compare(rows, budget, timing):
    for key in ("time_factor", "allocation_factor"):
        if not math.isfinite(budget[key]) or budget[key] < 1:
            raise ValueError(f"{key}: restore a reviewed finite relative factor >= 1")
    if set(budget["allocation_slack"]) != {"B/op", "allocs/op"} or any(
            not math.isfinite(value) or value < 0 for value in budget["allocation_slack"].values()):
        raise ValueError("allocation_slack: restore finite nonnegative B/op and allocs/op tolerances")
    expected = set(budget["required_names"])
    if len(expected) != len(budget["required_names"]) or expected != set(budget["baselines"]) or expected != set(rows):
        raise ValueError(f"benchmark membership changed; missing={sorted(expected - set(rows))}, "
                         f"unpriced={sorted(set(rows) - expected)}; review corpus/rule coverage and rebaseline explicitly")
    failures = []
    for name, baseline in budget["baselines"].items():
        units = {"ns/op", "B/op", "allocs/op"}
        if not name.startswith(("Construction", "RuleCompile/")):
            units.add("ns/byte")
        if set(baseline) != units:
            raise ValueError(f"{name}: baseline metrics differ from {sorted(units)}; restore measured costs")
        for unit, value in baseline.items():
            if unit not in rows[name] or not math.isfinite(value) or value < 0 or (unit.startswith("ns/") and value == 0):
                raise ValueError(f"{name}: invalid/missing {unit} baseline; restore reviewed finite costs")
            if unit in ("ns/op", "ns/byte") and not timing:
                continue
            factor = budget["time_factor"] if unit.startswith("ns/") else budget["allocation_factor"]
            slack = 0 if unit.startswith("ns/") else budget["allocation_slack"][unit]
            limit = value * factor + slack
            measured = rows[name][unit]
            if not math.isfinite(measured) or measured > limit:
                failures.append(f"{name} {unit}: median={measured:g}, baseline={value:g}, "
                                f"budget={limit:g}; investigate regression before approving a new baseline")
    return failures


def report(rows, elapsed):
    print("\nmedian of five samples: name | ns/op | ns/byte | B/op | allocs/op")
    for name, row in rows.items():
        print(f"{name} | {row['ns/op']:.2f} | {row.get('ns/byte', 0):.4f} | "
              f"{row['B/op']:.0f} | {row['allocs/op']:.0f}")
    construction = rows["Construction"]["ns/op"]
    full = {name: row for name, row in rows.items() if name.endswith("/Full")}
    corpus_ns = sum(row["ns/op"] for row in full.values())
    residue_ns = sum(rows[name.removesuffix("/Full") + "/Residue"]["ns/op"] for name in full)
    print(f"corpus wall time (one warm Full pass, sum of medians): {corpus_ns / 1e9:.6f}s")
    print(f"residue scan share of Full wall time: {100 * residue_ns / corpus_ns:.2f}% "
          "(separately measured stages; not a CPU profile)")
    print(f"construction: {construction / 1e6:.3f}ms; "
          f"{100 * construction / (construction + corpus_ns):.3f}% of one constructed corpus run")
    for name, row in full.items():
        print(f"{name}: construction amortizes below 1% after "
              f"{math.ceil(99 * construction / row['ns/op'])} strings")
    print(f"gate subprocess wall time (parity + benchmarks): {elapsed:.3f}s")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record", action="store_true", help="explicitly replace baseline after review; never used by make/CI")
    parser.add_argument("--ci", action="store_true", help="enforce allocation budgets only; retain timing report")
    args = parser.parse_args()
    env = dict(os.environ, REDACT_PERF="1")
    command = ["go", "test", "-run", "^TestEngine.*Parity$", "-bench", "^BenchmarkEnginePerf$",
               "-benchmem", "-benchtime=100ms", f"-count={SAMPLES}", "-cpu=1", "-timeout=10m", "."]
    print("command:", " ".join(command), flush=True)
    start = time.monotonic()
    result = subprocess.run(command, cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=660)
    print(result.stdout, end="")
    if result.returncode:
        return result.returncode
    rows = parse(result.stdout)
    report(rows, time.monotonic() - start)
    budget = json.loads(BASELINE.read_text()) # JSON is a YAML subset; no PyYAML dependency.
    if args.record:
        budget["required_names"] = sorted(rows)
        budget["baselines"] = {name: {unit: value for unit, value in row.items() if unit != "MB/s"}
                               for name, row in sorted(rows.items())}
        BASELINE.write_text(json.dumps(budget, indent=2) + "\n")
        print("baseline replaced explicitly; inspect diff and rerun make perf before committing")
        return 0
    failures = compare(rows, budget, timing=not args.ci)
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print("PASS: relative median budgets" + (" (allocation-only CI; timing is a required local release gate)" if args.ci else ""))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, KeyError, subprocess.TimeoutExpired) as error:
        sys.exit(f"engine performance gate failed: {error}")
