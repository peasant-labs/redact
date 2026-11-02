"""Small direct tests of the actual comparator/parser; no process harness."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("engine_perf", HERE / "engine-perf.py")
perf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(perf)


class EnginePerfTest(unittest.TestCase):
    def test_reviewed_cases(self):
        fixture = json.loads((HERE.parent / "testdata/engine_perf_gate_cases.yaml").read_text())
        self.assertEqual(set(fixture["required_names"]), {row["name"] for row in fixture["cases"]})
        for row in fixture["cases"]:
            with self.subTest(row["name"]):
                baseline = fixture["baseline"]
                measured = copy.deepcopy(baseline["baselines"])
                if "unit" in row:
                    measured["Construction"][row["unit"]] *= row["factor"]
                if row.get("remove"):
                    del measured["Construction"]
                if row.get("extra"):
                    measured["Rule/new_rule"] = measured["Construction"]
                if row.get("error"):
                    with self.assertRaises(ValueError):
                        perf.compare(measured, baseline, row["timing"])
                else:
                    failures = perf.compare(measured, baseline, row["timing"])
                    self.assertEqual(bool(failures), row["fails"])
                    if failures:
                        self.assertIn("Construction", failures[0])
                        self.assertIn(row["unit"], failures[0])
                        self.assertIn("baseline=", failures[0])

    def test_parser(self):
        fixture = json.loads((HERE.parent / "testdata/engine_perf_gate_cases.yaml").read_text())
        self.assertEqual(set(fixture["required_parse_names"]), {row["name"] for row in fixture["parse_cases"]})
        for row in fixture["parse_cases"]:
            with self.subTest(row["name"]):
                output = "\n".join([row["line"]] * row["samples"])
                if row.get("error"):
                    with self.assertRaises(ValueError):
                        perf.parse(output)
                else:
                    self.assertEqual(perf.parse(output), fixture["baseline"]["baselines"])
