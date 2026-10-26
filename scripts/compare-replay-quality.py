#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare two Carthago tuning-benchmark JSON reports without exposing telemetry.

Usage: python scripts/compare-replay-quality.py --baseline old.json --candidate new.json --strict
The shared-fixture cohort isolates behavior changes from fixture-set expansion.
All results are offline simulated alert decisions, not production precision.
"""
import argparse
import json
import sys
from pathlib import Path

PROFILES = ("Enterprise", "HomeLab", "IoTHeavy", "OTSegment", "Research", "SmallBusiness")
FLOORS = {"R118": .86, "R163": .84, "R102": .80}


class InvalidReport(ValueError):
    pass


def load(path):
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    samples = data.get("sampleResults")
    summary = data.get("summary")
    if not isinstance(samples, list) or not isinstance(summary, dict) or not samples:
        raise InvalidReport("missing sampleResults or summary")
    if summary.get("replaySampleCount") != len(samples):
        raise InvalidReport("replaySampleCount disagrees with sampleResults")
    by_name = {}
    for sample in samples:
        if not isinstance(sample, dict) or not isinstance(sample.get("name"), str):
            raise InvalidReport("sample missing name")
        name = sample["name"]
        if name in by_name:
            raise InvalidReport("duplicate sample name")
        if sample.get("classification") not in ("Benign", "Malicious"):
            raise InvalidReport("invalid classification")
        if sample.get("errors"):
            raise InvalidReport("benchmark contains replay errors")
        profiles = sample.get("profiles")
        if not isinstance(profiles, dict) or any(not isinstance(profiles.get(p), dict) for p in PROFILES):
            raise InvalidReport("sample missing a required profile")
        for p in PROFILES:
            if not isinstance(profiles[p].get("alertRuleIds"), list):
                raise InvalidReport("sample missing alertRuleIds")
        by_name[name] = sample
    # Recalculate rather than trusting potentially stale report-level metrics.
    expected = summary.get("sampleLevelQualityByProfile")
    if not isinstance(expected, dict):
        raise InvalidReport("missing sampleLevelQualityByProfile")
    for p in PROFILES:
        if not isinstance(expected.get(p), dict):
            raise InvalidReport("missing summary profile")
        calculated = matrix(by_name.values(), p)
        for key, value in calculated.items():
            if expected[p].get(key) != value:
                raise InvalidReport("summary confusion matrix disagrees with sample decisions")
    return by_name


def matrix(samples, profile, rule=None):
    counts = {"truePositives": 0, "falsePositives": 0, "falseNegatives": 0, "trueNegatives": 0}
    for sample in samples:
        alerts = sample["profiles"][profile]["alertRuleIds"]
        if rule:
            positive = rule in sample.get("expectedMatches", []) and sample["classification"] == "Malicious"
            negative = rule in sample.get("expectedNonMatches", [])
            if positive and negative:
                raise InvalidReport("contradictory rule labels")
            if not (positive or negative):
                continue  # Unlabeled samples are NOT negative controls.
        else:
            positive = sample["classification"] == "Malicious"
        alert = (rule in alerts) if rule else bool(alerts)
        key = ("truePositives" if alert else "falseNegatives") if positive else ("falsePositives" if alert else "trueNegatives")
        counts[key] += 1
    return counts


def ratios(c):
    tp, fp, fn = c["truePositives"], c["falsePositives"], c["falseNegatives"]
    return (tp / (tp + fp) if tp + fp else None,
            tp / (tp + fn) if tp + fn else None,
            2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None)


def percent(v):
    return "N/A" if v is None else f"{v * 100:.1f}%"


def render(profile, label, c):
    precision, recall, f1 = ratios(c)
    return (f"{profile:14} {label:12} "
            f"{c['truePositives']:3} {c['falsePositives']:3} {c['falseNegatives']:3} {c['trueNegatives']:3} "
            f"{percent(precision):>7} {percent(recall):>7} {percent(f1):>7}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--strict", action="store_true", help="Fail on benign alerts, shared-cohort regressions or target-rule promotion")
    args = parser.parse_args(argv)
    baseline, candidate = load(args.baseline), load(args.candidate)
    shared = sorted(baseline.keys() & candidate.keys())
    added, removed = candidate.keys() - baseline.keys(), baseline.keys() - candidate.keys()
    if any(baseline[name]["classification"] != candidate[name]["classification"] for name in shared):
        raise InvalidReport("classification changed for an existing sample")
    print(f"Samples: baseline={len(baseline)} candidate={len(candidate)} shared={len(shared)} added={len(added)} removed={len(removed)}")
    print("Offline simulated alert decisions; synthetic variants are correlated, not independent field observations.")
    print("Profile        Cohort        TP  FP  FN  TN Prec.   Recall      F1")
    failures = []
    for p in PROFILES:
        old_full, new_full = matrix(baseline.values(), p), matrix(candidate.values(), p)
        old_shared = matrix((baseline[name] for name in shared), p)
        new_shared = matrix((candidate[name] for name in shared), p)
        for label, values in (("old-all", old_full), ("new-all", new_full),
                              ("old-shared", old_shared), ("new-shared", new_shared)):
            print(render(p, label, values))
        if new_full["falsePositives"]:
            failures.append(f"{p}: benign alert(s) in candidate")
        if new_shared["falsePositives"] > old_shared["falsePositives"]:
            failures.append(f"{p}: new false positive(s) on shared cohort")
        if new_shared["truePositives"] < old_shared["truePositives"]:
            failures.append(f"{p}: lost true positive(s) on shared cohort")
    print("\nExplicitly labeled rule-level alert opportunities (candidate only):")
    print("Profile        Rule          TP  FP  FN  TN Prec.   Recall      F1")
    for p in PROFILES:
        for rule in FLOORS:
            print(render(p, rule, matrix(candidate.values(), p, rule)))
    for sample in candidate.values():
        for p in PROFILES:
            profile = sample["profiles"][p]
            for rule in FLOORS:
                if rule in profile["alertRuleIds"]:
                    failures.append(f"{p}: {rule} emitted an alert; promotion HOLD")
                for decision in profile.get("ruleDecisions", []):
                    if decision.get("ruleId") != rule:
                        continue
                    floor = decision.get("confidenceFloor")
                    if floor is not None and float(floor) + 1e-9 < FLOORS[rule]:
                        failures.append(f"{p}: {rule} confidence floor below required minimum")
    print("\nPromotion: HOLD for R118 (86%), R163 (84%), R102 (80%).")
    if failures:
        print(f"Quality gates: {len(failures)} violation(s); no telemetry values printed.", file=sys.stderr)
        if args.strict:
            return 2
    else:
        print("Quality gates: no observed violations in these reports (not a production validation).")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (InvalidReport, OSError, ValueError, TypeError, KeyError) as exc:
        print(f"Cannot compare reports: {type(exc).__name__} (details withheld).", file=sys.stderr)
        sys.exit(2)
