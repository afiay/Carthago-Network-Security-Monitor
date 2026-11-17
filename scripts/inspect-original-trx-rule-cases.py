#!/usr/bin/env python3
"""Read-only original TRX exact-test candidate inventory; never admits qualification."""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

NS = "{http://microsoft.com/schemas/VisualStudio/TeamTest/2010}"
ID = re.compile(r"(?<![A-Za-z0-9])R[0-9]{3,4}(?![0-9])")
OUTCOMES = {"Passed", "Failed", "Error", "Timeout", "Aborted", "Inconclusive", "NotExecuted", "Pending"}
MAX_BYTES = 16 * 1024 * 1024
MAX_RESULTS = 100000

def inspect(path: Path) -> dict:
    if not path.is_file() or path.stat().st_size > MAX_BYTES or path.stat().st_size == 0:
        raise ValueError("Missing, empty or oversized original TRX")
    data = path.read_bytes()
    if b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        raise ValueError("DTD/entity declaration not permitted")
    root = ET.fromstring(data)
    if root.tag != NS + "TestRun":
        raise ValueError("Unsupported TRX namespace/root")
    results = root.find(NS + "Results")
    summary = root.find(NS + "ResultSummary")
    if results is None or summary is None or summary.get("outcome") not in {"Completed", "Passed", "Failed"}:
        raise ValueError("Incomplete TRX")
    nodes = list(results)
    if not nodes or len(nodes) > MAX_RESULTS or any(node.tag != NS + "UnitTestResult" for node in nodes):
        raise ValueError("Unsupported or excessive result nodes")
    rows = []
    for node in nodes:
        name, outcome = node.get("testName"), node.get("outcome")
        if not name or len(name) > 4096 or outcome not in OUTCOMES:
            raise ValueError("Missing test identity or unknown outcome")
        ids = sorted(set(ID.findall(name)))
        rows.append({"exactTestName": name, "testId": node.get("testId"),
                     "outcome": outcome, "candidateRuleIds": ids,
                     "casePolarity": "unreviewed", "sourceSha": None,
                     "qualificationStatus": "not-admitted"})
    if any(not r["testId"] or len(r["testId"]) > 256 for r in rows):
        raise ValueError("Missing or oversized testId")
    if len({r["testId"] for r in rows}) != len(rows):
        raise ValueError("Duplicate testId across original results")
    if len({r["exactTestName"] for r in rows}) != len(rows):
        raise ValueError("Duplicate exact test name across original results")
    counters = summary.find(NS + "Counters")
    if counters is not None:
        actual = {"total": len(rows),
                  "passed": sum(r["outcome"] == "Passed" for r in rows),
                  "failed": sum(r["outcome"] == "Failed" for r in rows)}
        for key, expected in actual.items():
            raw = counters.get(key)
            if raw is not None and (not raw.isdecimal() or int(raw) != expected):
                raise ValueError("TRX summary counter mismatch: " + key)
    if summary.get("outcome") == "Passed" and any(r["outcome"] != "Passed" for r in rows):
        raise ValueError("Passed run contains non-passing result")
    if summary.get("outcome") == "Failed" and not any(r["outcome"] in {"Failed", "Error", "Timeout", "Aborted"} for r in rows):
        raise ValueError("Failed run contains no failing result")
    return {"schemaVersion": 1, "purpose": "original-trx-candidate-only",
            "originalTrxSha256": hashlib.sha256(data).hexdigest(),
            "originalResultCount": len(rows), "testsExecutedByInspector": 0,
            "evidenceAdmitted": False, "sourceShaAttested": False,
            "warning": "Rule IDs parsed from names are hints, not detector polarity or execution-source proof.",
            "results": rows}


def parse_review_json(data: bytes) -> dict:
    """Reject ambiguous duplicate keys rather than silently overriding review claims."""
    def unique_pairs(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError("Duplicate reviewed-map JSON key")
            obj[key] = value
        return obj
    return json.loads(data.decode("utf-8"), object_pairs_hook=unique_pairs)


def reconcile_reviewed_cases(report: dict, review: dict) -> dict:
    """Join exact reviewed declarations; never attest independent qualification."""
    if not isinstance(review, dict) or review.get("schemaVersion") != 1:
        raise ValueError("Unsupported review schema")
    if review.get("originalTrxSha256") != report["originalTrxSha256"]:
        raise ValueError("Original TRX digest mismatch")
    cases = review.get("cases")
    if not isinstance(cases, list) or len(cases) > MAX_RESULTS:
        raise ValueError("Invalid review cases")
    original = {(x["testId"], x["exactTestName"]): x for x in report["results"]}
    seen = set()
    joined = []
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("Invalid review entry")
        key = (case.get("testId"), case.get("exactTestName"))
        if key in seen or key not in original:
            raise ValueError("Duplicate or unmatched test identity")
        seen.add(key)
        rid = case.get("exactRuleId")
        polarity = case.get("casePolarity")
        if not isinstance(rid, str) or not re.fullmatch(r"R[0-9]{3,4}", rid):
            raise ValueError("Invalid exact rule ID")
        if rid not in original[key]["candidateRuleIds"]:
            raise ValueError("Rule ID not in test identity candidates")
        if polarity not in ("positive-detector", "negative-detector"):
            raise ValueError("Invalid detector polarity")
        joined.append({"testId": key[0], "exactTestName": key[1],
                       "exactRuleId": rid, "casePolarity": polarity,
                       "outcome": original[key]["outcome"],
                       "qualificationStatus": "not-admitted"})
    return {"originalTrxSha256": report["originalTrxSha256"],
            "reviewedCases": joined, "unreviewedCount": len(original)-len(joined),
            "sourceShaAttested": False, "evidenceAdmitted": False}

def self_test() -> None:
    import tempfile
    xml = ('<TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010">'
           '<Results><UnitTestResult testName="R102.Positive" testId="a" outcome="Passed"/>'
           '<UnitTestResult testName="Benign.Control" testId="b" outcome="Failed"/></Results>'
           '<ResultSummary outcome="Completed"/></TestRun>')
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "test.trx"
        p.write_text(xml, encoding="utf-8")
        r = inspect(p)
        assert r["results"][0]["candidateRuleIds"] == ["R102"]
        assert r["results"][1]["candidateRuleIds"] == []
        review = {"schemaVersion": 1, "originalTrxSha256": r["originalTrxSha256"],
                  "cases": [{"testId": "a", "exactTestName": "R102.Positive",
                             "exactRuleId": "R102", "casePolarity": "positive-detector"}]}
        assert parse_review_json(json.dumps(review).encode("utf-8")) == review
        for malformed in (b'{"schemaVersion":1,"schemaVersion":2}',
                          b'{"cases":[{"testId":"a","testId":"b"}]}'):
            try:
                parse_review_json(malformed)
            except ValueError:
                pass
            else:
                raise AssertionError("Duplicate reviewed-map key accepted")
        joined = reconcile_reviewed_cases(r, review)
        assert len(joined["reviewedCases"]) == 1 and joined["unreviewedCount"] == 1
        assert not joined["evidenceAdmitted"]
        for bad in (
            {**review, "originalTrxSha256": "0" * 64},
            {**review, "cases": review["cases"] * 2},
            {**review, "cases": [{**review["cases"][0], "casePolarity": "unknown"}]},
            {**review, "cases": [{**review["cases"][0], "exactRuleId": "R163"}]},
            {**review, "cases": [{**review["cases"][0], "testId": "missing"}]},
        ):
            try:
                reconcile_reviewed_cases(r, bad)
            except ValueError:
                pass
            else:
                raise AssertionError("Invalid review mapping accepted")
        assert all(x["casePolarity"] == "unreviewed" and x["sourceSha"] is None for x in r["results"])
        for bad in (xml.replace('outcome="Passed"', 'outcome="Unknown"'),
                    '<!DOCTYPE TestRun>' + xml,
                    xml.replace('testId="b"', 'testId="a"'),
                    xml.replace('testName="Benign.Control"', 'testName="R102.Positive"'),
                    xml.replace('<UnitTestResult testName="R102.Positive" testId="a" outcome="Passed"/>', '').replace('<UnitTestResult testName="Benign.Control" testId="b" outcome="Failed"/>', ''),
                    xml.replace('<ResultSummary outcome="Completed"/>',
                                '<ResultSummary outcome="Completed"><Counters total="3" passed="1" failed="1"/></ResultSummary>'),
                    xml.replace('outcome="Completed"', 'outcome="Passed"'),
                    xml.replace('outcome="Completed"', 'outcome="Failed"').replace('outcome="Failed"/></Results>', 'outcome="Passed"/></Results>')):
            p.write_text(bad, encoding="utf-8")
            try:
                inspect(p)
            except (ValueError, ET.ParseError):
                pass
            else:
                raise AssertionError("Invalid fixture accepted")
    print(json.dumps({"selfTest": "passed", "originalTestsExecuted": 0}))

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trx", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--reviewed-map", type=Path)
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if args.trx is None or args.output is None:
        parser.error("--trx and --output required")
    if args.output.exists() or args.output.resolve() == args.trx.resolve():
        parser.error("Refusing overwrite")
    report = inspect(args.trx)
    if args.reviewed_map is not None:
        if not args.reviewed_map.is_file() or not 0 < args.reviewed_map.stat().st_size <= MAX_BYTES:
            raise ValueError("Missing or oversized review map")
        review_bytes = args.reviewed_map.read_bytes()
        review = parse_review_json(review_bytes)
        report["reviewedCaseReconciliation"] = reconcile_reviewed_cases(report, review)
        report["reviewedCaseReconciliation"]["reviewedMapSha256"] = hashlib.sha256(review_bytes).hexdigest()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
        f.write("\n")
    print(json.dumps({"output": str(args.output), "originalResultCount": report["originalResultCount"],
                      "evidenceAdmitted": False}))

if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, ET.ParseError) as exc:
        print("BLOCKED: " + str(exc), file=sys.stderr)
        sys.exit(3)
