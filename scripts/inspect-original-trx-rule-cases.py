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
    if len(nodes) > MAX_RESULTS or any(node.tag != NS + "UnitTestResult" for node in nodes):
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
    if len({(r["exactTestName"], r["testId"]) for r in rows}) != len(rows):
        raise ValueError("Ambiguous duplicate test identities")
    return {"schemaVersion": 1, "purpose": "original-trx-candidate-only",
            "originalTrxSha256": hashlib.sha256(data).hexdigest(),
            "originalResultCount": len(rows), "testsExecutedByInspector": 0,
            "evidenceAdmitted": False, "sourceShaAttested": False,
            "warning": "Rule IDs parsed from names are hints, not detector polarity or execution-source proof.",
            "results": rows}

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
        assert all(x["casePolarity"] == "unreviewed" and x["sourceSha"] is None for x in r["results"])
        for bad in (xml.replace('outcome="Passed"', 'outcome="Unknown"'),
                    '<!DOCTYPE TestRun>' + xml,
                    xml.replace('testId="b"', 'testId="a"').replace('Benign.Control', 'R102.Positive')):
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
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if args.trx is None or args.output is None:
        parser.error("--trx and --output required")
    if args.output.exists() or args.output.resolve() == args.trx.resolve():
        parser.error("Refusing overwrite")
    report = inspect(args.trx)
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
