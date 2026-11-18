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
                  "failed": sum(r["outcome"] == "Failed" for r in rows),
                  "error": sum(r["outcome"] == "Error" for r in rows),
                  "timeout": sum(r["outcome"] == "Timeout" for r in rows),
                  "aborted": sum(r["outcome"] == "Aborted" for r in rows),
                  "inconclusive": sum(r["outcome"] == "Inconclusive" for r in rows),
                  "notExecuted": sum(r["outcome"] == "NotExecuted" for r in rows),
                  "pending": sum(r["outcome"] == "Pending" for r in rows)}
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
    digest = review.get("originalTrxSha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("Missing or malformed original TRX digest")
    if digest != report["originalTrxSha256"]:
        raise ValueError("Original TRX digest mismatch")
    if set(review) != {"schemaVersion", "originalTrxSha256", "cases"}:
        raise ValueError("Unexpected reviewed-map claims")
    cases = review.get("cases")
    if not isinstance(cases, list) or len(cases) > MAX_RESULTS:
        raise ValueError("Invalid review cases")
    original = {(x["testId"], x["exactTestName"]): x for x in report["results"]}
    seen = set()
    joined = []
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("Invalid review entry")
        if set(case) != {"testId", "exactTestName", "exactRuleId", "casePolarity"}:
            raise ValueError("Unexpected reviewed-case claims")
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
                       "executionClassification": ("passed" if original[key]["outcome"] == "Passed" else
                                                   "failed" if original[key]["outcome"] in {"Failed", "Error", "Timeout", "Aborted"} else
                                                   "unexecuted-or-inconclusive"),
                       "qualificationStatus": "not-admitted"})
    return {"originalTrxSha256": report["originalTrxSha256"],
            "reviewedCases": joined, "unreviewedCount": len(original)-len(joined),
            "sourceShaAttested": False, "evidenceAdmitted": False}

def reconcile_inventory(joined: dict, inventory: dict) -> dict:
    """Cross-check reviewed cases against the bounded exact-ID audit, not the registry."""
    if not isinstance(inventory, dict) or inventory.get("schemaVersion") != 1:
        raise ValueError("Unsupported exact-ID inventory schema")
    source_sha = inventory.get("sourceSha")
    if not isinstance(source_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise ValueError("Missing or invalid inventory source SHA")
    records = inventory.get("records")
    if not isinstance(records, list) or not 0 < len(records) <= 1000:
        raise ValueError("Invalid exact-ID inventory records")
    known = {}
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("Invalid exact-ID inventory entry")
        rid, cls = record.get("ruleId"), record.get("registeredClass")
        if not isinstance(rid, str) or not re.fullmatch(r"R[0-9]{3,4}", rid):
            raise ValueError("Invalid inventory rule ID")
        if not isinstance(cls, str) or not cls.startswith(rid + "_"):
            raise ValueError("Invalid registered class in inventory")
        if rid in known:
            raise ValueError("Duplicate exact-ID inventory entry")
        known[rid] = cls
    for case in joined["reviewedCases"]:
        if case["exactRuleId"] not in known:
            raise ValueError("Reviewed TRX rule not present in exact-ID inventory")
    # Candidate counts are diagnostic only: reviewed polarity is not independent proof.
    counts = {}
    for case in joined["reviewedCases"]:
        rid = case["exactRuleId"]
        bucket = counts.setdefault(rid, {"positive-detector": {"passed": 0, "failed": 0, "unexecuted-or-inconclusive": 0},
                                         "negative-detector": {"passed": 0, "failed": 0, "unexecuted-or-inconclusive": 0}})
        bucket[case["casePolarity"]][case["executionClassification"]] += 1
    counts = dict(sorted(counts.items(), key=lambda item: int(item[0][1:])))
    # A reviewed failing or unexecuted test is not equivalent to a passing candidate.
    # These are diagnostic outcomes only, not independent detector qualification.
    def candidate_state(bucket: dict | None, polarity: str) -> str:
        if bucket is None or sum(bucket[polarity].values()) == 0:
            return "missing-reviewed-case"
        outcomes = bucket[polarity]
        if outcomes["failed"]:
            return "reviewed-failed"
        if outcomes["unexecuted-or-inconclusive"]:
            return "reviewed-unexecuted-or-inconclusive"
        return "reviewed-passed-candidate-only"

    gaps = {}
    for rid in sorted(known, key=lambda value: int(value[1:])):
        bucket = counts.get(rid)
        gaps[rid] = {
            "positive": candidate_state(bucket, "positive-detector"),
            "negative": candidate_state(bucket, "negative-detector"),
        }
    return {"inventorySourceSha": inventory.get("sourceSha"),
            "inventoryRecordCount": len(known),
            "matchedReviewedCases": len(joined["reviewedCases"]),
            "reviewedOutcomeCountsByExactId": counts,
            "reviewedCaseGapsByExactId": gaps,
            "evidenceAdmitted": False, "independentValidation": "missing"}

def reconcile_execution_manifest(report: dict, manifest: dict) -> dict:
    """Bind declared source to original TRX bytes without attesting checkout."""
    if not isinstance(manifest, dict) or manifest.get("schemaVersion") != 1:
        raise ValueError("Unsupported execution manifest")
    digest, sha = manifest.get("originalTrxSha256"), manifest.get("executionSourceSha")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("Invalid manifest TRX digest")
    if digest != report["originalTrxSha256"]:
        raise ValueError("Execution manifest TRX digest mismatch")
    if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("Invalid declared execution SHA")
    if set(manifest) != {"schemaVersion", "originalTrxSha256", "executionSourceSha"}:
        raise ValueError("Unexpected execution manifest claims")
    return {"executionSourceShaDeclared": sha, "sourceShaAttested": False,
            "evidenceAdmitted": False, "provenanceStatus": "declared-unverified"}

def reconcile_source_provenance(inventory: dict, declaration: dict | None) -> dict:
    """Compare historical inventory and declared TRX checkout; never attest either."""
    historical = inventory.get("sourceSha")
    if not isinstance(historical, str) or not re.fullmatch(r"[0-9a-f]{40}", historical):
        raise ValueError("Invalid historical inventory source SHA")
    if declaration is None:
        return {"inventorySourceSha": historical, "executionSourceShaDeclared": None,
                "relationship": "execution-source-undeclared", "sourceShaAttested": False,
                "evidenceAdmitted": False}
    executed = declaration.get("executionSourceShaDeclared")
    if not isinstance(executed, str) or not re.fullmatch(r"[0-9a-f]{40}", executed):
        raise ValueError("Invalid declared execution source SHA")
    return {"inventorySourceSha": historical, "executionSourceShaDeclared": executed,
            "relationship": ("same-declared-source" if executed == historical
                             else "historical-source-differs-from-declared-execution"),
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
        manifest = {"schemaVersion": 1, "originalTrxSha256": r["originalTrxSha256"],
                    "executionSourceSha": "a" * 40}
        declared = reconcile_execution_manifest(r, manifest)
        assert not declared["sourceShaAttested"] and not declared["evidenceAdmitted"]
        for invalid in ({**manifest, "executionSourceSha": None},
                        {**manifest, "executionSourceSha": "A" * 40},
                        {**manifest, "originalTrxSha256": "0" * 64},
                        {**manifest, "extra": "verified"},
                        {**manifest, "schemaVersion": 2}):
            try:
                reconcile_execution_manifest(r, invalid)
            except ValueError:
                pass
            else:
                raise AssertionError("Invalid execution manifest accepted")
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
        assert joined["reviewedCases"][0]["executionClassification"] == "passed"
        for outcome, expected in (("Failed", "failed"), ("Error", "failed"), ("Timeout", "failed"),
                                  ("Aborted", "failed"), ("Inconclusive", "unexecuted-or-inconclusive"),
                                  ("NotExecuted", "unexecuted-or-inconclusive")):
            altered = {**r, "results": [{**r["results"][0], "outcome": outcome}, r["results"][1]]}
            case = reconcile_reviewed_cases(altered, review)["reviewedCases"][0]
            assert case["executionClassification"] == expected
            assert case["qualificationStatus"] == "not-admitted"
        assert not joined["evidenceAdmitted"]
        inventory = {"schemaVersion": 1, "sourceSha": "a" * 40,
                     "records": [{"ruleId": "R102", "registeredClass": "R102_TestRule"}]}
        missing_source = reconcile_source_provenance(inventory, None)
        assert missing_source["relationship"] == "execution-source-undeclared"
        assert missing_source["executionSourceShaDeclared"] is None
        same_source = reconcile_source_provenance(inventory, declared)
        assert same_source["relationship"] == "same-declared-source"
        different_source = reconcile_source_provenance(
            inventory, {**declared, "executionSourceShaDeclared": "b" * 40})
        assert different_source["relationship"] == "historical-source-differs-from-declared-execution"
        assert all(not item["sourceShaAttested"] and not item["evidenceAdmitted"]
                   for item in (missing_source, same_source, different_source))
        for invalid_source in ({"sourceSha": "invalid"}, {"sourceSha": None}):
            try:
                reconcile_source_provenance(invalid_source, declared)
            except ValueError:
                pass
            else:
                raise AssertionError("Invalid historical source SHA accepted")
        try:
            reconcile_source_provenance(inventory, {"executionSourceShaDeclared": "INVALID"})
        except ValueError:
            pass
        else:
            raise AssertionError("Invalid execution source declaration accepted")
        matched = reconcile_inventory(joined, inventory)
        assert matched["matchedReviewedCases"] == 1 and not matched["evidenceAdmitted"]
        assert matched["reviewedOutcomeCountsByExactId"]["R102"]["positive-detector"]["passed"] == 1
        assert matched["reviewedOutcomeCountsByExactId"]["R102"]["negative-detector"]["passed"] == 0
        assert matched["independentValidation"] == "missing"
        assert matched["reviewedCaseGapsByExactId"]["R102"] == {
            "positive": "reviewed-passed-candidate-only", "negative": "missing-reviewed-case"}
        expanded_inventory = {**inventory, "records": inventory["records"] + [
            {"ruleId": "R163", "registeredClass": "R163_TestRule"}]}
        expanded = reconcile_inventory(joined, expanded_inventory)
        assert expanded["reviewedCaseGapsByExactId"]["R163"] == {
            "positive": "missing-reviewed-case", "negative": "missing-reviewed-case"}
        mixed = {**joined, "reviewedCases": joined["reviewedCases"] + [
            {**joined["reviewedCases"][0], "casePolarity": "negative-detector",
             "executionClassification": "failed"}]}
        mixed_counts = reconcile_inventory(mixed, inventory)["reviewedOutcomeCountsByExactId"]["R102"]
        assert mixed_counts["positive-detector"]["passed"] == 1
        assert mixed_counts["negative-detector"]["failed"] == 1
        assert mixed_counts["negative-detector"]["passed"] == 0
        mixed_gaps = reconcile_inventory(mixed, inventory)["reviewedCaseGapsByExactId"]["R102"]
        assert mixed_gaps["negative"] == "reviewed-failed"
        inconclusive = {**joined, "reviewedCases": [
            {**joined["reviewedCases"][0], "executionClassification": "unexecuted-or-inconclusive"}]}
        assert reconcile_inventory(inconclusive, inventory)["reviewedCaseGapsByExactId"]["R102"]["positive"] == "reviewed-unexecuted-or-inconclusive"
        # Mixed passing/failing evidence must not hide a failing reviewed case.
        mixed_positive = {**joined, "reviewedCases": joined["reviewedCases"] + [
            {**joined["reviewedCases"][0], "executionClassification": "failed"}]}
        assert reconcile_inventory(mixed_positive, inventory)["reviewedCaseGapsByExactId"]["R102"]["positive"] == "reviewed-failed"


        for bad_inventory in (
            {**inventory, "records": inventory["records"] * 2},
            {**inventory, "records": []},
            {**inventory, "records": [{"ruleId": "R163", "registeredClass": "R163_TestRule"}]},
            {**inventory, "records": [{"ruleId": "R102", "registeredClass": "R163_TestRule"}]},
            {**inventory, "schemaVersion": 2},
            {**inventory, "sourceSha": None},
            {**inventory, "sourceSha": "unknown"},
            {**inventory, "sourceSha": "A" * 40},
        ):
            try:
                reconcile_inventory(joined, bad_inventory)
            except ValueError:
                pass
            else:
                raise AssertionError("Invalid inventory reconciliation accepted")
        for bad in (
            {**review, "originalTrxSha256": "0" * 64},
            {**review, "originalTrxSha256": None},
            {**review, "originalTrxSha256": "not-a-digest"},
            {**review, "originalTrxSha256": "A" * 64},
            {**review, "cases": review["cases"] * 2},
            {**review, "independentlyVerified": True},
            {**review, "cases": [{**review["cases"][0], "qualificationStatus": "admitted"}]},
            {**review, "cases": [{key: value for key, value in review["cases"][0].items() if key != "casePolarity"}]},
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
                    xml.replace('<ResultSummary outcome="Completed"/>',
                                '<ResultSummary outcome="Completed"><Counters total="2" passed="1" failed="1" error="1"/></ResultSummary>'),
                    xml.replace('<ResultSummary outcome="Completed"/>',
                                '<ResultSummary outcome="Completed"><Counters total="2" passed="1" failed="1" notExecuted="1"/></ResultSummary>'),
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
    parser.add_argument("--inventory", type=Path)
    parser.add_argument("--execution-manifest", type=Path)
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if args.trx is None or args.output is None:
        parser.error("--trx and --output required")
    if args.output.exists() or args.output.resolve() == args.trx.resolve():
        parser.error("Refusing overwrite")
    if args.inventory is not None and args.reviewed_map is None:
        parser.error("--inventory requires --reviewed-map")
    report = inspect(args.trx)
    if args.execution_manifest is not None:
        if not args.execution_manifest.is_file() or not 0 < args.execution_manifest.stat().st_size <= MAX_BYTES:
            raise ValueError("Missing or oversized execution manifest")
        manifest_bytes = args.execution_manifest.read_bytes()
        report["executionSourceDeclaration"] = reconcile_execution_manifest(report, parse_review_json(manifest_bytes))
        report["executionSourceDeclaration"]["manifestSha256"] = hashlib.sha256(manifest_bytes).hexdigest()
    if args.reviewed_map is not None:
        if not args.reviewed_map.is_file() or not 0 < args.reviewed_map.stat().st_size <= MAX_BYTES:
            raise ValueError("Missing or oversized review map")
        review_bytes = args.reviewed_map.read_bytes()
        review = parse_review_json(review_bytes)
        report["reviewedCaseReconciliation"] = reconcile_reviewed_cases(report, review)
        report["reviewedCaseReconciliation"]["reviewedMapSha256"] = hashlib.sha256(review_bytes).hexdigest()
        if args.inventory is not None:
            if not args.inventory.is_file() or not 0 < args.inventory.stat().st_size <= MAX_BYTES:
                raise ValueError("Missing or oversized exact-ID inventory")
            inventory_bytes = args.inventory.read_bytes()
            inventory = parse_review_json(inventory_bytes)
            report["exactIdInventoryReconciliation"] = reconcile_inventory(
                report["reviewedCaseReconciliation"], inventory)
            report["exactIdInventoryReconciliation"]["inventorySha256"] = hashlib.sha256(inventory_bytes).hexdigest()
            report["sourceProvenanceComparison"] = reconcile_source_provenance(
                inventory, report.get("executionSourceDeclaration"))
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
