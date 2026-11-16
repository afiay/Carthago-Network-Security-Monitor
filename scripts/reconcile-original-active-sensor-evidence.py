#!/usr/bin/env python3
"""Read-only source/report/TRX reconciliation of historical active-sensor suite.

No network access, builds, tests, captures, changes to originals or evidence admission.
Only runner-declared historical synthetic qualification may be linked.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
import uuid
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

NS = "{http://microsoft.com/schemas/VisualStudio/TeamTest/2010}"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
BRANCH = "feature/carthago-reliability-hardening"
EXPECTED = {
    "TcpExposureSensorTests": 17, "DnsIntegritySensorTests": 33,
    "TlsInspectionSensorTests": 22, "HttpHealthSensorTests": 38,
    "GatewayIntegritySensorTests": 23, "SnmpInfrastructureSensorTests": 41,
    "ActiveEvidenceStoreTests": 21, "ActiveSensorManagerTests": 16,
    "ActiveChangeDetectorTests": 15, "ActiveFindingQualificationTests": 15,
    "ActiveSensorPipelineLabTests": 5, "ActiveSensorLifecycleStressTests": 7,
    "ActiveIncidentContextTests": 8, "ActiveSensorProfileStoreTests": 10,
    "ActiveSchedulerOwnershipTests": 5, "ActiveExecutionGrantTests": 9,
    "ActiveSensorWorkerTests": 8, "SnmpCredentialVaultTests": 7,
    "ScheduledSnmpAuthorizationTests": 8, "ActiveNpcapCoordinationTests": 8,
    "ScheduledGatewayTests": 7, "ActiveServiceLifecycleTests": 8,
    "ActiveServiceProvisioningTests": 5, "ActiveServiceHealthTests": 5,
    "ActiveServiceNegativeStartupTests": 6,
    "ActiveAuthorizationSurveillanceTests": 5,
    "ActiveServiceRejectionTests": 6, "ActiveFindingReleaseMatrixTests": 34,
}
TOTAL = 392

def file_sha256(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            sha.update(chunk)
    return sha.hexdigest()

def load_json(path: Path) -> dict:
    raw = path.read_bytes()
    text = raw.decode("utf-16") if raw[:2] in (bytes((255, 254)), bytes((254, 255))) else raw.decode("utf-8-sig")
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("JSON object required")
    return data

def timestamp(s: object) -> dt.datetime | None:
    if not isinstance(s, str):
        return None
    try:
        date = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
        return date.astimezone(dt.timezone.utc) if date.tzinfo else None
    except ValueError:
        return None

def recovered_copy(bundle: Path, index: dict, rel: str) -> tuple[Path | None, str]:
    row = index.get(rel.lower())
    if row is None:
        return None, "missing-original"
    relpath = row["relativeCopy"].replace("\\", "/")
    parts = relpath.split("/")
    if parts[0] != "originals" or any(p in ("", ".", "..") for p in parts):
        return None, "invalid-path"
    path = bundle
    for component in parts:
        path = path / component
        if path.is_symlink():
            return None, "symlink-rejected"
    if not path.resolve().is_relative_to(bundle.resolve()) or not path.is_file():
        return None, "invalid-original"
    if type(row.get("bytes")) is not int or path.stat().st_size != row["bytes"]:
        return None, "length-mismatch"
    if file_sha256(path) != str(row.get("sha256", "")).lower():
        return None, "sha256-mismatch"
    return path, "sha256-verified"

def trx_cases(path: Path, max_trx_bytes: int) -> dict:
    if not 1 <= path.stat().st_size <= max_trx_bytes:
        return {"status": "rejected-size"}
    data = path.read_bytes()
    if b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        return {"status": "rejected-unsafe-xml"}
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        return {"status": "invalid-xml"}
    if root.tag != NS + "TestRun":
        return {"status": "invalid-root"}
    defs = root.findall(NS + "TestDefinitions/" + NS + "UnitTest")
    res = root.findall(NS + "Results/" + NS + "UnitTestResult")
    ctr = root.find(NS + "ResultSummary/" + NS + "Counters")
    summary = root.find(NS + "ResultSummary")
    times = root.find(NS + "Times")
    if len(defs) != TOTAL or len(res) != TOTAL or ctr is None or summary is None or times is None:
        return {"status": "missing-results-or-definitions"}
    try:
        uuid.UUID(root.attrib["id"])
        counts = {k: int(ctr.attrib[k]) for k in ("total", "executed", "passed", "failed")}
        if any(not re.fullmatch(r"\d+", ctr.attrib[k]) for k in counts):
            return {"status": "invalid-counters"}
    except (KeyError, ValueError):
        return {"status": "invalid-counters"}
    if counts != {"total": TOTAL, "executed": TOTAL, "passed": TOTAL, "failed": 0}:
        return {"status": "failed-or-incomplete", "counters": counts}
    by_id = {}
    for definition in defs:
        method = definition.find(NS + "TestMethod")
        test_id = definition.get("id")
        if method is None or not test_id or test_id in by_id:
            return {"status": "ambiguous-definitions"}
        by_id[test_id] = method.get("className", "").split(",")[0].strip()
    seen_execution, seen_result = set(), set()
    cases = Counter()
    for result in res:
        test_id = result.get("testId")
        eid = result.get("executionId")
        if not test_id or not eid or test_id not in by_id or test_id in seen_result or eid in seen_execution:
            return {"status": "ambiguous-results"}
        seen_result.add(test_id)
        seen_execution.add(eid)
        if result.get("outcome") != "Passed":
            return {"status": "failed-or-skipped-result"}
        cls = by_id[test_id]
        if not cls.startswith("Carthago.Tests."):
            return {"status": "unexpected-test-class"}
        name = cls.removeprefix("Carthago.Tests.")
        if name not in EXPECTED:
            return {"status": "unknown-test-class"}
        cases[name] += 1
    if cases != Counter(EXPECTED):
        return {"status": "unexpected-suite-coverage", "actual": dict(cases)}
    start, finish = timestamp(times.get("start")), timestamp(times.get("finish"))
    if not start or not finish or start > finish:
        return {"status": "invalid-trx-times"}
    return {
        "status": "passed",
        "runId": root.attrib["id"],
        "startUtc": start.isoformat(),
        "finishUtc": finish.isoformat(),
        "counters": counts,
        "verifiedSuites": len(cases),
    }

def audit(bundle: Path, max_trx_bytes: int, prior: dict | None) -> dict:
    manifest = load_json(bundle / "recovery-manifest.json")
    rows = manifest.get("artifacts")
    if manifest.get("purpose") != "historical-Windows-artifact-byte-recovery" or not isinstance(rows, list):
        raise ValueError("Invalid recovery manifest")
    if len(rows) != manifest.get("artifactCount"):
        raise ValueError("Recovery artifact count mismatch")
    index = {}
    for row in rows:
        key = row["relativeCopy"].replace("\\", "/").lower()
        if key in index:
            raise ValueError("Duplicate original path")
        index[key] = row
    if prior is not None:
        if prior.get("purpose") != "read-only-original-source-and-synthetic-replay-reconciliation":
            raise ValueError("Unexpected previous evidence report")
        found = [x for x in prior.get("trxRuns", []) if x.get("relativeCopy", "").lower().endswith("/active-sensors.trx")]
        if len(found) != 1:
            raise ValueError("Prior active-sensors TRX inventory missing/ambiguous")
        prior_hash = str(found[0]["trxSha256"]).lower()
    else:
        prior_hash = None

    audits = []
    for rel, row in sorted(index.items()):
        if not rel.endswith("/active-sensors/") and not (rel.endswith("/qualification.json") and "/active-sensors/" in rel):
            continue
        if not rel.endswith("/qualification.json"):
            continue
        root = rel.rsplit("/", 1)[0]
        entry = {"reportRelativeCopy": row["relativeCopy"], "runnerDeclaredSourceSha": None,
                 "sourceShaRunnerLinkedToTrx": None, "status": "blocked", "checks": {},
                 "testsExecutedByAudit": 0, "evidenceAdmitted": False}
        audits.append(entry)
        report_path, report_status = recovered_copy(bundle, index, rel)
        trx_rel = root + "/active-sensors.trx"
        trx_path, trx_status = recovered_copy(bundle, index, trx_rel)
        entry["checks"]["reportCopy"] = report_status
        entry["checks"]["originalTrxCopy"] = trx_status
        if report_path is None or trx_path is None:
            continue
        try:
            report = load_json(report_path)
        except (ValueError, UnicodeError):
            entry["status"] = "invalid-original-report"
            continue
        sha = str(report.get("sourceSha", "")).lower()
        entry["runnerDeclaredSourceSha"] = sha if SHA40.fullmatch(sha) else None
        trx_hash = str(index[trx_rel]["sha256"]).lower()
        entry["reportSha256"] = str(row.get("sha256", "")).lower()
        entry["trxSha256"] = trx_hash
        matrix = report.get("suites")
        if not isinstance(matrix, list):
            entry["status"] = "invalid-suite-report-shape"
            continue
        suites = {}
        for s in matrix:
            if not isinstance(s, dict) or not isinstance(s.get("name"), str) or s["name"] in suites:
                entry["status"] = "ambiguous-reported-suite"
                break
            suites[s["name"]] = s
        if entry["status"] == "ambiguous-reported-suite":
            continue
        if len(suites) != len(EXPECTED):
            entry["status"] = "incomplete-reported-suites"
            continue
        matches = all(
            name in suites and all(type(suites[name].get(key)) is int and suites[name][key] == value
                                   for key, value in (("expected", count), ("total", count), ("passed", count),
                                                      ("failedOrSkipped", 0)))
            for name, count in EXPECTED.items()
        )
        stage_zero = all(type(report.get(k)) is int and report[k] == 0 for k in (
            "buildExitCode", "monitorBuildExitCode", "monitorHelpExitCode",
            "processQualificationBuildExitCode", "processQualificationExitCode",
            "liveLabContractExitCode", "testExitCode"))
        flags = all(report.get(k) is True for k in (
            "releaseContractPassed", "deploymentContractPassed", "serviceLifecycleContractPassed",
            "serviceNegativeContractPassed"))
        valid_report = (report.get("schemaVersion") == 1 and entry["runnerDeclaredSourceSha"] is not None and
                        report.get("branch") == BRANCH and report.get("status") == "Passed" and
                        report.get("blocker") is None and report.get("liveNetworkValidated") is False and
                        all(type(report.get(k)) is int and report[k] == v for k, v in (
                            ("expectedTotal", TOTAL), ("total", TOTAL), ("passed", TOTAL),
                            ("failedOrSkipped", 0), ("monitorInvalidCommandExitCode", 2))) and
                        matches and stage_zero and flags and
                        str(report.get("trxSha256", "")).lower() == trx_hash and
                        (prior_hash is None or trx_hash == prior_hash))
        trx = trx_cases(trx_path, max_trx_bytes)
        entry["originalTrx"] = trx
        start, finish = timestamp(report.get("startedUtc")), timestamp(report.get("finishedUtc"))
        ts, tf = timestamp(trx.get("startUtc")), timestamp(trx.get("finishUtc"))
        inside = bool(start and finish and ts and tf and start <= finish and
                      start - dt.timedelta(minutes=2) <= ts <= tf <= finish + dt.timedelta(minutes=2))
        entry["checks"].update({"originalReportContract": valid_report,
                                 "sourceReportHashBinding": str(report.get("trxSha256", "")).lower() == trx_hash,
                                 "suiteMatrixMatchesHistoricalSource": matches,
                                 "reportRunTimeEnclosesTrx": inside,
                                 "trxAll392And28SuitesPassed": trx.get("status") == "passed"})
        if valid_report and inside and trx.get("status") == "passed":
            entry["sourceShaRunnerLinkedToTrx"] = sha
            entry["status"] = "historical-synthetic-active-source-run-linked"
    return {
        "schemaVersion": 1,
        "purpose": "read-only-original-active-sensor-evidence-reconciliation",
        "summary": {
            "activeSensorReportsInspected": len(audits),
            "historicalActiveTrxRunnerLinked": sum(bool(x["sourceShaRunnerLinkedToTrx"]) for x in audits),
            "newFieldQualifications": 0,
            "newEvidenceAdmissions": 0,
            "testsExecutedByAudit": 0,
            "capturesExecutedByAudit": 0
        },
        "warnings": [
            "Runner-declared source SHA is not an independent cryptographic attestation.",
            "Source/run linkage is for historical synthetic and loopback active sensor tests only.",
            "Does not establish current HEAD, physical-network, unattended-service or field accuracy qualification.",
            "No test execution, artifact edits, evidence registry promotions, or captures."
        ],
        "reports": audits
    }

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--bundle", required=True, type=Path)
    p.add_argument("--previous", type=Path)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--max-trx-bytes", type=int, default=33554432)
    a = p.parse_args()
    if not 1 <= a.max_trx_bytes <= 67108864:
        p.error("Invalid TRX size ceiling")
    bundle = a.bundle.resolve()
    output = a.output.resolve()
    if output.exists() or output.is_relative_to((bundle / "originals").resolve()):
        p.error("Output exists or would overwrite an original")
    prior = load_json(a.previous) if a.previous else None
    result = audit(bundle, a.max_trx_bytes, prior)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    print(json.dumps(result["summary"], indent=2))
    return 0

if __name__ == "__main__":
    sys.exit(main())
