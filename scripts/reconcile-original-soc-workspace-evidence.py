#!/usr/bin/env python3
"""Read-only historical SOC workspace source-file/TRX/log correlation.

Never upgrades a pre-run source-sha.txt into post-run runner attestation.
Reads only byte-recovered originals, original recovery manifest and v4 audit.
No network operations, builds, tests, capture, registry changes or admissions.
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
from pathlib import Path

NS = "{http://microsoft.com/schemas/VisualStudio/TeamTest/2010}"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
GROUPS = ("NetworkInvestigation", "IncidentTimeline", "IncidentDetectionLinkVm")
FILES = ("source-sha.txt", "sdk-version.txt", "restore.log",
         "build-release.log", "soc-tests.log", "soc-workspace-tests.trx")

def sha256(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1048576), b""):
            result.update(chunk)
    return result.hexdigest()

def original_text(path: Path) -> str:
    raw = path.read_bytes()
    return raw.decode("utf-16") if raw[:2] in (bytes((255, 254)), bytes((254, 255))) else raw.decode("utf-8-sig")

def read_json(path: Path) -> dict:
    obj = json.loads(original_text(path))
    if not isinstance(obj, dict):
        raise ValueError("JSON object required")
    return obj

def parse_utc(value: object) -> dt.datetime | None:
    if not isinstance(value, str):
        return None
    try:
        when = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        return when.astimezone(dt.timezone.utc) if when.tzinfo is not None else None
    except ValueError:
        return None

def safe_original_path(bundle: Path, rel: str) -> Path:
    if not isinstance(rel, str):
        raise ValueError("Invalid relative path")
    rel = rel.replace("\\", "/")
    parts = rel.split("/")
    if len(parts) < 3 or parts[0] != "originals" or any(x in ("", ".", "..") for x in parts):
        raise ValueError("Unsafe original path")
    path = bundle
    for component in parts:
        path = path / component
        if path.is_symlink():
            raise ValueError("Original symlink rejected")
    if not path.resolve().is_relative_to(bundle.resolve()):
        raise ValueError("Original path outside recovery root")
    return path

def get_original(bundle: Path, index: dict, rel: str) -> tuple[Path | None, str]:
    entry = index.get(rel.lower())
    if not entry:
        return None, "missing-original-manifest-record"
    path = safe_original_path(bundle, entry["relativeCopy"])
    if not path.is_file() or type(entry.get("bytes")) is not int:
        return None, "missing-original-copy"
    if path.stat().st_size != entry["bytes"]:
        return None, "original-size-mismatch"
    if sha256(path) != str(entry.get("sha256", "")).lower():
        return None, "original-sha256-mismatch"
    return path, "original-sha256-verified"

def inspect_trx(path: Path, max_bytes: int) -> dict:
    if not 1 <= path.stat().st_size <= max_bytes:
        return {"status": "invalid-size"}
    raw = path.read_bytes()
    if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        return {"status": "unsafe-xml"}
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return {"status": "invalid-xml"}
    if root.tag != NS + "TestRun":
        return {"status": "invalid-schema"}
    defs = root.findall(NS + "TestDefinitions/" + NS + "UnitTest")
    res = root.findall(NS + "Results/" + NS + "UnitTestResult")
    ctr = root.find(NS + "ResultSummary/" + NS + "Counters")
    summ = root.find(NS + "ResultSummary")
    times = root.find(NS + "Times")
    if ctr is None or summ is None or times is None:
        return {"status": "missing-xml-metadata"}
    try:
        uuid.UUID(root.attrib["id"])
        counts = {k: int(ctr.attrib[k]) for k in ("total", "passed", "failed", "executed")}
    except (KeyError, ValueError):
        return {"status": "invalid-trx-metadata"}
    if len(res) != 69 or len(defs) != 69 or counts != {
        "total": 69, "passed": 69, "failed": 0, "executed": 69
    } or summ.get("outcome") not in ("Completed", "Passed"):
        return {"status": "not-all-69-passed", "counters": counts}
    owners = {}
    for unit in defs:
        method = unit.find(NS + "TestMethod")
        key = unit.get("id")
        if not key or key in owners or method is None:
            return {"status": "ambiguous-test-definitions"}
        owners[key] = method.get("className", "").split(",")[0]
    execution_ids = set()
    test_ids = set()
    group_counts = {name: 0 for name in GROUPS}
    for result in res:
        tid, eid = result.get("testId"), result.get("executionId")
        if not tid or not eid or tid in test_ids or eid in execution_ids or tid not in owners:
            return {"status": "ambiguous-test-results"}
        if result.get("outcome") != "Passed":
            return {"status": "nonpass-result"}
        test_ids.add(tid)
        execution_ids.add(eid)
        for group in GROUPS:
            if group in owners[tid]:
                group_counts[group] += 1
    start, finish = parse_utc(times.get("start")), parse_utc(times.get("finish"))
    if any(value == 0 for value in group_counts.values()) or not start or not finish or start > finish:
        return {"status": "missing-groups-or-times", "groups": group_counts}
    return {"status": "passed-all-69", "trxRunId": root.attrib["id"],
            "startUtc": start.isoformat(), "finishUtc": finish.isoformat(),
            "groups": group_counts, "counters": counts}

def audit(bundle: Path, previous: dict, max_bytes: int) -> dict:
    if previous.get("purpose") != "read-only-original-source-and-synthetic-replay-reconciliation":
        raise ValueError("Previous audit is not the source/replay reconciliation")
    manifest = read_json(bundle / "recovery-manifest.json")
    entries = manifest.get("artifacts")
    if manifest.get("purpose") != "historical-Windows-artifact-byte-recovery" or not isinstance(entries, list) or len(entries) != manifest.get("artifactCount"):
        raise ValueError("Invalid original recovery manifest")
    index = {}
    for entry in entries:
        key = entry["relativeCopy"].replace("\\", "/").lower()
        if key in index:
            raise ValueError("Duplicate original manifest entry")
        index[key] = entry
    source_refs = [x for x in previous.get("sourceShaTextArtifacts", [])
                   if x.get("path", "").lower().endswith("/source-sha.txt")
                   and "/soc-workspace-" in x.get("path", "").lower()]
    if len(source_refs) != 1:
        raise ValueError("Previous audit must have exactly one SOC source-sha record")
    prefix = source_refs[0]["path"].replace("\\", "/").rsplit("/", 1)[0]
    prior_runs = [x for x in previous.get("trxRuns", [])
                  if x.get("relativeCopy", "").lower() == (prefix + "/soc-workspace-tests.trx").lower()]
    if len(prior_runs) != 1:
        raise ValueError("Previous audit must have exactly one SOC TRX record")
    files = {}
    paths = {}
    for name in FILES:
        rel = prefix + "/" + name
        path, state = get_original(bundle, index, rel)
        files[name] = {
            "originalRelativeCopy": rel, "copyVerification": state,
            "sha256": index[rel.lower()]["sha256"] if rel.lower() in index else None,
            "recordedOriginalLastWriteUtc": index.get(rel.lower(), {}).get("sourceLastWriteUtc"),
        }
        paths[name] = path
    checks = {
        "allSixOriginalFilesHashVerified": all(paths.values()),
        "sourceContentsEqualPriorAudit": False,
        "originalTrxHashEqualsPriorAudit": False,
        "69TrxAndThreeSocGroupCoveragePassed": False,
        "sourceFilePredatesTrxStart": False,
        "stageLogsReadable": False,
        "buildLogReportsSuccess": False,
        "testLogReportsSuccess": False,
        "savedPostRunSourceRecheckObserved": False,
    }
    sha = None
    trx = {"status": "not-inspected"}
    if paths["source-sha.txt"]:
        try:
            candidate = original_text(paths["source-sha.txt"]).strip().lower()
            if SHA40.fullmatch(candidate):
                sha = candidate
                checks["sourceContentsEqualPriorAudit"] = (
                    sha == source_refs[0].get("sourceSha40") and
                    source_refs[0].get("sourceIdentityLevel") == "original-source-file-only-unbound")
        except UnicodeError:
            pass
    if paths["soc-workspace-tests.trx"]:
        trx = inspect_trx(paths["soc-workspace-tests.trx"], max_bytes)
        checks["originalTrxHashEqualsPriorAudit"] = (
            files["soc-workspace-tests.trx"]["sha256"].lower() ==
            str(prior_runs[0].get("trxSha256", "")).lower()
        )
        checks["69TrxAndThreeSocGroupCoveragePassed"] = trx.get("status") == "passed-all-69"
    src_mtime = parse_utc(files["source-sha.txt"]["recordedOriginalLastWriteUtc"])
    test_start = parse_utc(trx.get("startUtc"))
    if src_mtime and test_start:
        checks["sourceFilePredatesTrxStart"] = src_mtime <= test_start
    if all(paths[n] for n in ("restore.log", "build-release.log", "soc-tests.log")):
        try:
            restore = original_text(paths["restore.log"])
            build = original_text(paths["build-release.log"])
            tests = original_text(paths["soc-tests.log"])
            checks["stageLogsReadable"] = bool(restore.strip() and build.strip() and tests.strip())
            checks["buildLogReportsSuccess"] = bool(re.search(r"(?im)^\s*Build succeeded\.\s*$", build))
            checks["testLogReportsSuccess"] = bool(
                re.search(r"(?i)\b(?:passed|succeeded)\b", tests) and
                re.search(r"(?<!\d)69(?!\d)", tests))
            # The original verifier's final checkout assertion is printed
            # to the console, not recorded in its per-dotnet-stage logs.
            # Never infer it from an earlier source-sha file or a TRX PASS.
        except UnicodeError:
            pass
    correlated = bool(sha and all(checks[key] for key in (
        "allSixOriginalFilesHashVerified", "sourceContentsEqualPriorAudit",
        "originalTrxHashEqualsPriorAudit", "69TrxAndThreeSocGroupCoveragePassed",
        "sourceFilePredatesTrxStart", "stageLogsReadable", "buildLogReportsSuccess",
        "testLogReportsSuccess")))
    return {
        "schemaVersion": 1,
        "purpose": "read-only-original-soc-source-file-and-stage-log-reconciliation",
        "sourceShaFromOriginalPreTestFile": sha,
        "sourceIdentityLevel": "original-pretest-source-file-correlated" if correlated else "blocked",
        "sourceFileCorrelatedToHistoricalSocTrx": correlated,
        "sourceShaRunnerLinkedToTrx": None,
        "strictRunnerLinkEstablished": False,
        "missingProof": "Persisted successful post-test checkout assertion or contemporaneous runner completion attestation",
        "originalTrx": trx,
        "checks": checks,
        "originalFiles": files,
        "testsExecutedByAudit": 0,
        "capturesExecutedByAudit": 0,
        "newEvidenceAdmissions": 0,
        "fieldAccuracyEstablished": False,
        "warnings": [
            "A real commit in a pre-run SHA file is not proof of clean checkout after tests.",
            "The checked historical SOC script prints its final checkout PASS to console, not to the recovered individual stage logs.",
            "A source-file-correlated SOC TRX must not be added to the strict runner-linked count.",
            "This is historical synthetic SOC UI validation only, not field accuracy or current-source readiness."
        ]
    }

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--bundle", required=True, type=Path)
    p.add_argument("--previous", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--max-trx-bytes", type=int, default=33554432)
    args = p.parse_args()
    if not 1 <= args.max_trx_bytes <= 67108864:
        p.error("Invalid TRX size gate")
    bundle, output = args.bundle.resolve(), args.output.resolve()
    if output.exists() or output.is_relative_to((bundle / "originals").resolve()):
        p.error("Output exists or would modify original evidence")
    result = audit(bundle, read_json(args.previous), args.max_trx_bytes)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
    print(json.dumps({
        "sourceShaFromOriginalPreTestFile": result["sourceShaFromOriginalPreTestFile"],
        "sourceFileCorrelatedToHistoricalSocTrx": result["sourceFileCorrelatedToHistoricalSocTrx"],
        "strictRunnerLinkEstablished": result["strictRunnerLinkEstablished"],
        "checks": result["checks"],
        "output": str(output)
    }, indent=2))
    return 0

if __name__ == "__main__":
    sys.exit(main())
