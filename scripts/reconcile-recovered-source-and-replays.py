#!/usr/bin/env python3
"""Read-only historical evidence provenance audit; no test/build/capture/admission.

Run against a recovered bundle containing recovery-manifest.json and originals/.
Uses only Python's standard library. Emits aggregate metadata, not raw traffic.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

SHA40 = re.compile(r"^[0-9a-f]{40}$")
RUN_SHA_HINT = re.compile(r"(?<![0-9a-f])([0-9a-f]{8,40})(?![0-9a-f])")
PAIR = re.compile(r"^cli-paired-(pcap|pcapng)-(R(?:[0-9]{3}|1000))-(positive|negative)$")
NS = "{http://microsoft.com/schemas/VisualStudio/TeamTest/2010}"
TARGET_RULES = {"R102", "R118", "R163", "R272", "R275", *("R%03d" % n for n in range(586, 606))}

def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for data in iter(lambda: stream.read(1048576), b""):
            digest.update(data)
    return digest.hexdigest()

def mapping(value: object) -> dict:
    """Some historical qualification formats use lists, nulls or dictionaries."""
    return value if isinstance(value, dict) else {}

def valid_zero_stage(stages: object, name: str) -> bool:
    code = mapping(stages).get(name)
    return type(code) is int and code == 0

def matching_counters(suite: object, trx: dict) -> bool:
    if trx.get("status") != "parsed":
        return False
    counters = mapping(mapping(suite).get("counters"))
    try:
        return all(
            isinstance(counters.get(key), (int, str))
            and not isinstance(counters.get(key), bool)
            and int(counters[key]) == trx.get(key)
            for key in ("total", "passed", "failed")
        )
    except (TypeError, ValueError, KeyError):
        return False

def read_original_text(path: Path) -> str:
    """Decode original PowerShell UTF-16 BOM files and UTF-8 without altering bytes."""
    raw = path.read_bytes()
    if raw[:2] in (bytes((255, 254)), bytes((254, 255))):
        return raw.decode("utf-16")
    return raw.decode("utf-8-sig")

def read_json(path: Path) -> dict:
    data = json.loads(read_original_text(path))
    if not isinstance(data, dict):
        raise ValueError("JSON object required")
    return data

def safe_copy_path(bundle: Path, relative: str) -> Path:
    rel = Path(relative.replace("\\", "/"))
    if rel.is_absolute() or ".." in rel.parts or rel.parts[0] != "originals":
        raise ValueError("Unsafe relative copy path")
    path = bundle / rel
    if path.is_symlink() or any(parent.is_symlink() for parent in path.parents if parent != bundle.parent):
        raise ValueError("Symlink in recovered copy path")
    if not path.resolve().is_relative_to(bundle.resolve()):
        raise ValueError("Escaping recovered bundle")
    return path

def find_report_for_trx(rel: str, reports: dict) -> dict | None:
    return reports.get(str(Path(rel).parent).replace("\\", "/"))

def summarize_trx(path: Path, expected_size: int, max_size: int) -> dict:
    if expected_size > max_size:
        return {"status": "skipped-size"}
    data = path.read_bytes()
    if len(data) != expected_size or b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        return {"status": "rejected-content"}
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        return {"status": "rejected-xml"}
    if root.tag != NS + "TestRun":
        return {"status": "rejected-schema"}
    defs = {}
    for unit in root.findall("./" + NS + "TestDefinitions/" + NS + "UnitTest"):
        method = unit.find(NS + "TestMethod")
        if method is not None:
            defs[unit.get("id")] = {
                "className": method.get("className", "").split(",")[0],
                "methodName": method.get("name", ""),
                "definitionName": unit.get("name", "")
            }
    results = root.findall("./" + NS + "Results/" + NS + "UnitTestResult")
    counters = root.find("./" + NS + "ResultSummary/" + NS + "Counters")
    if counters is None or int(counters.get("total", "-1")) != len(results):
        return {"status": "rejected-counters"}
    duplicate = collections.defaultdict(list)
    mapped = 0
    target = collections.defaultdict(lambda: collections.Counter())
    for r in results:
        name = r.get("testName", "")
        tid = r.get("testId", "")
        definition = defs.get(tid)
        if definition:
            mapped += 1
            owner = definition["className"].split(".")[-1]
            match = re.match(r"^(R(?:[0-9]{3}|1000))(?!\d)", owner)
            if match and match.group(1) in TARGET_RULES:
                target[match.group(1)][r.get("outcome", "?")] += 1
        duplicate[name].append((tid, r.get("executionId", "")))
    collisions = []
    for name, instances in duplicate.items():
        if len(instances) > 1:
            collisions.append({
                "displayName": name[:220],
                "occurrences": len(instances),
                "distinctTestIds": len({x[0] for x in instances}),
                "distinctExecutionIds": len({x[1] for x in instances}),
                "definitions": list({(defs.get(x[0]) or {}).get("methodName", "") for x in instances})
            })
    return {
        "status": "parsed",
        "total": len(results),
        "passed": sum(r.get("outcome") == "Passed" for r in results),
        "failed": sum(r.get("outcome") == "Failed" for r in results),
        "definitionsMapped": mapped,
        "definitionsMissing": len(results) - mapped,
        "collisionGroups": collisions[:30],
        "directClassOutcomes": {k: dict(v) for k, v in sorted(target.items())}
    }

def replay_control(bundle: Path, index: dict, parent: str, fmt: str, key: str, expected: dict) -> dict:
    match = re.match(r"^(R(?:[0-9]{3}|1000))-(positive|negative)$", key)
    result = {"format": fmt, "key": key, "status": "unverified", "checks": []}
    if not match:
        result["status"] = "invalid-control"
        return result
    if not isinstance(expected, dict):
        result["status"] = "invalid-control-metadata"
        return result
    rid, polarity = match.groups()
    stem = "cli-paired-%s-%s-%s" % (fmt, rid, polarity)
    file_names = [(stem + "." + fmt, "fixtureSha256"), (stem + ".log", "outputSha256")]
    verified_files = []
    for name, hash_key in file_names:
        rel = (parent + "/" + name).replace("\\", "/")
        original = index.get(rel.lower())
        if not original:
            result["checks"].append("missing-" + name)
            return result
        file_path = safe_copy_path(bundle, original["relativeCopy"])
        actual = sha256(file_path)
        if actual != original["sha256"].lower() or actual != str(expected.get(hash_key, "")).lower():
            result["checks"].append("hash-mismatch-" + name)
            return result
        verified_files.append(file_path)
    try:
        raw = read_json(verified_files[1])
        replay = raw["replay"]
        rules = replay["rules"]
        findings = replay["findings"]
        required = 1 if polarity == "positive" else 0
        checks = [
            raw.get("schemaVersion") == 1,
            raw.get("mode") == "offline_replay",
            raw.get("provenance") == "untrusted_capture",
            raw.get("detectionValidation") == "not_assessed",
            replay.get("format") == fmt,
            replay.get("packetsRead") == expected.get("packets"),
            replay.get("parsed") == expected.get("packets"),
            replay.get("rejected") == 0,
            replay.get("captureTruncated") == 0,
            replay.get("clockResets") == 0,
            replay.get("rules") is not None,
            replay.get("matchCount") == required,
            replay.get("suppressedCount") == 0,
            replay.get("findingsTruncated") is False,
            len(findings) == required,
            len(rules) == 1,
            rules[0].get("ruleId") == rid,
            rules[0].get("status") == "evaluated",
            rules[0].get("matches") == required,
            rules[0].get("suppressed") == 0,
            str(expected.get("ruleId")) == rid,
            str(expected.get("control")) == polarity,
            expected.get("matches") == required,
            expected.get("suppressed") == 0,
        ]
        if polarity == "positive":
            checks.extend([
                findings[0].get("ruleId") == rid,
                findings[0].get("packetNumber") == expected.get("packets")
            ])
        result["status"] = "synthetic-control-observed" if all(checks) else "replay-contract-mismatch"
        result["checks"] = ["paired-copy-and-report-sha256-verified", "replay-json-contract-checked"]
        result["matches"] = replay.get("matchCount")
        result["packets"] = replay.get("packetsRead")
    except (UnicodeError, json.JSONDecodeError) as exc:
        result["status"] = "log-text-or-json-decode-failed"
        result["errorType"] = type(exc).__name__
    except (OSError, ValueError, KeyError, TypeError, IndexError, AttributeError) as exc:
        result["status"] = "replay-contract-unreadable-or-invalid"
        result["errorType"] = type(exc).__name__
    return result

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--max-trx-bytes", type=int, default=33554432)
    args = parser.parse_args()
    bundle = args.bundle.resolve()
    if args.max_trx_bytes < 1 or args.max_trx_bytes > 67108864:
        parser.error("--max-trx-bytes outside safe 1..67108864")
    output = args.output.resolve()
    if output.exists():
        parser.error("Output already exists; use a new filename")
    if output.is_relative_to((bundle / "originals").resolve()):
        parser.error("Do not write outputs into original evidence copies")
    recovery = read_json(bundle / "recovery-manifest.json")
    if recovery.get("purpose") != "historical-Windows-artifact-byte-recovery":
        parser.error("Not an original evidence recovery manifest")
    artifacts = recovery.get("artifacts", [])
    index = {str(x["relativeCopy"]).lower().replace("\\", "/"): x for x in artifacts}
    if len(artifacts) != recovery.get("artifactCount") or len(index) != len(artifacts):
        parser.error("Duplicate or missing recovery manifest entries")
    reports = {}
    for rel, item in index.items():
        if not rel.endswith("/qualification.json"):
            continue
        path = safe_copy_path(bundle, item["relativeCopy"])
        if path.stat().st_size != item["bytes"] or sha256(path) != item["sha256"].lower():
            reports[rel.rsplit("/", 1)[0]] = {"status": "hash-mismatch"}
            continue
        try:
            report = read_json(path)
            source = str(report.get("sourceSha", "")).lower()
            suite_data = mapping(report.get("suites"))
            stage_data = mapping(report.get("stages"))
            replay_data = mapping(report.get("perRuleReplay"))
            reports[rel.rsplit("/", 1)[0]] = {
                "status": "original-report-hash-verified",
                "sha256": item["sha256"],
                "sourceSha": source if SHA40.fullmatch(source) else None,
                "sourceIdentityLevel": "runner-declared-only",
                "qualificationStatus": report.get("status"),
                "platform": report.get("platform"),
                "start": report.get("startedUtc"),
                "finish": report.get("finishedUtc"),
                "portableSyntheticQualified": report.get("portableSyntheticQualified"),
                "windowsParityQualified": report.get("windowsParityQualified"),
                "fieldAccuracyQualified": report.get("fieldAccuracyQualified"),
                "suites": suite_data,
                "stageCodes": stage_data,
                "reportFieldTypes": {
                    "suites": type(report.get("suites")).__name__,
                    "stages": type(report.get("stages")).__name__,
                    "perRuleReplay": type(report.get("perRuleReplay")).__name__
                },
                "replays": [],
            }
            if replay_data:
                parent = rel.rsplit("/", 1)[0]
                for fmt, scenarios in replay_data.items():
                    if fmt not in ("pcap", "pcapng") or not isinstance(scenarios, dict):
                        reports[parent]["replays"].append({
                            "format": str(fmt), "status": "invalid-replay-report-shape"
                        })
                        continue
                    for key, expected in scenarios.items():
                        evidence = replay_control(bundle, index, parent, fmt, key, expected)
                        stage = "cli-paired-%s-%s" % (fmt, key)
                        evidence["runnerStageExitCode"] = stage_data.get(stage)
                        if evidence["status"] == "synthetic-control-observed" and not valid_zero_stage(stage_data, stage):
                            evidence["status"] = "stage-code-not-zero-or-missing"
                        reports[parent]["replays"].append(evidence)
        except (ValueError, UnicodeError, OSError):
            reports[rel.rsplit("/", 1)[0]] = {"status": "unreadable-report"}
    # Link original reports ONLY within the same folder; never inherit SHA from parent/checkout.
    runs = []
    for rel, item in sorted(index.items()):
        if not rel.endswith(".trx"):
            continue
        path = safe_copy_path(bundle, item["relativeCopy"])
        status = "original-hash-verified"
        if path.stat().st_size != item["bytes"] or sha256(path) != item["sha256"].lower():
            status = "hash-mismatch"
            detail = {"status": "not-parsed"}
        else:
            detail = summarize_trx(path, item["bytes"], args.max_trx_bytes)
        report = find_report_for_trx(rel, reports)
        hints = sorted(set(RUN_SHA_HINT.findall(rel)))
        source = report.get("sourceSha") if report and report.get("status") == "original-report-hash-verified" else None
        suite = mapping(mapping(report.get("suites")).get(path.stem)) if report else {}
        counter_match = matching_counters(suite, detail)
        completed = report and report.get("qualificationStatus") in (
            "SyntheticPortablePassed", "SyntheticPortableAndWindowsParityPassed"
        )
        runner_linked = bool(source and status == "original-hash-verified" and
                             counter_match and completed and
                             valid_zero_stage(report.get("stageCodes"), path.stem))
        runs.append({
            "relativeCopy": item["relativeCopy"],
            "trxSha256": item["sha256"],
            "sourceShaDeclaredInSameDirectoryReport": source,
            "sourceShaRunnerLinkedToTrx": source if runner_linked else None,
            "reportCountersMatchOriginalTrx": bool(counter_match),
            "sourceAttribution": ("pinned-runner-report-matching-original-trx" if runner_linked
                                  else "unverified-report-claim" if source else "unknown"),
            "pathShaHintsUnverified": hints,
            "originalArtifactStatus": status,
            "originalTrxDefinitions": detail
        })
    workspace = []
    for rel, item in sorted(index.items()):
        if not rel.endswith("/source-sha.txt"):
            continue
        path = safe_copy_path(bundle, item["relativeCopy"])
        if sha256(path) != item["sha256"].lower():
            workspace.append({"path": rel, "status": "hash-mismatch"})
            continue
        try:
            decoded = read_original_text(path)
        except UnicodeError:
            workspace.append({"path": rel, "status": "unreadable-encoding", "sourceSha40": None})
            continue
        candidate = decoded.strip().lower()
        source_sha = candidate if SHA40.fullmatch(candidate) else None
        workspace.append({
            "path": rel, "status": "original-content-read",
            "sourceSha40": source_sha,
            "sourceIdentityLevel": "original-source-file-only-unbound",
            "sha40Tokens": re.findall(r"\b[0-9a-f]{40}\b", decoded.lower()),
        })
    controls = [v for r in reports.values() for v in r.get("replays", [])]
    summary = {
        "recoveredManifestFileCount": len(artifacts),
        "originalTrxCount": len(runs),
        "originalReportsHashVerified": sum(x.get("status") == "original-report-hash-verified" for x in reports.values()),
        "runSourceShaFromSameDirectoryReport": sum(bool(x["sourceShaDeclaredInSameDirectoryReport"]) for x in runs),
        "runSourceShaRunnerLinkedToTrx": sum(bool(x["sourceShaRunnerLinkedToTrx"]) for x in runs),
        "runsWithoutSameDirectoryReport": sum(not x["sourceShaDeclaredInSameDirectoryReport"] for x in runs),
        "originalTrxDefinitionParseCount": sum(x["originalTrxDefinitions"].get("status") == "parsed" for x in runs),
        "syntheticReplayControlsChecked": len(controls),
        "syntheticReplayControlsObserved": sum(x["status"] == "synthetic-control-observed" for x in controls),
        "replayControlsBlocked": sum(x["status"] != "synthetic-control-observed" for x in controls),
        "testsExecutedByAudit": 0,
        "artifactsAdmitted": 0,
        "fieldDetectionQualityEstablished": False
    }
    result = {
        "schemaVersion": 1,
        "purpose": "read-only-original-source-and-synthetic-replay-reconciliation",
        "warnings": [
            "Runner-declared source SHA is not a cryptographic binding between a historical test and checkout.",
            "TRX display names may truncate parameters; original UnitTest definitions do not prove fixture values.",
            "Synthetic replay success is not field accuracy, production telemetry, or current HEAD acceptance.",
            "No detector tests or captures are executed; no rules or original manifests are modified."
        ],
        "summary": summary,
        "qualificationReports": reports,
        "trxRuns": runs,
        "sourceShaTextArtifacts": workspace
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, ensure_ascii=False)
    print(json.dumps({"summary": summary, "output": str(output)}, indent=2))
    return 0

if __name__ == "__main__":
    sys.exit(main())
