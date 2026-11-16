#!/usr/bin/env python3
"""Read-only cross-check of original Windows integration reports, TRXs and PASS logs.

This is historical provenance inspection, NOT execution, field qualification or
an admission to the exact-ID evidence registry. Standard-library-only Python.
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
FINAL_PASS = re.compile(r"(?m)^PASS: local build, tests and replay validation\.\s*$")

def read_text(path: Path) -> str:
    raw = path.read_bytes()
    if raw[:2] in (bytes((255, 254)), bytes((254, 255))):
        return raw.decode("utf-16")
    return raw.decode("utf-8-sig")

def load_json(path: Path) -> dict:
    data = json.loads(read_text(path))
    if not isinstance(data, dict):
        raise ValueError("Expected JSON object")
    return data

def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def path_in_bundle(bundle: Path, relative: str) -> Path:
    if not isinstance(relative, str):
        raise ValueError("Nonstring recovery path")
    raw = relative.replace("\\", "/")
    parts = raw.split("/")
    if parts[0] != "originals" or any(p in ("", ".", "..") for p in parts):
        raise ValueError("Unsafe recovered relative path")
    resolved = bundle
    for component in parts:
        resolved = resolved / component
        if resolved.is_symlink():
            raise ValueError("Symlink in original evidence")
    if not resolved.resolve().is_relative_to(bundle.resolve()):
        raise ValueError("Recovered path escapes evidence bundle")
    return resolved

def manifest_index(bundle: Path) -> tuple[dict, dict]:
    manifest = load_json(bundle / "recovery-manifest.json")
    if manifest.get("purpose") != "historical-Windows-artifact-byte-recovery":
        raise ValueError("Unexpected recovery manifest purpose")
    rows = manifest.get("artifacts")
    if not isinstance(rows, list) or len(rows) != manifest.get("artifactCount"):
        raise ValueError("Recovery manifest count mismatch")
    found = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("Non-object artifact")
        key = str(row["relativeCopy"]).replace("\\", "/").lower()
        if key in found:
            raise ValueError("Duplicate recovered path")
        found[key] = row
    return manifest, found

def original(bundle: Path, index: dict, relative: str) -> tuple[Path | None, str]:
    row = index.get(relative.lower())
    if row is None:
        return None, "missing-original"
    file_path = path_in_bundle(bundle, row["relativeCopy"])
    if not file_path.is_file() or type(row.get("bytes")) is not int:
        return None, "missing-or-invalid-copy"
    if file_path.stat().st_size != row["bytes"]:
        return None, "original-length-mismatch"
    if digest(file_path) != str(row.get("sha256", "")).lower():
        return None, "original-sha256-mismatch"
    return file_path, "sha256-verified"

def utc_timestamp(value: object) -> dt.datetime | None:
    if not isinstance(value, str):
        return None
    try:
        when = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        return when.astimezone(dt.timezone.utc) if when.tzinfo else None
    except ValueError:
        return None

def trx_summary(path: Path, max_bytes: int) -> dict:
    if path.stat().st_size < 1 or path.stat().st_size > max_bytes:
        return {"status": "rejected-size"}
    data = path.read_bytes()
    if b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        return {"status": "rejected-xml-declarations"}
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        return {"status": "rejected-xml"}
    if root.tag != NS + "TestRun":
        return {"status": "rejected-schema"}
    try:
        run_id = root.attrib["id"]
        uuid.UUID(run_id)
        summ = root.find(NS + "ResultSummary")
        ctr = root.find(NS + "ResultSummary/" + NS + "Counters")
        times = root.find(NS + "Times")
        results = root.findall(NS + "Results/" + NS + "UnitTestResult")
        if summ is None or ctr is None or times is None or not results:
            return {"status": "missing-required-xml"}
        counters = {}
        for key in ("total", "executed", "passed", "failed"):
            raw = ctr.attrib[key]
            if not re.fullmatch(r"\d+", raw):
                return {"status": "rejected-counters"}
            counters[key] = int(raw)
        start = utc_timestamp(times.get("start"))
        finish = utc_timestamp(times.get("finish"))
        valid = (summ.get("outcome") in ("Completed", "Passed") and
                 counters["total"] == len(results) and counters["total"] > 0 and
                 counters["total"] == counters["executed"] == counters["passed"] and
                 counters["failed"] == 0 and
                 all(r.get("outcome") == "Passed" for r in results) and
                 start is not None and finish is not None and start <= finish)
        return {
            "status": "passed" if valid else "failed-or-incomplete",
            "runId": run_id, "counters": counters,
            "start": start.isoformat() if start else None,
            "finish": finish.isoformat() if finish else None
        }
    except (KeyError, ValueError, OverflowError):
        return {"status": "invalid-trx-metadata"}

def exact_report_counters(source: object, trx: dict) -> bool:
    if trx.get("status") != "passed" or not isinstance(source, dict):
        return False
    required = trx["counters"]
    try:
        return all(type(source.get(k)) is int and source[k] == required[k]
                   for k in ("total", "executed", "passed", "failed"))
    except (KeyError, TypeError):
        return False

def contained_in_runner_period(trx: dict, start: object, finish: object) -> bool:
    started, finished = utc_timestamp(start), utc_timestamp(finish)
    ts, tf = utc_timestamp(trx.get("start")), utc_timestamp(trx.get("finish"))
    if not all((started, finished, ts, tf)) or started > finished:
        return False
    grace = dt.timedelta(minutes=2)
    return started - grace <= ts <= tf <= finished + grace

def zero_stage(stages: object, key: str) -> bool:
    if not isinstance(stages, dict):
        return False
    value = stages.get(key)
    return type(value) is int and value == 0

def audit_bundle(bundle: Path, max_trx_bytes: int, baseline: dict | None) -> dict:
    manifest, index = manifest_index(bundle)
    old_runs = {}
    if baseline:
        if baseline.get("purpose") != "read-only-original-source-and-synthetic-replay-reconciliation":
            raise ValueError("Unexpected baseline audit purpose")
        old_runs = {x["relativeCopy"].lower(): x for x in baseline.get("trxRuns", [])}
        for key in old_runs:
            if key not in index:
                raise ValueError("Baseline contains TRX absent from original manifest")
    reports = []
    bindings = []
    for rel, row in sorted(index.items()):
        if not rel.endswith("/integration.json"):
            continue
        f, status = original(bundle, index, rel)
        result = {
            "reportPath": row["relativeCopy"],
            "reportSha256": row["sha256"],
            "reportCopyStatus": status,
            "sourceShaDeclaration": None,
            "status": "not-attributed",
            "suiteLinks": []
        }
        reports.append(result)
        if f is None:
            continue
        try:
            record = load_json(f)
        except (UnicodeError, ValueError):
            result["status"] = "invalid-report-json"
            continue
        source = str(record.get("sourceSha", "")).lower()
        result["sourceShaDeclaration"] = source if SHA40.fullmatch(source) else None
        # Do not interpret failed/incomplete integration reports as passing evidence.
        passed_report = (
            record.get("schemaVersion") == 1 and
            SHA40.fullmatch(source) is not None and
            record.get("status") == "SyntheticIntegrationPassed" and
            record.get("fieldAccuracyQualified") is False and
            all(zero_stage(record.get("stages"), key)
                for key in ("solution-build", "cli-tests", "windows-verification"))
        )
        parent = rel.rsplit("/", 1)[0]
        log_path, log_status = original(bundle, index, parent + "/windows-verification.log")
        log_pass = False
        if log_path:
            try:
                log_pass = FINAL_PASS.search(read_text(log_path)) is not None
            except UnicodeError:
                log_status = "unreadable-log"
        result["windowsVerifierLogCopyStatus"] = log_status
        result["windowsVerifierFinalPassObserved"] = log_pass
        if not passed_report or not log_pass:
            result["status"] = "report-or-verifier-not-passing"
            continue

        for kind, name, counters_key, stage in (
            ("cli", "cli.trx", "cliTests", "cli-tests"),
            ("windows", "windows-tests/carthago-tests.trx", "windowsTests", "windows-verification")
        ):
            target = parent + "/" + name
            trx_file, original_status = original(bundle, index, target)
            link = {
                "kind": kind, "trxRelativeCopy": target,
                "originalCopyStatus": original_status,
                "matchedOriginalTrx": False,
                "reportCountersMatch": False,
                "runnerTimeEnclosed": False,
                "stageSuccess": zero_stage(record.get("stages"), stage),
                "sourceShaRunnerLinkedToTrx": None,
                "linkReason": "missing-or-unverified-original"
            }
            result["suiteLinks"].append(link)
            if trx_file is None:
                continue
            parsed = trx_summary(trx_file, max_trx_bytes)
            link["originalTrxStatus"] = parsed["status"]
            link["trxSha256"] = index[target.lower()]["sha256"]
            link["trxRunId"] = parsed.get("runId")
            link["originalTrxCounters"] = parsed.get("counters")
            link["matchedOriginalTrx"] = parsed.get("status") == "passed"
            link["reportCountersMatch"] = exact_report_counters(record.get(counters_key), parsed)
            link["runnerTimeEnclosed"] = contained_in_runner_period(
                parsed, record.get("startedUtc"), record.get("finishedUtc"))
            allowed = all((link["matchedOriginalTrx"], link["reportCountersMatch"],
                           link["runnerTimeEnclosed"], link["stageSuccess"]))
            if allowed:
                if old_runs and target.lower() not in old_runs:
                    link["linkReason"] = "not-in-prior-42-trx-inventory"
                    continue
                if old_runs and old_runs[target.lower()]["trxSha256"].lower() != link["trxSha256"].lower():
                    link["linkReason"] = "prior-manifest-trx-digest-disagreement"
                    continue
                link["sourceShaRunnerLinkedToTrx"] = source
                link["linkReason"] = "same-run-pinned-integration-report-verified"
                bindings.append({
                    "trxRelativeCopy": target, "trxSha256": link["trxSha256"],
                    "runnerDeclaredSourceSha": source, "sourceIdentityLevel": "runner-report-linked",
                    "suiteKind": kind, "resultCount": parsed["counters"]["passed"],
                    "evidenceAdmitted": False
                })
            else:
                failed = [k for k in ("matchedOriginalTrx", "reportCountersMatch",
                                      "runnerTimeEnclosed", "stageSuccess") if not link[k]]
                link["linkReason"] = "failed-gates:" + ",".join(failed)
        result["status"] = "attributed-only-linked-suites" if any(
            v["sourceShaRunnerLinkedToTrx"] for v in result["suiteLinks"]) else "no-suites-attributed"

    prior_linked = sum(bool(x.get("sourceShaRunnerLinkedToTrx"))
                       for x in old_runs.values())
    new_binding_paths = {b["trxRelativeCopy"].lower() for b in bindings}
    already_linked = {path for path, x in old_runs.items()
                      if x.get("sourceShaRunnerLinkedToTrx")}
    all_linked = new_binding_paths | already_linked
    summary = {
        "originalManifestArtifactCount": manifest["artifactCount"],
        "originalIntegrationReportsInspected": len(reports),
        "reportLinkedIntegrationTrx": len(bindings),
        "previousTrxSourceLinks": prior_linked if old_runs else None,
        "newTrxSourceLinksNotInPreviousAudit": len(new_binding_paths - already_linked) if old_runs else None,
        "sourceLinkedTrxCumulative": len(all_linked) if old_runs else None,
        "trxRemainingWithoutRunnerLink": (len(old_runs) - len(all_linked)) if old_runs else None,
        "testsExecutedByAudit": 0,
        "captureOperations": 0,
        "newEvidenceAdmissions": 0,
        "fieldAccuracyQualified": False
    }
    return {
        "schemaVersion": 1,
        "purpose": "read-only-historical-Windows-integration-provenance-reconciliation",
        "warnings": [
            "A runner-declared SHA is a contemporaneous claim, not independent cryptographic attestation.",
            "Only exact original TRX files with hash, per-run report counters, timestamps, stage success and verifier PASS are linked.",
            "Unlinked standalone regressions remain unverified; never infer source from adjacent filenames or current checkout.",
            "This audit does not run detectors, builds or captures and does not admit production or field rule quality."
        ],
        "summary": summary,
        "sourceShaBindings": bindings,
        "integrationReports": reports
    }

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--bundle", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--previous", type=Path, help="Optional v3 original TRX reconciliation JSON")
    p.add_argument("--max-trx-bytes", type=int, default=33554432)
    a = p.parse_args()
    if not 1 <= a.max_trx_bytes <= 67108864:
        p.error("TRX maximum outside range 1..67108864")
    bundle = a.bundle.resolve()
    output = a.output.resolve()
    if output.exists() or output.is_relative_to((bundle / "originals").resolve()):
        p.error("Output exists or would alter recovered originals")
    baseline = load_json(a.previous) if a.previous else None
    result = audit_bundle(bundle, a.max_trx_bytes, baseline)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(json.dumps(result["summary"], indent=2))
    return 0

if __name__ == "__main__":
    sys.exit(main())
