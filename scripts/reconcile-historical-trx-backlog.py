#!/usr/bin/env python3
"""Read-only exact-file reconciliation of historical Windows TRX provenance.

Inputs are derived reports and the reviewed six-run historical linkage ledger,
not original traffic. A SHA-like filename is NEVER accepted as source proof.
No tests, network captures, repository edits, or evidence admissions.
"""
from __future__ import annotations

import argparse
import collections
import csv
import hashlib
import json
import re
import sys
from pathlib import Path

SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
BRANCH = "feature/carthago-reliability-hardening"
V4_PURPOSE = "read-only-original-source-and-synthetic-replay-reconciliation"


def load_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("Expected JSON object in " + str(path))
    return value


def digest(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1048576), b""):
            sha.update(chunk)
    return sha.hexdigest()


def check_hex(value: object, pattern: re.Pattern, field: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ValueError("Invalid " + field)
    return value


def load_linkage(ledger: Path, v4: dict, integration: dict, active: dict) -> dict:
    with ledger.open("r", encoding="utf-8-sig", newline="") as inp:
        rows = list(csv.DictReader(inp))
    if len(rows) != 6:
        raise ValueError("Expected six exact linked TRX rows; do not silently change baseline")
    direct = {r["relativeCopy"]: r for r in v4["trxRuns"]}
    integrated = {r["trxRelativeCopy"]: r for r in integration["sourceShaBindings"]}
    if integration.get("purpose") != "read-only-historical-Windows-integration-provenance-reconciliation":
        raise ValueError("Integration report purpose mismatch")
    if active.get("purpose") != "read-only-original-active-sensor-evidence-reconciliation":
        raise ValueError("Active-sensor report purpose mismatch")
    active_proofs = {}
    for report in active.get("reports", []):
        path = report["reportRelativeCopy"].rsplit("/", 1)[0] + "/active-sensors.trx"
        if path in active_proofs:
            raise ValueError("Duplicate active sensor linkage")
        active_proofs[path] = report
    linked = {}
    for row in rows:
        path = row["original_recovered_trx"]
        sha = check_hex(row["runner_declared_source_sha"], SHA40, "linked runner SHA")
        trx_hash = check_hex(row["original_trx_sha256"], SHA256, "linked TRX hash")
        if path in linked or path not in direct:
            raise ValueError("Duplicate or unknown original linked TRX " + path)
        orig = direct[path]
        test = orig["originalTrxDefinitions"]
        if orig["trxSha256"] != trx_hash:
            raise ValueError("Linked CSV TRX hash does not equal original v4 hash: " + path)
        if int(row["executed"]) != test["total"] or int(row["passed"]) != test["passed"] or \
           int(row["failed"]) != test["failed"] or test["failed"] != 0:
            raise ValueError("Linked CSV counters do not equal original results: " + path)
        if row["source_link_level"] != "historical_runner_report_linked" or \
           any(row[k] != "false" for k in ("field_qualified","current_sha_qualified","formally_admitted")):
            raise ValueError("Unjustified evidence promotion in CSV")
        if orig.get("sourceShaRunnerLinkedToTrx"):
            if orig["sourceShaRunnerLinkedToTrx"] != sha or \
               not orig.get("reportCountersMatchOriginalTrx"):
                raise ValueError("V4 same-report linkage mismatch " + path)
            proof = "same-directory-original-qualification-report"
        elif path in integrated:
            match = integrated[path]
            if match.get("trxSha256") != trx_hash or match.get("runnerDeclaredSourceSha") != sha or \
               match.get("sourceIdentityLevel") != "runner-report-linked" or \
               match.get("evidenceAdmitted") is not False:
                raise ValueError("Integration source linkage mismatch " + path)
            proof = "original-integration-report-and-verifier"
        elif path in active_proofs:
            match = active_proofs[path]
            if match.get("trxSha256") != trx_hash or \
               match.get("sourceShaRunnerLinkedToTrx") != sha or \
               match.get("status") != "historical-synthetic-active-source-run-linked" or \
               not all(v is True for v in match.get("checks", {}).values()):
                raise ValueError("Active-sensor source linkage mismatch " + path)
            proof = "original-active-report-suite-contract"
        else:
            raise ValueError("No original-report proof for linked ledger row " + path)
        linked[path] = {"sourceSha": sha, "proof": proof}
    if len(linked) != 6:
        raise ValueError("Linked ledger did not resolve six original TRX")
    return linked


def triage(v4: dict, linked: dict) -> list[dict]:
    original = v4.get("trxRuns")
    if not isinstance(original, list) or len(original) != 42:
        raise ValueError("Expected frozen original 42 TRXs")
    if len({r["relativeCopy"] for r in original}) != len(original):
        raise ValueError("Duplicate original TRX paths in v4")
    result = []
    for r in original:
        path, trx_hash = r["relativeCopy"], check_hex(r["trxSha256"], SHA256, "original TRX SHA")
        definitions = r["originalTrxDefinitions"]
        if r.get("originalArtifactStatus") != "original-hash-verified" or \
           definitions.get("status") != "parsed" or definitions.get("total") != definitions.get("passed",0)+definitions.get("failed",0):
            # In this source inventory no skipped TRX is admitted. If one appears,
            # require a separate blocked review rather than treating it as pass.
            raise ValueError("Unresolved original TRX integrity/counters " + path)
        count = definitions["total"]
        fails = definitions["failed"]
        hints = r.get("pathShaHintsUnverified") or []
        record = {
            "originalTrx": path, "trxSha256": trx_hash,
            "executedResultCount": count, "passed": definitions["passed"], "failed": fails,
            "sourceSha": linked[path]["sourceSha"] if path in linked else None,
            "sourceLinkStatus": "runner-report-linked" if path in linked else "unlinked",
            "runnerProof": linked[path]["proof"] if path in linked else None,
            "pathHintsUnverified": hints, "newEvidenceAdmitted": False,
            "fieldAccuracyQualified": False,
        }
        if path in linked:
            record["priority"] = "LINKED_DO_NOT_RECOUNT"
            record["nextEvidenceNeeded"] = "Retain source report and original TRX; no promotion"
        elif "/soc-workspace-" in path:
            record["priority"] = "P1_PRETEST_SOURCE_ONLY"
            record["nextEvidenceNeeded"] = "Authentic historical final checkout/PASS record (not the later completed SOC run)"
        elif fails:
            record["priority"] = "P1_FAILURE_INVESTIGATION"
            record["nextEvidenceNeeded"] = "Review specific failed outcomes, original logs and contemporaneous source provenance; never count as all-pass"
        elif count >= 5000:
            record["priority"] = "P2_FULL_REGRESSION_SHA"
            record["nextEvidenceNeeded"] = "Recover contemporaneous runner source SHA plus original stage log/report; path hash hints do not qualify"
        else:
            record["priority"] = "P3_TARGETED_OR_CLI_SHA"
            record["nextEvidenceNeeded"] = "Find exact matching original qualification report or preserved command transcript with source identity"
        result.append(record)
    return result


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--v4", type=Path, required=True)
    p.add_argument("--integration", type=Path, required=True)
    p.add_argument("--active", type=Path, required=True)
    p.add_argument("--linked-ledger", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True, help="New derived JSON filename; not originals")
    a = p.parse_args()
    if a.output.exists() or "originals" in a.output.parts:
        p.error("Refusing to overwrite or write into original evidence")
    v4, integration, active = load_json(a.v4), load_json(a.integration), load_json(a.active)
    if v4.get("purpose") != V4_PURPOSE or v4.get("summary",{}).get("originalTrxCount") != 42:
        raise ValueError("Wrong v4 source-run report")
    linked = load_linkage(a.linked_ledger, v4, integration, active)
    runs = triage(v4, linked)
    count = collections.Counter(r["priority"] for r in runs)
    digest_copies = collections.defaultdict(list)
    for row in runs:
        digest_copies[row["trxSha256"]].append(row["originalTrx"])
    duplicate_groups = [
        {"trxSha256": sha, "originalCopies": sorted(paths)}
        for sha, paths in sorted(digest_copies.items()) if len(paths) > 1
    ]
    if len(runs) != 42 or len(linked) != 6 or sum(r["sourceSha"] is None for r in runs) != 36:
        raise ValueError("Historical TRX inventory/link counts changed without proof")
    if len(digest_copies) != 41 or len(duplicate_groups) != 1 or        len(duplicate_groups[0]["originalCopies"]) != 2:
        raise ValueError("Historical original-copy digest grouping changed; requires review")
    result = {
        "schemaVersion": 1, "purpose": "historical-windows-42-trx-backlog-readonly",
        "branch": BRANCH, "inputs": {
            "v4Sha256": digest(a.v4), "integrationSha256": digest(a.integration),
            "activeSha256": digest(a.active), "linkedLedgerSha256": digest(a.linked_ledger)
        }, "summary": {
            "frozenOriginalTrx": 42, "runnerReportLinked": 6, "stillUnlinked": 36,
            "distinctOriginalTrxDigests": len(digest_copies),
            "distinctUnlinkedTrxDigests": len({r["trxSha256"] for r in runs if r["sourceSha"] is None}),
            "duplicateFileCopyGroups": len(duplicate_groups),
            "unlinkedHistoricalFailedRuns": sum(r["failed"] > 0 and r["sourceSha"] is None for r in runs),
            "priorityCounts": dict(sorted(count.items())),
            "testsExecutedByAudit": 0, "capturesExecutedByAudit": 0,
            "fieldQualified": False, "newEvidenceAdmissions": 0
        },
        "duplicateOriginalCopies": duplicate_groups,
        "warnings": [
            "42 recovered TRX files contain 41 unique original TRX SHA-256 digests; duplicate copies are not independent test executions.",
            "A short SHA-like filename, Git HEAD today, or neighboring runner cannot attest a historical run.",
            "Result counts are test executions, not distinct rules nor positive/negative field accuracy.",
            "The newer successful SOC completion belongs outside this frozen historical 42-TRX inventory.",
        ],
        "runs": sorted(runs, key=lambda r: (r["priority"], -r["failed"], -r["executedResultCount"], r["originalTrx"])),
    }
    a.output.parent.mkdir(parents=True, exist_ok=True)
    with a.output.open("x", encoding="utf-8") as file:
        json.dump(result, file, indent=2, ensure_ascii=False)
        file.write("\n")
    print(json.dumps({"output": str(a.output), "summary": result["summary"]}, indent=2))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyError, OSError, TypeError, ValueError) as error:
        print("BLOCKED: " + str(error), file=sys.stderr)
        sys.exit(3)
