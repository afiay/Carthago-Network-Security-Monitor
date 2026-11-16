#!/usr/bin/env python3
"""Read-only original-log candidate scan for unlinked historical Windows TRXs.

Enumerates hash/size-verified nearby original logs from the 359-artifact Windows
recovery. Emits only full SHA token candidates and log hashes, never log lines.
Log proximity and SHA tokens are UNVERIFIED HINTS, never runner attestations.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

SHA40 = re.compile(r"\b[a-fA-F0-9]{40}\b")
SOURCE_LINE = re.compile(r"\b(?:source|commit|revision|checkout|rev-parse|git\s+sha|head)\b", re.I)
MAX_BYTES = 8 * 1024 * 1024


def load(path: Path) -> dict:
    result = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(result, dict):
        raise ValueError("JSON object required")
    return result


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1048576), b""):
            h.update(chunk)
    return h.hexdigest()


def original_path(bundle: Path, relative: str) -> Path:
    rel = relative.replace("\\", "/")
    parts = rel.split("/")
    if len(parts) < 3 or parts[0] != "originals" or any(p in ("", ".", "..") for p in parts):
        raise ValueError("Unsafe original artifact path")
    item = bundle
    for part in parts:
        item = item / part
        if item.is_symlink():
            raise ValueError("Original artifact symlink rejected")
    if not item.resolve().is_relative_to(bundle.resolve()):
        raise ValueError("Evidence path escapes recovery bundle")
    return item


def same_run_family(trx: str, candidate: str) -> bool:
    t = trx.replace("\\", "/").split("/")[:-1]
    c = candidate.replace("\\", "/").split("/")[:-1]
    if len(t) < 3 or len(c) < 3 or t[:2] != c[:2]:
        return False
    if c == t:
        return True
    # Genuine subfolders like <run>/local-logs or <run>/diagnostic.
    return len(c) <= len(t) + 2 and c[:len(t)] == t


def inspect(bundle: Path, backlog: dict, max_bytes: int) -> dict:
    manifest = load(bundle / "recovery-manifest.json")
    originals = manifest.get("artifacts")
    if manifest.get("purpose") != "historical-Windows-artifact-byte-recovery" or \
       not isinstance(originals, list) or len(originals) != manifest.get("artifactCount"):
        raise ValueError("Original recovery manifest invalid")
    if backlog.get("purpose") != "historical-windows-42-trx-backlog-readonly" or \
       backlog.get("summary",{}).get("stillUnlinked") != 36:
        raise ValueError("Expected checked 36-unlinked backlog")
    available = {}
    for entry in originals:
        rel = entry["relativeCopy"].replace("\\", "/")
        key = rel.lower()
        if key in available:
            raise ValueError("Duplicate original artifact in recovery manifest")
        available[key] = entry
    candidates = [
        entry for entry in originals
        if entry["relativeCopy"].lower().endswith((".log", ".txt", ".json"))
        and "/originals/" not in entry["relativeCopy"].lower()
    ]
    # Cached validation prevents re-reading the same original log for many runs.
    cache: dict[str, dict] = {}
    entries: list[dict] = []
    for row in backlog["runs"]:
        if row["sourceLinkStatus"] != "unlinked":
            continue
        trx = row["originalTrx"]
        near = []
        for entry in candidates:
            log_rel = entry["relativeCopy"].replace("\\", "/")
            if not same_run_family(trx, log_rel):
                continue
            if log_rel not in cache:
                file = original_path(bundle, log_rel)
                state = {"relativeOriginal": log_rel,
                         "reportedBytes": entry.get("bytes"),
                         "reportedSha256": entry.get("sha256"),
                         "status": "not-scanned", "sha40Tokens": [],
                         "sourceContextShaTokens": []}
                if not file.is_file():
                    state["status"] = "missing-original"
                elif file.stat().st_size != entry.get("bytes"):
                    state["status"] = "original-size-mismatch"
                elif file.stat().st_size > max_bytes:
                    state["status"] = "too-large-to-scan"
                elif sha256(file) != str(entry.get("sha256", "")).lower():
                    state["status"] = "original-hash-mismatch"
                else:
                    raw = file.read_bytes()
                    try:
                        decoded = raw.decode("utf-16") if raw[:2] in (bytes((255,254)),bytes((254,255))) else raw.decode("utf-8-sig")
                    except UnicodeError:
                        state["status"] = "binary-or-unknown-encoding"
                    else:
                        tokens = set()
                        contextual = set()
                        for line in decoded.splitlines():
                            matches = [s.lower() for s in SHA40.findall(line)]
                            tokens.update(matches)
                            if matches and SOURCE_LINE.search(line):
                                contextual.update(matches)
                        state["status"] = "original-hash-verified-and-scanned"
                        state["sha40Tokens"] = sorted(tokens)[:30]
                        state["sourceContextShaTokens"] = sorted(contextual)[:30]
                cache[log_rel] = state
            near.append(cache[log_rel])
        entries.append({
            "originalTrx": trx,
            "linkedAfterScan": False,
            "companionOriginalFiles": near,
            "candidateShaTokensUnverified": sorted({
                sha for record in near for sha in record["sourceContextShaTokens"]
            }),
        })
    return {
        "schemaVersion": 1, "purpose": "original-log-source-hints-no-attribution",
        "summary": {
            "unlinkedTrxInspected": len(entries),
            "originalCompanionFilesExamined": len(cache),
            "originalCompanionFilesHashVerifiedAndScanned": sum(
                v["status"] == "original-hash-verified-and-scanned" for v in cache.values()),
            "trxsWithSourceContextCandidates": sum(bool(x["candidateShaTokensUnverified"]) for x in entries),
            "newRunnerSourceLinks": 0, "testsExecuted": 0, "capturesExecuted": 0,
            "evidenceAdmitted": False,
        },
        "warnings": [
            "Proximity, chronological file names, and full SHA text tokens are hints, not proof the TRX executed at that SHA.",
            "Original log contents are not reproduced in the derived report; only SHA candidate tokens and hashes.",
            "Independently check runner stage status, actual test/TRX binding and post-run source verification before any promotion.",
            "Logs larger than configured byte bound are skipped, not treated as empty.",
        ],
        "runs": entries,
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--bundle", required=True, type=Path)
    p.add_argument("--backlog", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--max-log-bytes", type=int, default=MAX_BYTES)
    args = p.parse_args()
    if not 1 <= args.max_log_bytes <= 32 * 1024 * 1024:
        p.error("Invalid log scan bound")
    if args.output.exists() or "originals" in args.output.parts:
        p.error("Refusing to overwrite or write among originals")
    report = inspect(args.bundle.resolve(), load(args.backlog), args.max_log_bytes)
    if report["summary"]["unlinkedTrxInspected"] != 36:
        raise ValueError("Not all 36 historical unlinked TRXs inspected")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as file:
        json.dump(report, file, indent=2)
        file.write("\n")
    print(json.dumps({"output": str(args.output),
                      "summary": report["summary"]}, indent=2))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError) as error:
        print("BLOCKED: " + str(error), file=sys.stderr)
        sys.exit(3)
