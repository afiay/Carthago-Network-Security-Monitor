#!/usr/bin/env python3
"""Human-operated WPF G5/G6 acceptance: prepare/assess without running Carthago.

Only an operator observing the Windows GUI can mark checks PASS. No screenshots,
network captures, tests, application launches, or evidence admissions are faked.
The assessment validates a pinned Git source and hashes evidence the operator saved.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
import uuid
from pathlib import Path

BRANCH = "feature/carthago-reliability-hardening"
PURPOSE = "manual-wpf-g5-g6-owner-acceptance"
CASES = (
    ("G5-01", "G5", "Launch and visible startup: no crash, clipped headings or missing main controls"),
    ("G5-02", "G5", "Overview, Live Traffic, Monitoring Health and Detection Coverage navigation stays in one window"),
    ("G5-03", "G5", "Monitoring Health differentiates stopped, unavailable, paused, active, parse errors and UI queue drops"),
    ("G5-04", "G5", "Network Investigation IP, port, DNS QNAME and recorded event ID searches select only retained data"),
    ("G5-05", "G5", "Incident timeline exact-ID pivots, missing values and evidence provenance are never inferred"),
    ("G5-06", "G5", "History back/forward, row boundaries, Alt+Up/Down, Tab, focus and accessible names"),
    ("G5-07", "G5", "Analytics time window, historical redraw and approximate-only geolocation; private addresses not public pins"),
    ("G5-08", "G5", "Incident and session export: explicit scope confirmation, Excel content, unknown fields and redaction"),
    ("G5-09", "G5", "Active sensor status: distinguish unconfigured, disabled, failed, running, and missing observations"),
    ("G5-10", "G5", "Settings, window resize, minimize/restore, and retained-state navigation without UI stalls"),
    ("G6-01", "G6", "Record actual ETW/Npcap source, privilege and interface; unavailable hardware is NOT a pass"),
    ("G6-02", "G6", "Authorized capture-to-display path with real source/delivered/dropped deltas, never fabricated rates"),
    ("G6-03", "G6", "Correlate Monitoring Health with source logs, queue timing and CSA diagnostics during workload"),
    ("G6-04", "G6", "At least 15-minute process responsiveness, CPU/private memory, stalled dispatcher and UI-drop observation"),
    ("G6-05", "G6", "Graceful stop, restart and original incident/session persistence without unintended loss"),
    ("G6-06", "G6", "Original export/CSA evidence corresponds to selected sessions; no invented process or country data"),
)
ALLOWED = {"not_run", "pass", "fail", "blocked"}
HEX40 = re.compile(r"^[0-9a-f]{40}$")


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def git(command: list[str]) -> str:
    result = subprocess.run(["git", "-C", str(repo_root()), *command],
                            text=True, capture_output=True, check=False)
    if result.returncode:
        raise ValueError("Git failed for " + " ".join(command) + ": " + result.stderr.strip()[:200])
    return result.stdout.strip()


def pin_checkout() -> dict:
    branch = git(["symbolic-ref", "--short", "HEAD"])
    sha = git(["rev-parse", "HEAD"]).lower()
    origin = git(["rev-parse", "refs/remotes/origin/" + BRANCH]).lower()
    clean = git(["status", "--porcelain", "--untracked-files=all"]) == ""
    if branch != BRANCH or not HEX40.fullmatch(sha) or not HEX40.fullmatch(origin):
        raise ValueError("Wrong branch or unavailable full source identity")
    if sha != origin or not clean:
        raise ValueError("Working tree unclean or local HEAD differs from origin tracking ref")
    return {"branch": branch, "sourceSha": sha, "originSha": origin, "clean": clean}


def new_file(path: Path, data: dict) -> None:
    with path.open("x", encoding="utf-8") as out:
        json.dump(data, out, indent=2, ensure_ascii=False)
        out.write("\n")


def load(path: Path) -> dict:
    if path.stat().st_size > 4 * 1024 * 1024:
        raise ValueError("Input JSON too large")
    result = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(result, dict):
        raise ValueError("JSON object required")
    return result


def verify_evidence(run: Path, names: list[str]) -> tuple[list[dict], list[str]]:
    found, failures = [], []
    for name in names:
        if not isinstance(name, str) or not name or "\\" in name:
            failures.append("invalid evidence name")
            continue
        parts = name.split("/")
        if any(p in ("", ".", "..") for p in parts) or parts[0] != "evidence":
            failures.append("evidence must be under evidence/ with relative paths only")
            continue
        target = run
        try:
            for part in parts:
                target = target / part
                if target.is_symlink():
                    raise ValueError("evidence symlink rejected")
            if not target.resolve().is_relative_to((run / "evidence").resolve()):
                raise ValueError("evidence escapes run folder")
            if not target.is_file() or not 0 < target.stat().st_size <= 20 * 1024 * 1024:
                raise ValueError("missing, empty or oversized evidence")
            digest = hashlib.file_digest(target.open("rb"), "sha256").hexdigest()
            found.append({"path": name, "sha256": digest, "bytes": target.stat().st_size})
        except (OSError, ValueError) as exc:
            failures.append(name + ": " + str(exc))
    return found, failures


def initialize(output_root: Path) -> Path:
    pin = pin_checkout()
    output_root = output_root.resolve()
    # The accepted default is in ignored TestResults; custom roots are allowed,
    # but still never overwrite an existing directory.
    output_root.mkdir(parents=True, exist_ok=True)
    session = "wpf-g5-g6-" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8]
    run = output_root / session
    run.mkdir()
    (run / "evidence").mkdir()
    new_file(run / "run-info.json", {
        "schemaVersion": 1, "purpose": PURPOSE, "createdUtc": now(),
        "branch": pin["branch"], "sourceSha": pin["sourceSha"],
        "originSha": pin["originSha"],
        "cases": [{"id": cid, "gate": gate, "instruction": label} for cid, gate, label in CASES],
        "fieldQualified": False, "ruleEvidenceAdmitted": False,
    })
    new_file(run / "responses.json", {
        "schemaVersion": 1, "purpose": PURPOSE,
        "responses": [{"id": cid, "status": "not_run", "notes": "", "observedAtUtc": None, "evidence": []}
                      for cid, _, _ in CASES],
    })
    print(json.dumps({"status": "initialized-not-accepted", "directory": str(run),
                      "sourceSha": pin["sourceSha"], "cases": len(CASES),
                      "next": "Observe running WPF on Windows; edit responses.json and save redacted screenshots/logs under evidence/."},
                     indent=2))
    return run


def assess(run: Path, output: Path) -> dict:
    info = load(run / "run-info.json")
    responses = load(run / "responses.json")
    expected = {cid: (gate, label) for cid, gate, label in CASES}
    if info.get("schemaVersion") != 1 or info.get("purpose") != PURPOSE or \
       responses.get("schemaVersion") != 1 or responses.get("purpose") != PURPOSE or \
       info.get("branch") != BRANCH or \
       not HEX40.fullmatch(str(info.get("sourceSha", ""))) or \
       info.get("originSha") != info.get("sourceSha") or \
       [x.get("id") for x in info.get("cases", [])] != list(expected):
        raise ValueError("Unknown acceptance manifest or changed case identity")
    all_rows = responses.get("responses")
    if not isinstance(all_rows, list) or len(all_rows) != len(expected):
        raise ValueError("Missing/extra acceptance responses")
    if [x.get("id") for x in all_rows if isinstance(x, dict)] != list(expected):
        raise ValueError("Response order, IDs or record shape changed")
    try:
        current = pin_checkout()
        source_consistent = current["sourceSha"] == info["sourceSha"]
    except ValueError:
        source_consistent = False
    results = []
    for item in all_rows:
        cid = item["id"]
        status = item.get("status")
        if status not in ALLOWED:
            raise ValueError("Unknown status for " + cid)
        notes = item.get("notes", "")
        names = item.get("evidence", [])
        if not isinstance(notes, str) or not isinstance(names, list) or len(names) > 8:
            raise ValueError("Bad notes/evidence shape for " + cid)
        files, errors = verify_evidence(run, names)
        observed = item.get("observedAtUtc")
        observed_ok = False
        if isinstance(observed, str):
            try:
                date = dt.datetime.fromisoformat(observed.replace("Z", "+00:00"))
                observed_ok = bool(date.tzinfo and date.astimezone(dt.timezone.utc) <= dt.datetime.now(dt.timezone.utc))
            except ValueError:
                pass
        accepted = status == "pass" and len(notes.strip()) >= 15 and observed_ok and bool(files) and not errors
        results.append({
            "id": cid, "gate": expected[cid][0], "status": status,
            "verifiedHumanEvidence": accepted, "evidence": files,
            "reason": None if accepted else (
                "; ".join(errors) if errors else
                "Missing manual PASS, timestamp, descriptive notes (>=15 chars) or hashed evidence")
        })
    by_gate = {gate: "PASS" if source_consistent and all(r["verifiedHumanEvidence"] for r in results if r["gate"] == gate)
               else "NO_GO" for gate in ("G5", "G6")}
    assessment = {
        "schemaVersion": 1, "purpose": PURPOSE + "-assessment",
        "assessedUtc": now(), "sourceSha": info["sourceSha"],
        "checkoutConsistent": source_consistent, "gates": by_gate,
        "releaseDecision": "CANDIDATE_ONLY" if all(x == "PASS" for x in by_gate.values()) else "NO_GO",
        "manualEvidenceAccepted": sum(r["verifiedHumanEvidence"] for r in results),
        "manualEvidenceRequired": len(CASES), "results": results,
        "fieldQualified": False, "ruleEvidenceAdmitted": False,
        "warnings": [
            "Human-submitted evidence is not a machine-verifiable observation of the rendered WPF UI.",
            "Do not equate G5/G6 CANDIDATE_ONLY with full CARTHAGO release, field accuracy or exact-rule qualification.",
            "Source SHA must match a clean unchanged local and tracking checkout when assessing."
        ],
    }
    new_file(output, assessment)
    return assessment


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init")
    init.add_argument("--output-root", type=Path, default=Path("TestResults"))
    finalize = sub.add_parser("assess")
    finalize.add_argument("--run-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "init":
            initialize(args.output_root)
            return 0
        run = args.run_dir.resolve()
        if not run.is_dir() or run.is_symlink():
            raise ValueError("Run directory absent or is a symlink")
        report = assess(run, run / "assessment.json")
        print(json.dumps({"assessment": str(run / "assessment.json"),
                          "sourceSha": report["sourceSha"],
                          "gates": report["gates"],
                          "releaseDecision": report["releaseDecision"],
                          "manualEvidenceAccepted": report["manualEvidenceAccepted"],
                          "required": report["manualEvidenceRequired"]}, indent=2))
        return 0 if report["releaseDecision"] == "CANDIDATE_ONLY" else 2
    except (OSError, ValueError, KeyError) as exc:
        print("BLOCKED: " + str(exc), file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
