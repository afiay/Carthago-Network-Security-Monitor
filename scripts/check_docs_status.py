#!/usr/bin/env python3
"""Check Carthago documentation status overlays; source-only, no test/approval inference."""
from __future__ import annotations
import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REQUIRED = {
    "docs/README.md": ["CURRENT_STATUS.md", "Current verification status:"],
    "scripts/build_docs_index.py": ["CURRENT_STATUS.md", "Current verification status:"],
    "docs/CURRENT_STATUS.md": ["R001–R1000", "14,361/14,361", "0/4", "Exact-ID"],
    "docs/DEVELOPMENT_VALIDATION_LEDGER.md": ["Current-status overlay", "Historical GA verification snapshot"],
    "docs/02-architecture/ActiveSensors.md": ["Current-status overlay", "392/392", "seven"],
    "docs/07-design/roadmap/CARTHAGO_CLI_IMPLEMENTATION.md": ["Current-status overlay", "80 paired replay"],
    "docs/03-detection-rules/batches/RULE_BATCH_001-005.md": ["Historical batch gate"],
    "docs/03-detection-rules/batches/RULE_BATCH_001_005.md": ["Historical batch gate"],
    "docs/05-detection-quality/WINDOWS_EVIDENCE_RECOVERY_20261116.md": ["Reading guide", "same-run"],
    "docs/05-detection-quality/holdout/HOLDOUT_V2_PROTOCOL.md": ["Current-status distinction", "0/4"],
    "docs/08-operations/guides/CARTHAGO_WINDOWS_MONITOR_SERVICE.md": ["Deployment-status interpretation"],
    "docs/08-operations/guides/CARTHAGO_WINDOWS_ACTIVE_SERVICE.md": ["Deployment-status interpretation"],
    "docs/RULE_HARDENING_PROGRESS.md": ["Current-status overlay"],
    "docs/03-detection-rules/MASTER_RULE_CATALOG.md": ["HISTORICAL batch declaration, NOT latest qualification"],
    "scripts/build_rule_catalog.py": ["HISTORICAL batch declaration, NOT latest qualification"],
}

def audit(root: Path) -> list[str]:
    failures: list[str] = []
    for path, markers in REQUIRED.items():
        file = root / path
        if not file.is_file():
            failures.append(f"MISSING {path}")
            continue
        text = file.read_text(encoding="utf-8-sig")
        for marker in markers:
            if marker not in text:
                failures.append(f"STALE {path}: missing {marker!r}")
    return failures

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    failures = audit(args.root.resolve())
    for failure in failures:
        print(failure)
    if failures:
        print(f"FAIL: {len(failures)} documentation status entry-point problem(s)")
        return 1
    print(f"PASS: {len(REQUIRED)} documentation status entry points checked; no tests executed")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
