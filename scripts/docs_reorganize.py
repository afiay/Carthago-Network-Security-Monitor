#!/usr/bin/env python3
"""One-time, deterministic Markdown migration for the 2026-11-03 documentation plan.

Use --dry-run first. The script uses git mv, rewrites relative Markdown links,
and writes a historical path map. It does not run product tests or touch JSON.
"""

import argparse
import os
import posixpath
import re
import subprocess
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parent.parent
INLINE = re.compile(r"(!?\[[^\]]*\]\(\s*)(<[^>]+>|[^\s)]+)")
REFERENCE = re.compile(r"(^\s*\[[^\]]+\]:\s*)(<[^>]+>|\S+)", re.MULTILINE)
HTML = re.compile(r"(\b(?:href|src)\s*=\s*['\"])([^'\"]+)")

ARCHITECTURE = {
    "ArchitectureSafetyRules", "AttackStoryCorrelation", "BaselineEngine",
    "CarthagoV6Vision", "EntityGraphAndRisk", "SensorFleet",
}
RULES = {
    "AddingDetectionRules", "ContentPacks", "DetectionEngineeringModel",
    "R123_R272_SelectedRules", "R273_R544_SelectedRules",
    "ResearchBackedDetectionRules", "RuleMetadata", "RuleOwnedPrecisionDetectorMigration",
    "RulePrecisionProfiles", "RuleProfiles",
}
QUALITY = {"AdvancedPrecisionRuntimeGate", "BenchmarkScorecard", "ReplayTesting"}
OPERATIONS = {"AnalystFeedback", "AutonomousTriage", "HuntingQueries", "InvestigationCopilot", "ResponsePlaybooks", "TimelineAndEvidenceExport"}
ROOT_FILES = {
    "ACCURACY_SCENARIO_STRATEGY.md": "05-detection-quality",
    "BaselineReadiness.md": "05-detection-quality",
    "CATALOG_WIDE_RULE_HARDENING.md": "03-detection-rules",
    "GA_DETECTION_EVIDENCE_PRODUCER_INTEGRATION_20261102.md": "05-detection-quality/ga-evidence",
    "HOLDOUT_AND_FIELD_VALIDATION.md": "05-detection-quality/holdout",
    "HOLDOUT_V2_PROTOCOL.md": "05-detection-quality/holdout",
    "HOLDOUT_V2_SOURCE_REVIEW.md": "05-detection-quality/holdout",
    "R118-R163-evidence-and-replay-matrix.md": "05-detection-quality",
    "RECALL_TUNING.md": "05-detection-quality",
    "REPLAY_COVERAGE_GAPS.md": "05-detection-quality",
    "SESSION_ARCHIVE_EXPORT.md": "08-operations",
    "VERIFICATION_TRIAGE_20261028.md": "05-detection-quality/verification-history",
    "anomaly-first-validation.md": "05-detection-quality",
    "demo-scenario.md": "01-getting-started",
    "elegant-responsive-design.md": "07-design",
    "minimal-dashboard.md": "07-design",
    "package-audit.md": "08-operations",
    "runtime-data.md": "08-operations",
    "threat-feed-workspace.md": "07-design",
}
STABLE_ROOT = {"DEVELOPMENT_VALIDATION_LEDGER.md", "RULE_HARDENING_PROGRESS.md"}


def destination(name):
    if name.startswith("Carthago/docs/"):
        stem = Path(name).stem
        if stem in ARCHITECTURE:
            section = "02-architecture"
        elif stem in RULES:
            section = "03-detection-rules/guides"
        elif stem in QUALITY:
            section = "05-detection-quality/guides"
        elif stem in OPERATIONS:
            section = "08-operations/guides"
        elif stem == "InteropSigmaSuricataZeek":
            section = "09-integrations"
        elif stem == "carthago-design-system-pages":
            section = "07-design"
        else:
            section = "archive/ui-history"
        return f"docs/{section}/{Path(name).name}"
    if not name.startswith("docs/") or not name.endswith(".md"):
        return name
    rel = name[5:]
    if rel in STABLE_ROOT or rel.startswith(("rules/", "development/", "superpowers/", "contracts/")):
        return name
    if rel == "design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md":
        return name
    if rel == "protocols/PROTOCOL_EXPANSION_PROGRESS.md":
        return name
    if rel.startswith("RULE_BATCH_"):
        return f"docs/03-detection-rules/batches/{rel}"
    if rel.startswith("GA_R437_"):
        return f"docs/05-detection-quality/ga-evidence/{rel}"
    if rel.startswith("STAGE6") or rel.startswith("STAGE7"):
        return f"docs/05-detection-quality/verification-history/{rel}"
    if rel.startswith(("soc-", "xaml-compat", "incident-host-vm-")):
        return f"docs/archive/ui-history/{rel}"
    if rel.startswith("ContentPacks/"):
        return f"docs/03-detection-rules/content-packs/{rel.removeprefix('ContentPacks/')}"
    if rel.startswith("protocols/PROTOCOL_GA_"):
        return f"docs/04-protocols/research/{rel.removeprefix('protocols/')}"
    if rel.startswith("detection-quality/"):
        return f"docs/05-detection-quality/contracts/{rel.removeprefix('detection-quality/')}"
    if rel.startswith("engineering/"):
        return f"docs/06-development/engineering/{rel.removeprefix('engineering/')}"
    if rel.startswith("integrations/"):
        return f"docs/09-integrations/{rel.removeprefix('integrations/')}"
    if rel == "design/CARTHAGO_CLI_AVALONIA_FUTURE_ARCHITECTURE.md":
        return "docs/07-design/roadmap/CARTHAGO_CLI_AVALONIA_FUTURE_ARCHITECTURE.md"
    if rel in ROOT_FILES:
        return f"docs/{ROOT_FILES[rel]}/{rel}"
    raise ValueError(f"Unclassified documentation: {name}")


def target_link(url, old_source, new_source, moves):
    angle = url.startswith("<") and url.endswith(">")
    raw = url[1:-1] if angle else url
    if raw.startswith(("#", "//")):
        return url
    parts = urlsplit(raw)
    if parts.scheme or not parts.path or parts.path.startswith("/"):
        return url
    original_target = posixpath.normpath(posixpath.join(posixpath.dirname(old_source), parts.path))
    if original_target.startswith("../"):
        return url
    final_target = moves.get(original_target, original_target)
    if new_source == old_source and final_target == original_target:
        return url
    adjusted = posixpath.relpath(final_target, posixpath.dirname(new_source) or ".")
    if parts.path.endswith("/"):
        adjusted += "/"
    result = urlunsplit(("", "", adjusted, parts.query, parts.fragment))
    return f"<{result}>" if angle else result


def rewrite(data, old, new, moves):
    def replace(match):
        return match.group(1) + target_link(match.group(2), old, new, moves)
    for regex in (INLINE, REFERENCE, HTML):
        data = regex.sub(replace, data)
    return data


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    names = subprocess.check_output(
        ["git", "ls-files", "--cached", "--", "*.md"], cwd=ROOT, text=True
    ).splitlines()
    originals = {name: (ROOT / name).read_bytes() for name in names if (ROOT / name).exists()}
    moves = {name: destination(name) for name in originals if destination(name) != name}
    collisions = set(moves.values()) & (set(originals) - set(moves))
    if len(set(moves.values())) != len(moves) or collisions:
        raise RuntimeError(f"Destination conflicts: {collisions}")
    print(f"Tracked Markdown: {len(originals)}; planned moves: {len(moves)}")
    if args.dry_run:
        for old, new in sorted(moves.items()):
            print(f"{old} -> {new}")
        return

    for old, new in sorted(moves.items()):
        (ROOT / new).parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "mv", "--", old, new], cwd=ROOT, check=True)
    rewritten = 0
    for old, original in originals.items():
        new = moves.get(old, old)
        data = original.decode("utf-8-sig")
        modified = rewrite(data, old, new, moves)
        if modified != data:
            (ROOT / new).write_text(modified, encoding="utf-8", newline="")
            rewritten += 1
    mapping = ROOT / "docs/10-reference/LEGACY_DOCUMENTATION_PATHS.md"
    mapping.parent.mkdir(parents=True, exist_ok=True)
    rows = ["# Legacy documentation paths", "", "This table preserves historical path identity after the 2026-11-03 reorganization. Git history is the evidence record; paths to machine-consumed contracts were not moved.", "", "| Previous repository path | Canonical location |", "| --- | --- |"]
    for old, new in sorted(moves.items()):
        rows.append(f"| `{old}` | [`{new}`](../{new.removeprefix('docs/')}) |")
    mapping.write_text("\n".join(rows) + "\n", encoding="utf-8")
    print(f"Moved {len(moves)} source documents; re-anchored links in {rewritten} Markdown files; map: {mapping.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
