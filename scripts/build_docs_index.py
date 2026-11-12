#!/usr/bin/env python3
"""Regenerate Carthago's Markdown documentation indexes after a new GA.

This is documentation-only and does not inspect or execute product tests.
"""

import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
SECTIONS = [
    ("01-getting-started", "Getting started", "Installation context, initial workflow and a safe guided demonstration."),
    ("02-architecture", "Architecture", "System boundaries, evidence lineage, sensors and architectural constraints."),
    ("03-detection-rules", "Detection rules", "Rule-authoring contracts, catalog guides, content packs and every historical rule batch."),
    ("04-protocols", "Protocols", "Research inputs and protocol-GA decision history; not a claim of supported decoders."),
    ("05-detection-quality", "Detection quality", "Accuracy strategy, replay coverage, holdout methodology and verification evidence."),
    ("06-development", "Development", "Engineering processes, reliability changes, source-candidate guidance and change plans."),
    ("07-design", "Design", "Design principles, interface workspaces, plans and current UI implementation ledger."),
    ("08-operations", "Operations", "Runtime storage, journaling, evidence export and investigation workflows."),
    ("09-integrations", "Integrations", "External sinks, telemetry integrations and interoperability guidance."),
    ("10-reference", "Reference", "Path-stable contracts, provenance assets and a history of moved documentation paths."),
    ("archive", "Archive", "Superseded or chronological UI implementation notes retained for traceability."),
]
SUBTITLES = {
    ".": "Guides and reports", "batches": "Rule-batch evidence", "guides": "Engineering guides",
    "content-packs": "Content packs", "research": "Protocol research GAs",
    "ga-evidence": "Producer and integration GAs", "verification-history": "Verification history",
    "holdout": "Holdout methodology", "contracts": "Detection-quality contracts",
    "engineering": "Reliability and engineering", "roadmap": "Roadmap",
    "ui-history": "Historical UI iterations",
}


def label(file):
    # Stable, sortable IDs are more useful than transcribed/occasionally stale document headings.
    return file.stem.replace("_", " ").replace("-", "–")


def list_documents(directory, location):
    groups = {}
    for file in directory.rglob("*.md"):
        if file.name == "README.md":
            continue
        relative = file.relative_to(directory)
        archive = ARCHIVE_GROUPS.get(location)
        if archive and relative.parts[0] == archive[0]:
            continue
        groups.setdefault(str(relative.parent), []).append(relative)
    lines = []
    for group, files in sorted(groups.items(), key=lambda v: (v[0] != ".", v[0])):
        lines.extend([f"## {SUBTITLES.get(group, group.replace('-', ' ').title())}", ""])
        for rel in sorted(files, key=lambda p: p.name):
            lines.append(f"- [{label(rel)}]({rel.as_posix()})")
        lines.append("")
    if not groups and location not in ARCHIVE_GROUPS:
        lines.append("Documents for this topic will be linked here when added.\n")
    return lines


EXTRA = {
    "01-getting-started": [
        "## First run", "",
        "- [Prerequisites, setup and quick start](../../README.md#quick-start)",
        "- [Configuration and local secrets](../../README.md#configuration)",
        "- [Runtime files and persistence](../08-operations/runtime-data.md)", "",
    ],
    "03-detection-rules": [
        "## Working source of truth", "",
        "- **[Master detection-rule catalog](MASTER_RULE_CATALOG.md)** — every registered RNNN rule, direct source links and historical evidence",
        "- [Rule hardening progress ledger](../RULE_HARDENING_PROGRESS.md)",
        "- [Rule documentation standard](../rules/RULE_DOCUMENTATION_STANDARD.md)",
        "- [Content-pack overview](content-packs/README.md)",
        "- [Detection expansion cursor](../rules/DETECTION_EXPANSION_CANDIDATE_CURSOR_20261103.md)",
        "- [Unified 2,500-rule admission cursor](../rules/UNIFIED_2500_RULE_ADMISSION_CURSOR.md)",
        "- [Protocol-informed backlog](../rules/PROTOCOL_INFORMED_THREAT_BACKLOG.md)",
        "", "The master catalog is the central entry point; batch files remain historical *source-candidate evidence*, not proof of a green runtime or holdout. Two separate R001–R005 documents were retained because they represent distinct historical records. Active automations may initially write new batches at the original `docs/RULE_BATCH_*` paths; the catalog links those too.", "",
    ],
    "04-protocols": [
        "## Current status", "", "- [Protocol expansion progress ledger](../protocols/PROTOCOL_EXPANSION_PROGRESS.md)",
        "", "P0001–P0500 are research/GA entries, not 500 separate implemented packet decoders. They inform normal RNNN detection-rule development.", "",
    ],
    "05-detection-quality": [
        "## Verification and immutable evidence", "",
        "- [Current development verification ledger](../DEVELOPMENT_VALIDATION_LEDGER.md)",
        "- [Frozen V1 manifest](../holdout-evaluation-manifest.json)",
        "- [V2 manifest](../holdout-evaluation-v2-manifest.json)",
        "- [R102 frozen holdout telemetry audit](../development/R102_FROZEN_HOLDOUT_TELEMETRY_AUDIT_20261029.md)",
        "- [Development verification records](../development/)", "",
        "Never reinterpret an authored test as an executed test. Holdout V1 remains immutable.", "",
    ],
    "06-development": [
        "## Ongoing development records", "",
        "- [Development verification GAs](../development/)",
        "- [Design specifications and implementation plans](../superpowers/)",
        "- [Indexed verification records, plans and specifications](../10-reference/WORKFLOW_ANCHORS.md)",
        "- [Development validation ledger](../DEVELOPMENT_VALIDATION_LEDGER.md)", "",
    ],
    "07-design": [
        "## Live UI development", "",
        "- [UI implementation ledger](../design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md)",
        "- [Indexed UI engineering records](../10-reference/WORKFLOW_ANCHORS.md#ui-implementation)",
        "", "The live ledger stays at its existing path so scheduled design work can continue. Historical alignment reports are indexed under [Archive](../archive/README.md).", "",
    ],
    "10-reference": [
        "## Path-stable reference assets", "",
        "- [Stable path register](WORKFLOW_ANCHORS.md)",
        "- [Documentation maintenance standard](DOCUMENTATION_MAINTENANCE.md)",
        "- [Legacy document path map](LEGACY_DOCUMENTATION_PATHS.md)",
        "- [Frozen V1 manifest](../holdout-evaluation-manifest.json)",
        "- [V2 manifest](../holdout-evaluation-v2-manifest.json)",
        "- [V2 provenance schema](../contracts/holdout-v2-private-provenance-v2.schema.json)", "",
    ],
}


CHECK_ONLY = False
STALE = []


def write(path, lines):
    content = "\n".join(lines).rstrip() + "\n"
    if CHECK_ONLY:
        if not path.exists() or path.read_text(encoding="utf-8") != content:
            STALE.append(path.relative_to(ROOT).as_posix())
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


HOME_PATHS = [
    "## Choose your starting point",
    "",
    "| I want to… | Follow this path |",
    "| --- | --- |",
    "| Install and run Carthago | [Quick start](../README.md#quick-start) → [Getting started](01-getting-started/README.md) → [Demo scenario](01-getting-started/demo-scenario.md) |",
    "| Investigate an alert | [Operations](08-operations/README.md) → [Investigation copilot](08-operations/guides/InvestigationCopilot.md) → [Evidence export](08-operations/guides/TimelineAndEvidenceExport.md) |",
    "| Understand the system | [Architecture](02-architecture/README.md) → [Architecture safety rules](02-architecture/ArchitectureSafetyRules.md) → [Runtime data](08-operations/runtime-data.md) |",
    "| Add or review a detection rule | [Detection rules](03-detection-rules/README.md) → [Rule authoring](03-detection-rules/guides/AddingDetectionRules.md) → [Rule documentation standard](rules/RULE_DOCUMENTATION_STANDARD.md) |",
    "| Verify a rule or release | [Detection quality](05-detection-quality/README.md) → [Replay testing](05-detection-quality/guides/ReplayTesting.md) → [Validation ledger](DEVELOPMENT_VALIDATION_LEDGER.md) |",
    "| Develop the application or UI | [Development](06-development/README.md) → [Design](07-design/README.md) → [UI implementation ledger](design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md) |",
    "| Configure a sink or external integration | [Integrations](09-integrations/README.md) → [Configuration](../README.md#configuration) |",
    "",
    "## Documentation status and authority",
    "",
    "| Question | Authoritative record |",
    "| --- | --- |",
    "| What rules are registered? | [Master rule catalog](03-detection-rules/MASTER_RULE_CATALOG.md); the registry source is linked there. |",
    "| What has actually been verified? | [Validation ledger](DEVELOPMENT_VALIDATION_LEDGER.md) and [detection quality](05-detection-quality/README.md); check the exact SHA, scope and outcome. |",
    "| What is still being researched? | [Protocol research ledger](protocols/PROTOCOL_EXPANSION_PROGRESS.md) and [unified rule admission cursor](rules/UNIFIED_2500_RULE_ADMISSION_CURSOR.md). |",
    "| What is being designed or implemented? | [Development records](06-development/README.md) and [UI ledger](design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md). |",
    "| How should documentation be maintained? | [Documentation maintenance standard](10-reference/DOCUMENTATION_MAINTENANCE.md) and [stable paths](10-reference/WORKFLOW_ANCHORS.md). |",
    ""
]

ARCHIVE_GROUPS = {
    "03-detection-rules": ("batches", "Rule-batch evidence", "R", "RULE_BATCH_"),
    "04-protocols": ("research", "Protocol research GAs", "P", "PROTOCOL_GA_P"),
}


def archive_lines(directory, title, prefix, file_prefix):
    """Keep historical navigation compact without moving any evidence file."""
    lines = [f"# {title}", "", "[Topic overview](../README.md) · [Documentation home](../../README.md)", "",
             "Historical records describe their own scope and status. A listed record is not evidence of fresh execution or production readiness.", ""]
    groups = {}
    for file in sorted(directory.glob("*.md"), key=lambda p: p.name):
        if file.name == "README.md":
            continue
        tail = file.stem.removeprefix(file_prefix)
        first = tail.split("-")[0].split("_")[0]
        if file.stem.startswith(file_prefix) and first.isdigit():
            start = (int(first) - 1) // 100 * 100 + 1
            width = 3 if prefix == "R" else 4
            group = (start, f"{prefix}{start:0{width}d}–{prefix}{start + 99:0{width}d} (start IDs)")
        else:
            group = (0, "Reconciliation and other records")
        groups.setdefault(group, []).append(file)
    for (_, heading), files in sorted(groups.items()):
        lines.extend([f"## {heading}", ""])
        for file in files:
            lines.append(f"- [{label(file)}]({file.name})")
        lines.append("")
    return lines


def stable_group_lines():
    """Index every stable working record, including manifests and contracts."""
    groups = [
        ("Live ledgers", [DOCS / "DEVELOPMENT_VALIDATION_LEDGER.md", DOCS / "RULE_HARDENING_PROGRESS.md", DOCS / "protocols/PROTOCOL_EXPANSION_PROGRESS.md"]),
        ("Rule workflow", sorted((DOCS / "rules").rglob("*.md"))),
        ("Development verification", sorted((DOCS / "development").rglob("*.md"))),
        ("UI implementation", sorted((DOCS / "design").rglob("*.md"))),
        ("Engineering plans", sorted((DOCS / "superpowers/plans").rglob("*.md"))),
        ("Engineering specifications", sorted((DOCS / "superpowers/specs").rglob("*.md"))),
        ("Machine-readable evidence contracts", sorted((DOCS / "contracts").rglob("*.json")) + sorted(DOCS.glob("holdout-evaluation*-manifest.json"))),
    ]
    lines = []
    for heading, files in groups:
        lines.extend([f"## {heading}", ""])
        for file in files:
            rel = file.relative_to(DOCS).as_posix()
            lines.append(f"- [{rel}](../{rel})")
        lines.append("")
    return lines


def main():
    global CHECK_ONLY
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Report stale indexes without writing files")
    CHECK_ONLY = parser.parse_args().check
    STALE.clear()
    for folder, title, description in SECTIONS:
        path = DOCS / folder
        lines = [f"# {title}", "", description, "", "[Documentation home](../README.md)", ""]
        lines.extend(EXTRA.get(folder, []))
        lines.extend(list_documents(path, folder))
        if folder in ARCHIVE_GROUPS:
            subfolder, archive_title, prefix, file_prefix = ARCHIVE_GROUPS[folder]
            lines.extend([f"## {archive_title}", "", f"[Browse the complete historical index]({subfolder}/README.md) — grouped by starting ID; all original records are preserved.", ""])
            write(path / subfolder / "README.md", archive_lines(path / subfolder, archive_title, prefix, file_prefix))
        if folder == "03-detection-rules":
            legacy_batches = sorted(DOCS.glob("RULE_BATCH_*.md"))
            if legacy_batches:
                lines.extend(["## New batches pending path normalization", "", "These live automation batch reports are also included in the master catalog, even before they are moved into the categorized batch directory.", ""])
                for batch in legacy_batches:
                    lines.append(f"- [{batch.stem}](../{batch.name})")
                lines.append("")
        write(path / "README.md", lines)

    anchors = [
        "# Stable paths used by development and evidence automation", "",
        "These documents keep their previous locations intentionally. Updating their paths without coordinating the scripts, tests and scheduled jobs would be a breaking interface change. They are canonical, not legacy copies.", "",
    ]
    anchors.extend(stable_group_lines())
    write(DOCS / "10-reference/WORKFLOW_ANCHORS.md", anchors)

    lines = [
        "# Carthago documentation", "",
        "Canonical navigation for users, contributors, security analysts, detection engineers and UI developers.", "",
        "> **Status convention:** Historical GA notes, authored xUnit scenarios and research inventories document what was written or observed at that time. They do **not** imply a fresh successful test run, field validation or production readiness. Read the live ledgers for precise verification state.", "",
    ]
    lines.extend(HOME_PATHS)
    lines.extend(["## Browse by topic", "", "| Area | Contents |", "| --- | --- |"])
    for folder, title, description in SECTIONS:
        lines.append(f"| [{title}]({folder}/README.md) | {description} |")
    lines.extend([
        "", "## Live working records", "",
        "- [Detection-rule hardening](RULE_HARDENING_PROGRESS.md) · [rule expansion cursor](rules/DETECTION_EXPANSION_CANDIDATE_CURSOR_20261103.md) · [rule writing contract](rules/RULE_DOCUMENTATION_STANDARD.md)",
        "- **[All registered detection rules — master catalog](03-detection-rules/MASTER_RULE_CATALOG.md)**",
        "- [Protocol research](protocols/PROTOCOL_EXPANSION_PROGRESS.md)",
        "- [Verification and validation ledger](DEVELOPMENT_VALIDATION_LEDGER.md)",
        "- [UI implementation ledger](design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md)",
        "- [Path-stable work documents](10-reference/WORKFLOW_ANCHORS.md) and [previous locations](10-reference/LEGACY_DOCUMENTATION_PATHS.md)",
        "", "## Where new documents belong", "",
        "Write new user-facing guides under the numbered topic directories. For detection-rule batches, use `docs/03-detection-rules/batches/RULE_BATCH_NNN-NNN.md`; keep one batch page per scope and link it from the progress ledger. The historical batch pages remain immutable evidence except for explicit, traceable corrections.",
        "", "Keep the exact paths of ongoing automation ledgers, `docs/rules/*`, `docs/development/*`, `docs/superpowers/*`, `docs/contracts/*`, holdout manifests and other machine-consumed inputs. See the [stable-path register](10-reference/WORKFLOW_ANCHORS.md).",
        "", "After adding a detection rule, run `python3 scripts/build_rule_catalog.py` and then `python3 scripts/build_docs_index.py` from the repository root. For other documentation changes, run the index generator alone. `python3 scripts/check_docs_links.py` checks links only; it does not execute application tests.",
        "", "## Preservation policy", "",
        "- Original research and verification claims retain their dates, scope and identity; review actual artifacts before elevating them to verified results.",
        "- The frozen V1 holdout remains unchanged; V2 manifests and provenance contracts retain their established paths.",
        "- Every moved path can be traced through [the move map](10-reference/LEGACY_DOCUMENTATION_PATHS.md) and Git history.",
        "- Do not conflate P-series protocol research with R-series registered detection rules, or source candidates with tested detections.",
        "", "[Return to repository overview](../README.md)", "",
    ])
    write(DOCS / "README.md", lines)
    count = len(SECTIONS) + 2 + len(ARCHIVE_GROUPS)
    if CHECK_ONLY:
        if STALE:
            print("Stale documentation indexes:")
            for name in STALE:
                print(f"  {name}")
            return 1
        print(f"Verified {count} documentation indexes are current.")
        return 0
    print(f"Generated {count} documentation indexes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
