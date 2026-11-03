#!/usr/bin/env python3
"""Regenerate Carthago's Markdown documentation indexes after a new GA.

This is documentation-only and does not inspect or execute product tests.
"""

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
        groups.setdefault(str(relative.parent), []).append(relative)
    lines = []
    for group, files in sorted(groups.items(), key=lambda v: (v[0] != ".", v[0])):
        lines.extend([f"## {SUBTITLES.get(group, group.replace('-', ' ').title())}", ""])
        for rel in sorted(files, key=lambda p: p.name):
            lines.append(f"- [{label(rel)}]({rel.as_posix()})")
        lines.append("")
    if not groups:
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
        "- [Development validation ledger](../DEVELOPMENT_VALIDATION_LEDGER.md)", "",
    ],
    "07-design": [
        "## Live UI development", "",
        "- [UI implementation ledger](../design/CARTHAGO_UI_IMPLEMENTATION_LEDGER.md)",
        "", "The live ledger stays at its existing path so scheduled design work can continue. Historical alignment reports are indexed under [Archive](../archive/README.md).", "",
    ],
    "10-reference": [
        "## Path-stable reference assets", "",
        "- [Stable path register](WORKFLOW_ANCHORS.md)",
        "- [Legacy document path map](LEGACY_DOCUMENTATION_PATHS.md)",
        "- [Frozen V1 manifest](../holdout-evaluation-manifest.json)",
        "- [V2 manifest](../holdout-evaluation-v2-manifest.json)",
        "- [V2 provenance schema](../contracts/holdout-v2-private-provenance-v2.schema.json)", "",
    ],
}


def write(path, lines):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def main():
    for folder, title, description in SECTIONS:
        path = DOCS / folder
        lines = [f"# {title}", "", description, "", "[Documentation home](../README.md)", ""]
        lines.extend(EXTRA.get(folder, []))
        lines.extend(list_documents(path, folder))
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
    anchor_dirs = [DOCS / "rules", DOCS / "development", DOCS / "superpowers", DOCS / "design", DOCS / "protocols"]
    files = [DOCS / "DEVELOPMENT_VALIDATION_LEDGER.md", DOCS / "RULE_HARDENING_PROGRESS.md"]
    for directory in anchor_dirs:
        if directory == DOCS / "design":
            files.extend(p for p in directory.glob("*.md") if p.name == "CARTHAGO_UI_IMPLEMENTATION_LEDGER.md")
        elif directory == DOCS / "protocols":
            files.extend(p for p in directory.glob("*.md") if p.name == "PROTOCOL_EXPANSION_PROGRESS.md")
        else:
            files.extend(directory.rglob("*.md"))
    for file in sorted(files):
        rel = file.relative_to(DOCS).as_posix()
        anchors.append(f"- [{rel}](../{rel})")
    anchors.append("")
    write(DOCS / "10-reference/WORKFLOW_ANCHORS.md", anchors)

    lines = [
        "# Carthago documentation", "",
        "Canonical navigation for users, contributors, security analysts, detection engineers and UI developers.", "",
        "> **Status convention:** Historical GA notes, authored xUnit scenarios and research inventories document what was written or observed at that time. They do **not** imply a fresh successful test run, field validation or production readiness. Read the live ledgers for precise verification state.", "",
        "## Browse by topic", "", "| Area | Contents |", "| --- | --- |",
    ]
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
    print(f"Generated {len(SECTIONS) + 2} topic, reference and root documentation indexes.")


if __name__ == "__main__":
    main()
