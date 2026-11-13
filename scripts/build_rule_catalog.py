#!/usr/bin/env python3
"""Build the source-derived, single-page R-series documentation catalog.

This command inspects source text only. It never builds or runs Carthago.
Use --check to fail when the generated catalog is out of date.
"""

import argparse
import collections
import hashlib
import html
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
REGISTRY = ROOT / "Carthago/Engine/Rules/Catalog/RuleRegistry.cs"
RULE_ROOT = ROOT / "Carthago/Engine/Rules"
BATCH_DIRS = [ROOT / "docs/03-detection-rules/batches", ROOT / "docs"]
CATALOG = ROOT / "docs/03-detection-rules/MASTER_RULE_CATALOG.md"

REGISTRATION = re.compile(r"\bnew\s+(R(?P<id>\d{3,})_[A-Za-z0-9_]+)\s*\(\s*\)")
BATCH = re.compile(r"^RULE_BATCH_(\d{3,})[-_](\d{3,})\.md$")
STRING_FIELD = r'\b{field}\s*:\s*"((?:\\.|[^"\\])*)"'
SEVERITY = re.compile(r"\bDefaultSeverity\s*:\s*SeverityLevel\.(\w+)")
ENABLED = re.compile(r"\bEnabledByDefault\s*:\s*(true|false)\b")


@dataclass(frozen=True)
class Rule:
    identifier: str
    name: str
    category: str
    description: str
    severity: str
    enabled: str
    source: Path
    batch: Path | None
    verification: str


def descriptor_text(source: str) -> str:
    """Return one explicit descriptor initializer; never substitute profile claims."""
    for match in re.finditer(r"\bRuleDescriptor\b", source):
        tail = source[match.end():match.end() + 300]
        candidate = re.search(r"(?:=>|=)\s*new\s*(?:RuleDescriptor)?\s*\(", tail)
        if not candidate:
            continue
        start = match.end() + candidate.end()
        # A descriptor constructor contains no nested code except string literals.
        # Stop at its first `);` boundary, then extract named literal arguments.
        end = source.find(");", start)
        if end != -1:
            return source[start:end]
    return ""


def field(text: str, name: str) -> str:
    match = re.search(STRING_FIELD.format(field=re.escape(name)), text)
    if not match:
        return "Not specified as a literal"
    return re.sub(r"\\([\\\"])", r"\1", match.group(1)).strip()


def positional_descriptor(text: str) -> list[str] | None:
    """Recognize seven literal constructor arguments in older R-series rules."""
    tokens = re.findall(r'"(?:\\.|[^"\\])*"|SeverityLevel\.\w+|\b(?:true|false)\b', text)
    if len(tokens) != 7 or not re.fullmatch(r'"R\d{3,}"', tokens[0]):
        return None
    if not all(tokens[i].startswith('"') for i in (1, 2, 3, 5)):
        return None
    if not tokens[4].startswith("SeverityLevel.") or tokens[6] not in ("true", "false"):
        return None
    return [token[1:-1] if token.startswith('"') else token for token in tokens]


def clean_cell(value: str, limit: int = 170) -> str:
    value = " ".join(value.split()).replace("|", r"\|").replace("[", r"\[").replace("]", r"\]")
    return value if len(value) <= limit else value[:limit - 1].rstrip() + "…"


def batches() -> list[tuple[int, int, Path]]:
    found = []
    for directory in BATCH_DIRS:
        for path in directory.glob("RULE_BATCH_*.md"):
            m = BATCH.match(path.name)
            if m:
                found.append((int(m.group(1)), int(m.group(2)), path))
    return found


def choose_batch(number: int, available: list[tuple[int, int, Path]]) -> Path | None:
    matching = [(stop - start, "_" in path.stem, path) for start, stop, path in available if start <= number <= stop]
    return min(matching)[2] if matching else None


def source_test_status(batch: Path | None) -> str:
    if batch is None:
        return "No batch record"
    text = batch.read_text(encoding="utf-8-sig")[:1200]
    if re.search(r"(?:SOURCE\s+)?CANDIDATE\s*[—-]\s*UNVERIFIED", text, re.IGNORECASE):
        return "Candidate — unverified (reported)"
    if re.search(r"(?:zero|0)\s+(?:tests?\s+)?executed", text, re.IGNORECASE):
        return "0 executed (reported)"
    return "See historical verification record"


def collect_rules() -> list[Rule]:
    registry = REGISTRY.read_text(encoding="utf-8-sig")
    # This literal is the default runtime's registration scope, not the
    # available-rule overlay or any description-only research inventory.
    default = registry.split("public static IReadOnlyList<IDetectionRule> CreateDefaultRules()", 1)[1]
    default = default.split("public static IReadOnlyList<IDetectionRule> CreateAvailableRules()", 1)[0]
    names = [m.group(1) for m in REGISTRATION.finditer(default)]
    if not names:
        raise ValueError("No registered R-series classes found in CreateDefaultRules")
    ids = [int(name.split('_', 1)[0][1:]) for name in names]
    if any(name.split("_", 1)[0] != f"R{number:03d}" for name, number in zip(names, ids)):
        raise ValueError("Noncanonical registered R-series ID")
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate registered RNNN IDs")
    if sorted(ids) != list(range(1, max(ids) + 1)):
        raise ValueError("Gaps in R-series registry; investigate before publishing a complete index")

    indexed = collections.defaultdict(list)
    for file in RULE_ROOT.rglob("*.cs"):
        indexed[file.stem].append(file)
    evidence = batches()
    rules = []
    for name in names:
        source_files = indexed.get(name, [])
        if len(source_files) != 1:
            raise ValueError(f"{name}: expected exactly one implementation, got {len(source_files)}")
        source = source_files[0]
        desc = descriptor_text(source.read_text(encoding="utf-8-sig"))
        if not desc:
            raise ValueError(f"{name}: no explicit RuleDescriptor initializer found")
        identifier = name.split('_', 1)[0]
        positional = positional_descriptor(desc)
        explicit_id = positional[0] if positional else field(desc, "RuleId")
        if explicit_id != identifier:
            raise ValueError(f"{name}: descriptor ID {explicit_id!r} differs from registration {identifier}")
        severity = SEVERITY.search(desc)
        enabled = ENABLED.search(desc)
        batch = choose_batch(int(identifier[1:]), evidence)
        rules.append(Rule(
            identifier, positional[1] if positional else field(desc, "Name"),
            positional[2] if positional else field(desc, "Category"),
            positional[3] if positional else field(desc, "Description"),
            positional[4].removeprefix("SeverityLevel.") if positional else (severity.group(1) if severity else "Not statically specified"),
            positional[6] if positional else (enabled.group(1) if enabled else "Not statically specified"),
            source, batch, source_test_status(batch),
        ))
    return sorted(rules, key=lambda r: int(r.identifier[1:]))


def relative_link(target: Path, label: str) -> str:
    return f"[{clean_cell(label, 100)}]({os.path.relpath(target, CATALOG.parent).replace(os.sep, '/')})"


def generate(rules: list[Rule], source_revision: str) -> str:
    by_category = collections.defaultdict(list)
    for rule in rules:
        by_category[rule.category].append(rule)
    lines = [
        "# Carthago — master detection-rule catalog", "",
        f"**Source-content digest:** `{source_revision}` · **Registered:** {len(rules)} unique R-series rules (`{rules[0].identifier}`–`{rules[-1].identifier}`)", "",
        "This is the **single central navigation catalog** for registered detection rules. Metadata is extracted from each rule's actual C# `RuleDescriptor` at the cited snapshot. Source registration is not proof that telemetry can reach the predicate, an alert is emitted, tests passed, or detection quality was field-validated.", "",
        "**Verification column:** a candidate or zero-execution label is quoted from the linked batch's opening record; otherwise consult the dated batch and [development verification ledger](../DEVELOPMENT_VALIDATION_LEDGER.md). No application tests were run to generate this catalog. The original batch reports remain the authoritative historical evidence.", "",
        "[All detection documentation](README.md) · [Rule documentation standard](../rules/RULE_DOCUMENTATION_STANDARD.md) · [Rule hardening progress](../RULE_HARDENING_PROGRESS.md) · [Research backlog](../rules/PROTOCOL_INFORMED_THREAT_BACKLOG.md)", "",
        "## Categories", "", "| Detection category | Registered rules |", "| --- | ---: |",
    ]
    for category, records in sorted(by_category.items(), key=lambda item: item[0].lower()):
        slug = re.sub(r"[^a-z0-9]+", "-", f"{category}-{len(records)}-rules".lower()).strip("-")
        lines.append(f"| [{clean_cell(category)}](#{slug}) | {len(records)} |")
    lines.extend(["", "## Browse rule documentation", "", "Select a category below, then expand any rule to view its documentation **on this page**. GitHub supports these native expandable sections without JavaScript. Use the category links above to jump directly to a group. Each entry is generated from its C# descriptor, with links to the authoritative batch evidence; authored tests are not proof of test execution.", ""])
    for category, records in sorted(by_category.items(), key=lambda item: item[0].lower()):
        lines.extend([f"### {category}: {len(records)} rules", "", "<details>", f"<summary>Choose a rule from {len(records)} {html.escape(category)} entries</summary>", ""])
        for rule in records:
            if rule.batch:
                batch = relative_link(rule.batch, rule.batch.stem.replace("RULE_BATCH_", ""))
            elif 273 <= int(rule.identifier[1:]) <= 544:
                batch = "[Selected rule overview](guides/R273_R544_SelectedRules.md) — no batch GA"
            else:
                batch = "Not located"
            lines.extend([
                "<details>",
                f"<summary><strong>{rule.identifier} — {html.escape(rule.name)}</strong> · {html.escape(rule.severity)}</summary>",
                "",
                f"- **Description:** {html.escape(rule.description)}",
                f"- **Category:** {html.escape(rule.category)}",
                f"- **Severity:** {html.escape(rule.severity)}",
                f"- **Enabled by default:** {html.escape(rule.enabled)}",
                f"- **Implementation:** {relative_link(rule.source, 'C# source')}",
                f"- **Detailed evidence and test scenarios:** {batch}",
                f"- **Verification record:** {html.escape(rule.verification)}",
                "",
                "</details>", "",
            ])
        lines.extend(["</details>", ""])
    missing = [rule.identifier for rule in rules if rule.batch is None]
    lines.extend(["## Evidence coverage notes", ""])
    if missing:
        lines.append("No direct `RULE_BATCH_*` page was located for: " + ", ".join(missing) + ". Consult the [selected historical rule guide](guides/R273_R544_SelectedRules.md) where applicable. Missing documentation is not evidence that a rule is absent or untested.")
    else:
        lines.append("Every registered rule maps to at least one historical batch page. That is evidence of documentation coverage only, not validation.")
    lines.extend(["", "**Refresh:** run `python3 scripts/build_rule_catalog.py` from the repository root after a rule GA, followed by `python3 scripts/build_docs_index.py` and the static `python3 scripts/check_docs_links.py` inspection. This is source-only and does not run Carthago tests.", ""])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="Read-only check of generated catalog freshness")
    args = parser.parse_args()
    rules = collect_rules()
    digest = hashlib.sha256()
    for file in [REGISTRY, *(rule.source for rule in rules)]:
        digest.update(file.relative_to(ROOT).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(file.read_bytes())
        digest.update(b"\0")
    revision = digest.hexdigest()[:20]
    text = generate(rules, revision)
    if args.check:
        if not CATALOG.exists() or CATALOG.read_text(encoding="utf-8") != text:
            print(f"STALE: {CATALOG.relative_to(ROOT)} is missing or differs from the current registered source", file=sys.stderr)
            return 1
        print(f"CURRENT: {len(rules)} registered rules; catalog matches HEAD source snapshot")
        return 0
    CATALOG.write_text(text, encoding="utf-8")
    by_category = collections.Counter(rule.category for rule in rules)
    missing = [rule.identifier for rule in rules if not rule.batch]
    print(f"Cataloged {len(rules)} IDs in {len(by_category)} categories. Missing batch pages: {', '.join(missing) if missing else 'none'}")
    print(f"Wrote {CATALOG.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
