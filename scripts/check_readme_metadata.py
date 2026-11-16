#!/usr/bin/env python3
"""Check root README version badges against checked-in project versions.

Static metadata check only: does not build, execute tests, or certify a release.
"""
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent.parent

def prop(project: str, name: str) -> str:
    element = ET.parse(ROOT / project).find(f".//{name}")
    if element is None or not element.text:
        raise ValueError(f"Missing {name} in {project}")
    return element.text.strip()

def package(project: str, name: str) -> str:
    for element in ET.parse(ROOT / project).findall(".//PackageReference"):
        if element.get("Include") == name and element.get("Version"):
            return element.get("Version")
    raise ValueError(f"Missing {name} version in {project}")

def main() -> int:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    cli = prop("Carthago.Cli/Carthago.Cli.csproj", "Version")
    desktop_tfm = prop("Carthago/Carthago.csproj", "TargetFramework")
    cli_tfm = prop("Carthago.Cli/Carthago.Cli.csproj", "TargetFramework")
    sharp = package("Carthago/Carthago.csproj", "SharpPcap")
    xunit = package("Carthago.Tests/Carthago.Tests.csproj", "xunit")
    catalog = (ROOT / "docs/03-detection-rules/MASTER_RULE_CATALOG.md").read_text(encoding="utf-8")
    match = re.search(r"\*\*Registered:\*\*\s*(\d+)\s+unique R-series", catalog)
    if not match:
        raise ValueError("Cannot obtain registered rule count from catalog")
    count = match.group(1)
    must = {
        "CLI badge": f"img.shields.io/badge/CLI-v{cli}-",
        ".NET badge": f"img.shields.io/badge/.NET-{cli_tfm.removeprefix('net')}-",
        "SharpPcap badge": f"img.shields.io/badge/SharpPcap-{sharp}-",
        "Rule count badge": f"img.shields.io/badge/rules-{count}%20registered-",
        "CLI table": f"**v{cli}**, `{cli_tfm}`",
        "Desktop table": f"`{desktop_tfm}`",
        "xUnit table": f"xUnit **{xunit}**",
        "Current status link": "(docs/CURRENT_STATUS.md)",
        "CI disclosure": "manual and owner-gated",
        "CLI permission flag": "`--authorized-test-time`",
        "CLI JSON flag": "`--json`",
        "Desktop release limitation": "no explicitly declared product version",
    }
    errors = [f"{label}: expected {needle!r}" for label, needle in must.items() if needle not in readme]
    for error in errors:
        print(f"FAIL: {error}", file=sys.stderr)
    if errors:
        return 1
    print(f"PASS: README badges/versions match source: CLI v{cli}, {desktop_tfm}, SharpPcap {sharp}, xUnit {xunit}, {count} IDs")
    print("Documentation only; not release or test qualification")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
