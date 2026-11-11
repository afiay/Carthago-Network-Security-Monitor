#!/usr/bin/env python3
"""Portable source-only SOC WPF structure check (not a WPF compiler)."""

from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET


EVENT_ATTRIBUTES = {
    "Click", "SelectionChanged", "PreviewKeyDown", "KeyDown", "Loaded", "Unloaded",
    "TextChanged", "Checked", "Unchecked", "MouseLeftButtonUp", "MouseLeftButtonDown",
    "MouseDoubleClick", "SizeChanged", "ValueChanged", "Navigating", "DropDownClosed",
    "Closing", "CurrentCellChanged", "LostFocus", "PreviewMouseLeftButtonDown",
    "PreviewMouseWheel",
}


def main() -> int:
    source_dir = Path(__file__).resolve().parent.parent / "Carthago"
    xaml_files = sorted(source_dir.rglob("*.xaml"))
    checked_bindings = 0
    errors = []

    for xaml in xaml_files:
        try:
            tree = ET.parse(xaml)
        except ET.ParseError as exc:
            errors.append(f"{xaml}: invalid XML: {exc}")
            continue

        partials = sorted(xaml.parent.glob(xaml.stem + "*.cs"))
        if not partials:
            continue  # Resource dictionary or XAML without paired C# code-behind.
        source = "\n".join(p.read_text(encoding="utf-8-sig", errors="replace") for p in partials)
        for element in tree.iter():
            for name, handler in element.attrib.items():
                if name.split("}")[-1] not in EVENT_ATTRIBUTES:
                    continue
                if not re.fullmatch(r"[A-Za-z_]\w*", handler):
                    continue
                checked_bindings += 1
                if not re.search(r"\b" + re.escape(handler) + r"\s*\(", source):
                    errors.append(f"{xaml}: unresolved source handler {handler}")

    print(f"XAML documents inspected: {len(xaml_files)}")
    print(f"WPF event bindings inspected: {checked_bindings}")
    for error in errors:
        print("ERROR:", error, file=sys.stderr)
    print("Source-only structure:", "PASS" if not errors else "FAIL")
    print("This does not compile XAML or verify Windows runtime behavior.")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
