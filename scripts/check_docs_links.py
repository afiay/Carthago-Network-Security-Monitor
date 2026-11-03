#!/usr/bin/env python3
"""Static local Markdown-link audit; never invokes application tests.

Usage: python3 scripts/check_docs_links.py [--json] [--ignore FILE]
The optional ignore file is a JSON array of original source/target pairs.
"""

import argparse
import json
import re
import subprocess
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parent.parent
INLINE = re.compile(r"!?\[[^\]]*\]\(\s*(?:<([^>]+)>|([^\s)]+))")
REFERENCE = re.compile(r"^\s*\[[^\]]+\]:\s*(?:<([^>]+)>|(\S+))", re.MULTILINE)
HTML = re.compile(r"\b(?:href|src)\s*=\s*['\"]([^'\"]+)['\"]")


def tracked_markdown():
    names = subprocess.check_output(
        ["git", "ls-files", "--cached", "--", "*.md", "*.mdx"], cwd=ROOT, text=True
    ).splitlines()
    return sorted((ROOT / p for p in names if (ROOT / p).exists()))


def links(text):
    for regex in (INLINE, REFERENCE, HTML):
        for match in regex.finditer(text):
            yield next(v for v in match.groups() if v is not None)


def inspect():
    invalid = []
    visited = 0
    for filename in tracked_markdown():
        relative = filename.relative_to(ROOT).as_posix()
        for raw in links(filename.read_text(encoding="utf-8-sig")):
            if raw.startswith(("#", "//")):
                continue
            parts = urlsplit(raw)
            if parts.scheme or not parts.path or parts.path.startswith("/"):
                continue
            visited += 1
            target = (filename.parent / unquote(parts.path)).resolve()
            if not target.is_relative_to(ROOT):
                continue
            if not target.exists():
                invalid.append({"source": relative, "target": raw})
    return {"files": len(tracked_markdown()), "links": visited, "broken": invalid}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--ignore", type=Path)
    args = parser.parse_args()
    result = inspect()
    ignored = set()
    if args.ignore:
        ignored = {(v["source"], v["target"]) for v in json.loads(args.ignore.read_text())}
    new = [e for e in result["broken"] if (e["source"], e["target"]) not in ignored]
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Markdown: {result['files']} | Local links: {result['links']} | Broken: {len(result['broken'])} | New: {len(new)}")
        for item in new[:80]:
            print(f"  {item['source']} -> {item['target']}")
    return 1 if new else 0


if __name__ == "__main__":
    raise SystemExit(main())
