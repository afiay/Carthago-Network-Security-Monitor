#!/usr/bin/env python3
"""Capture a local Git checkout before TRX execution and bind its resulting artifact.

This is a local declaration, NOT independently attested runner provenance.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

SHA = re.compile(r"[0-9a-f]{40}\\Z")
MAX_TRX_BYTES = 16 * 1024 * 1024

def git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(repo), *args], check=True,
                            capture_output=True, text=True, timeout=20)
    return result.stdout.strip()

def snapshot(repo: Path) -> dict:
    sha = git(repo, "rev-parse", "--verify", "HEAD")
    tree = git(repo, "rev-parse", "--verify", "HEAD^{tree}")
    if not SHA.fullmatch(sha) or not SHA.fullmatch(tree):
        raise ValueError("Invalid Git commit/tree SHA")
    if git(repo, "status", "--porcelain", "--untracked-files=normal"):
        raise ValueError("Checkout is not clean; cannot declare source provenance")
    return {"executionSourceSha": sha, "executionTreeSha": tree}

def unique_json(path: Path) -> dict:
    def pairs(items):
        obj = {}
        for key, value in items:
            if key in obj:
                raise ValueError("Duplicate JSON key")
            obj[key] = value
        return obj
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=pairs)

def begin(repo: Path, output: Path) -> None:
    record = {"schemaVersion": 1, "phase": "before-execution",
              **snapshot(repo), "sourceShaAttested": False}
    with output.open("x", encoding="utf-8") as stream:
        json.dump(record, stream, indent=2)
        stream.write("\\n")

def finish(repo: Path, before: Path, trx: Path, output: Path) -> None:
    record = unique_json(before)
    if not isinstance(record, dict) or set(record) != {
        "schemaVersion", "phase", "executionSourceSha", "executionTreeSha", "sourceShaAttested"
    } or record["schemaVersion"] != 1 or record["phase"] != "before-execution" or record["sourceShaAttested"] is not False:
        raise ValueError("Invalid before-execution record")
    current = snapshot(repo)
    if any(record.get(key) != value for key, value in current.items()):
        raise ValueError("Checkout changed between before/after snapshots")
    if not trx.is_file() or not 0 < trx.stat().st_size <= MAX_TRX_BYTES:
        raise ValueError("Missing, empty or oversized TRX")
    digest = hashlib.sha256(trx.read_bytes()).hexdigest()
    # Compatible with inspect-original-trx-rule-cases.py --execution-manifest.
    manifest = {"schemaVersion": 1, "originalTrxSha256": digest,
                "executionSourceSha": current["executionSourceSha"]}
    with output.open("x", encoding="utf-8") as stream:
        json.dump(manifest, stream, indent=2)
        stream.write("\\n")

def self_test() -> None:
    import tempfile
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        (root / "tracked.txt").write_text("baseline", encoding="utf-8")
        subprocess.run(["git", "-C", str(root), "add", "tracked.txt"], check=True)
        subprocess.run(["git", "-C", str(root), "-c", "user.name=Fixture",
                        "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture"], check=True)
        before = root.parent / (root.name + "-before.json")
        after = root.parent / (root.name + "-after.json")
        trx = root.parent / (root.name + "-original.trx")
        try:
            begin(root, before)
            trx.write_bytes(b"<TestRun/>")
            finish(root, before, trx, after)
            assert unique_json(after)["originalTrxSha256"] == hashlib.sha256(trx.read_bytes()).hexdigest()
            (root / "tracked.txt").write_text("changed", encoding="utf-8")
            try:
                finish(root, before, trx, root.parent / (root.name + "-rejected.json"))
            except ValueError:
                pass
            else:
                raise AssertionError("Dirty checkout accepted")
        finally:
            for path in (before, after, trx):
                path.unlink(missing_ok=True)
    print(json.dumps({"selfTest": "passed", "evidenceAttested": False}))

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--before", type=Path)
    parser.add_argument("--trx", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
    elif args.before is None and args.trx is None and args.output is not None:
        begin(args.repo, args.output)
    elif args.before is not None and args.trx is not None and args.output is not None:
        finish(args.repo, args.before, args.trx, args.output)
    else:
        parser.error("Use --output for begin, or --before --trx --output for finish")

if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        print("BLOCKED: " + str(error), file=sys.stderr)
        sys.exit(3)
