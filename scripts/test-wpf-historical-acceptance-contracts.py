#!/usr/bin/env python3
"""Offline source-only contract tests; no Windows GUI, capture or detector runs."""
from __future__ import annotations

import csv
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent


def module(path: str, name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Cannot load source module")
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj


WPF = module("wpf-operational-acceptance.py", "wpf_acceptance")
HIST = module("reconcile-historical-trx-backlog.py", "historical_reconciliation")
LOGS = module("inspect-historical-original-run-logs.py", "original_log_inspector")
GOOD_SHA = "a" * 40
OTHER_SHA = "b" * 40
TRX_HASH = "c" * 64


class AcceptanceContract(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.checkout = {"branch": WPF.BRANCH, "sourceSha": GOOD_SHA,
                         "originSha": GOOD_SHA, "clean": True}
        self.pin_patch = patch.object(WPF, "pin_checkout", return_value=self.checkout)
        self.pin_patch.start()
        self.addCleanup(self.pin_patch.stop)

    def test_no_go_by_default(self):
        run = WPF.initialize(self.dir)
        report = WPF.assess(run, run / "assessment-a.json")
        self.assertEqual(report["releaseDecision"], "NO_GO")
        self.assertEqual(report["manualEvidenceAccepted"], 0)
        self.assertEqual(report["manualEvidenceRequired"], 16)
        self.assertFalse(report["fieldQualified"])
        self.assertFalse(report["ruleEvidenceAdmitted"])

    def _fill(self, run: Path):
        record = WPF.load(run / "responses.json")
        for row in record["responses"]:
            item = run / "evidence" / (row["id"] + ".txt")
            item.write_text("redacted original WPF observation for " + row["id"], encoding="utf-8")
            row.update({"status": "pass", "notes": "Observed expected behavior on the live Windows WPF application",
                        "observedAtUtc": WPF.now(), "evidence": ["evidence/" + item.name]})
        (run / "responses.json").write_text(json.dumps(record), encoding="utf-8")

    def test_all_pass_uses_hashed_human_evidence_and_respects_original(self):
        run = WPF.initialize(self.dir)
        self._fill(run)
        result = WPF.assess(run, run / "assessment-a.json")
        self.assertEqual(result["releaseDecision"], "CANDIDATE_ONLY")
        self.assertEqual(result["gates"]["G5"], "PASS")
        self.assertEqual(result["gates"]["G6"], "PASS")
        self.assertEqual(result["manualEvidenceAccepted"], 16)
        self.assertEqual(result["results"][0]["evidence"][0]["sha256"],
                         WPF.hashlib.sha256((run / "evidence" / "G5-01.txt").read_bytes()).hexdigest())
        with self.assertRaises(FileExistsError):
            WPF.assess(run, run / "assessment-a.json")

    def test_rejects_unsafe_evidence_and_changed_checkout(self):
        run = WPF.initialize(self.dir)
        self._fill(run)
        responses = WPF.load(run / "responses.json")
        responses["responses"][0]["evidence"] = ["../not-an-original.txt"]
        (run / "responses.json").write_text(json.dumps(responses), encoding="utf-8")
        self.assertEqual(WPF.assess(run, run / "assessment-b.json")["releaseDecision"], "NO_GO")
        self.pin_patch.stop()
        with patch.object(WPF, "pin_checkout", return_value={
            "branch": WPF.BRANCH, "sourceSha": OTHER_SHA, "originSha": OTHER_SHA, "clean": True
        }):
            self.assertEqual(WPF.assess(run, run / "assessment-c.json")["releaseDecision"], "NO_GO")

    def test_record_only_with_real_evidence_and_checkout(self):
        run = WPF.initialize(self.dir)
        with self.assertRaises(ValueError):
            WPF.record_observation(run, "G5-01", "pass", "Observed real UI navigation", ["evidence/missing.png"])
        with self.assertRaises(ValueError):
            WPF.record_observation(run, "G5-99", "pass", "Observed real UI navigation", [])
        actual = run / "evidence" / "G5-01-observed.txt"
        actual.write_text("Redacted observation, actual WPF operator notes", encoding="utf-8")
        status = WPF.record_observation(run, "G5-01", "pass",
                                        "Actual WPF opened and key controls rendered correctly",
                                        ["evidence/G5-01-observed.txt"])
        self.assertEqual(status["hashVerifiedEvidenceFiles"], 1)
        self.assertFalse(status["acceptanceGranted"])
        updated = WPF.load(run / "responses.json")
        self.assertEqual(updated["responses"][0]["status"], "pass")
        self.assertEqual(WPF.assess(run, run / "assessment-record.json")["releaseDecision"], "NO_GO")

    def test_rejects_unknown_case_id(self):
        run = WPF.initialize(self.dir)
        data = WPF.load(run / "responses.json")
        data["responses"][0]["id"] = "G5-99"
        (run / "responses.json").write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaises(ValueError):
            WPF.assess(run, run / "assessment-d.json")


class HistoricalContract(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.linked = [f"originals/root-001/test-suite/known-{i:02}.trx" for i in range(6)]
        self.rows = []
        for index, path in enumerate(self.linked):
            self.rows.append({
                "relativeCopy": path, "trxSha256": TRX_HASH,
                "sourceShaRunnerLinkedToTrx": GOOD_SHA if index < 3 else None,
                "reportCountersMatchOriginalTrx": index < 3,
                "originalArtifactStatus": "original-hash-verified",
                "originalTrxDefinitions": {"status": "parsed", "total": 3, "passed": 3, "failed": 0}
            })
        for index in range(36):
            self.rows.append({
                "relativeCopy": f"originals/root-002/extra/batch-{index:02}.trx",
                "trxSha256": TRX_HASH, "sourceShaRunnerLinkedToTrx": None,
                "originalArtifactStatus": "original-hash-verified",
                "originalTrxDefinitions": {"status": "parsed", "total": 10,
                                          "passed": 9 if index < 7 else 10,
                                          "failed": 1 if index < 7 else 0},
                "pathShaHintsUnverified": ["deadbeef"]
            })
        self.v4 = {"purpose": HIST.V4_PURPOSE, "summary": {"originalTrxCount": 42},
                   "trxRuns": self.rows}
        self.integration = {
            "purpose": "read-only-historical-Windows-integration-provenance-reconciliation",
            "sourceShaBindings": [
                {"trxRelativeCopy": self.linked[i], "trxSha256": TRX_HASH,
                 "runnerDeclaredSourceSha": GOOD_SHA, "sourceIdentityLevel": "runner-report-linked",
                 "evidenceAdmitted": False} for i in (3, 4)
            ]
        }
        self.active = {
            "purpose": "read-only-original-active-sensor-evidence-reconciliation",
            "reports": [
                {"reportRelativeCopy": self.linked[5].rsplit("/",1)[0]+"/qualification.json",
                 "trxSha256": TRX_HASH, "sourceShaRunnerLinkedToTrx": GOOD_SHA,
                 "status": "historical-synthetic-active-source-run-linked",
                 "checks": {"reportCopy": True}}
            ]
        }
        # Active proof path must be exactly the expected active-sensors.trx.
        self.linked[5] = self.linked[5].rsplit("/",1)[0] + "/active-sensors.trx"
        self.rows[5]["relativeCopy"] = self.linked[5]
        self.ledger = self.dir / "linked.csv"
        keys = ["original_recovered_trx","runner_declared_source_sha","original_trx_sha256",
                "executed","passed","failed","source_link_level",
                "field_qualified","current_sha_qualified","formally_admitted"]
        with self.ledger.open("w", encoding="utf-8", newline="") as out:
            writer = csv.DictWriter(out, fieldnames=keys)
            writer.writeheader()
            for path in self.linked:
                writer.writerow({
                    "original_recovered_trx":path, "runner_declared_source_sha":GOOD_SHA,
                    "original_trx_sha256":TRX_HASH, "executed":3,"passed":3,"failed":0,
                    "source_link_level":"historical_runner_report_linked",
                    "field_qualified":"false","current_sha_qualified":"false",
                    "formally_admitted":"false"
                })

    def test_six_linked_thirty_six_unlinked_and_failures_preserved(self):
        linked = HIST.load_linkage(self.ledger, self.v4, self.integration, self.active)
        self.assertEqual(len(linked), 6)
        rows = HIST.triage(self.v4, linked)
        self.assertEqual(len(rows), 42)
        self.assertEqual(sum(r["sourceSha"] is None for r in rows), 36)
        self.assertEqual(sum(r["priority"] == "P1_FAILURE_INVESTIGATION" for r in rows), 7)
        self.assertTrue(all(r["newEvidenceAdmitted"] is False for r in rows))

    def test_rejects_tampered_runner_hash(self):
        self.rows[0]["trxSha256"] = "d" * 64
        with self.assertRaises(ValueError):
            HIST.load_linkage(self.ledger, self.v4, self.integration, self.active)

    def test_log_proximity_does_not_attest(self):
        self.assertTrue(LOGS.same_run_family(
            "originals/root-001/Verification/run-1/carthago-tests.trx",
            "originals/root-001/Verification/run-1/local-logs/tests.log"))
        self.assertFalse(LOGS.same_run_family(
            "originals/root-001/Verification/run-1/carthago-tests.trx",
            "originals/root-001/Verification/run-2/local-logs/tests.log"))
        self.assertFalse(LOGS.same_run_family(
            "originals/root-001/CLI/other.trx",
            "originals/root-002/CLI/other.log"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
