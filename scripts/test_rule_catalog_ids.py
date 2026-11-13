#!/usr/bin/env python3
"""Regression for the 999 -> 1000 catalog boundary."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import build_rule_catalog as catalog

class RuleCatalogIds(unittest.TestCase):
    def test_thousand_rule_catalog_and_batch(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            rule_root = root / "rules"
            rule_root.mkdir()
            batch = root / "RULE_BATCH_988-1000.md"
            batch.write_text("SOURCE CANDIDATE — UNVERIFIED", encoding="utf-8")
            registry = root / "RuleRegistry.cs"
            names = [f"R{i:03d}_Rule" for i in range(1,1001)]
            registry.write_text(
                "public static IReadOnlyList<IDetectionRule> CreateDefaultRules() {"
                + ",".join(f"new {name}()" for name in names)
                + "} public static IReadOnlyList<IDetectionRule> CreateAvailableRules() {}", encoding="utf-8")
            for i,name in enumerate(names, 1):
                (rule_root / (name + ".cs")).write_text(
                    f'RuleDescriptor Rule = new(RuleId: "R{i:03d}", Name: "Rule", Category: "Test", '
                    'Description: "Fixture", DefaultSeverity: SeverityLevel.Medium, '
                    'ConfigKey: "Test", EnabledByDefault: true);', encoding="utf-8")
            with patch.multiple(catalog, REGISTRY=registry, RULE_ROOT=rule_root, BATCH_DIRS=[root]):
                rules = catalog.collect_rules()
                self.assertEqual(1000,len(rules))
                self.assertEqual(["R999","R1000"], [r.identifier for r in rules[-2:]])
                self.assertEqual(batch, rules[-1].batch)
                self.assertEqual("Candidate — unverified (reported)", rules[-1].verification)
                self.assertEqual("R1000",catalog.REGISTRATION.search("new R1000_Rule()").group(1).split("_")[0])
                self.assertEqual(["R1000","Example","Test","Fixture","Medium","Test","true"],
                    catalog.positional_descriptor('"R1000", "Example", "Test", "Fixture", SeverityLevel.Medium, "Test", true'))
                registry.write_text(registry.read_text(encoding="utf-8").replace("R1000_Rule","R01000_Rule"),encoding="utf-8")
                with self.assertRaisesRegex(ValueError,"Noncanonical"):
                    catalog.collect_rules()

if __name__ == "__main__":
    unittest.main()
