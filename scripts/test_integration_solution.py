#!/usr/bin/env python3
"""Static solution integration contract; no application execution."""
import re
import unittest
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent.parent
EXPECTED = {"Carthago", "Carthago.Tests", "Carthago.Benchmarks",
            "Carthago.Contracts", "Carthago.Core", "Carthago.Cli",
            "Carthago.Cli.Tests", "Carthago.Monitor"}

class IntegrationSolutionContract(unittest.TestCase):
    def test_projects_and_configurations(self):
        text = (ROOT / "DOTNET.sln").read_text(encoding="utf-8-sig")
        entries = re.findall(r'^Project\("\{[^}]+\}"\) = "([^"]+)", "([^"]+)", "(\{[^}]+\})"$', text, re.M)
        self.assertEqual(EXPECTED, {name for name, _, _ in entries})
        self.assertEqual(len(EXPECTED), len(entries))
        self.assertEqual(len(entries), len({guid for _, _, guid in entries}))
        for name, path, guid in entries:
            self.assertEqual(f"{name}/{name}.csproj", path.replace("\\", "/"))
            self.assertTrue((ROOT / path.replace("\\", "/")).is_file())
            for configuration in ("Debug", "Release"):
                for key in ("ActiveCfg", "Build.0"):
                    self.assertIn(f"{guid}.{configuration}|Any CPU.{key} = {configuration}|Any CPU", text)

    def test_project_references_are_in_solution(self):
        for name in EXPECTED:
            project = ROOT / name / f"{name}.csproj"
            for ref in ET.parse(project).getroot().iter("ProjectReference"):
                target = (project.parent / ref.attrib["Include"].replace("\\", "/")).resolve()
                self.assertTrue(target.is_file(), str(target))
                self.assertIn(target.parent.name, EXPECTED)

if __name__ == "__main__":
    unittest.main()
