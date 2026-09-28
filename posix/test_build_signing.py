"""Offline checks for the macOS Panel.app signing boundary."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import build


DETAILS = ("Identifier=com.openabstractions.panel\n"
           "CodeDirectory v=20500 flags=0x10000(runtime)\n"
           "Authority=Developer ID Application: Fixture (TEAM)\n"
           "Timestamp=26 Sep 2026 at 12:00:00\n")


class PanelSigningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.app = self.root / build.PANEL_APP
        for name in ("Info.plist", "MacOS/panel", "MacOS/Abstraction Panel"):
            path = self.app / "Contents" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(name)

    def test_signs_nested_programs_before_outer_bundle_and_records_seal(self):
        calls = []

        def run(args, **kwargs):
            calls.append(args)
            if args[1] == "--force" and Path(args[-1]) == self.app:
                seal = self.app / "Contents/_CodeSignature/CodeResources"
                seal.parent.mkdir(parents=True)
                seal.write_text("sealed")
            return subprocess.CompletedProcess(args, 0, stderr=DETAILS if kwargs.get("text") else None)

        with patch.object(build.subprocess, "run", side_effect=run):
            seal = build.sign_panel_app(self.root, "Developer ID Application: Fixture (TEAM)", self.root / "keychain")
        self.assertEqual(seal, (build.PANEL_APP / "Contents/_CodeSignature/CodeResources").as_posix())
        signed = [Path(call[-1]).name for call in calls if call[1] == "--force"]
        self.assertEqual(signed, ["panel", "Abstraction Panel", "Abstraction Panel.app"])
        self.assertTrue(all("--timestamp" in call and "runtime" in call for call in calls if call[1] == "--force"))
        self.assertEqual(calls[-1][1:5], ["--verify", "--deep", "--strict", "--verbose=2"])
        self.assertEqual(Path(calls[-1][-1]), self.app)

    def test_requested_signing_fails_on_missing_bundle_or_signature_metadata(self):
        (self.app / "Contents/MacOS/panel").unlink()
        with patch.object(build.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "complete Panel.app"):
                build.sign_panel_app(self.root, "Developer ID Application: Fixture")
        run.assert_not_called()
        (self.app / "Contents/MacOS/panel").write_text("panel")
        with patch.object(build.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, stderr="no timestamp")):
            with self.assertRaisesRegex(RuntimeError, "secure timestamp"):
                build.sign_panel_app(self.root, "Developer ID Application: Fixture")

    def test_signature_seal_is_in_component_payload_and_uninstall_ledger(self):
        seal = (build.PANEL_APP / "Contents/_CodeSignature/CodeResources").as_posix()
        (self.root / seal).parent.mkdir(parents=True, exist_ok=True)
        (self.root / seal).write_text("sealed")
        license_file = self.root / ".local/share/abstraction/LICENSE"
        license_file.parent.mkdir(parents=True)
        license_file.write_text("license")
        files = [(str(build.PANEL_APP / "Contents/Info.plist"), 0o644),
                 (str(build.PANEL_APP / "Contents/MacOS/panel"), 0o755),
                 (str(build.PANEL_APP / "Contents/MacOS/Abstraction Panel"), 0o755),
                 (seal, 0o644), (".local/share/abstraction/LICENSE", 0o644)]
        work = self.root / "work"
        with patch.object(build.subprocess, "run"):
            build.pkg(self.root, files, self.root / "out.pkg", "1.0", work,
                      {path: build.BASE for path, _ in files})
        self.assertTrue((work / "root-service" / seal).is_file())
        self.assertIn(seal, (self.root / ".local/share/abstraction/FILES").read_text().splitlines())

    def test_cli_signing_is_opt_in_and_passes_signature_to_package_ledger(self):
        items = [(str(build.PANEL_APP / "Contents/Info.plist"), "authored", "posix", "Info.plist", 0o644),
                 (str(build.PANEL_APP / "Contents/MacOS/panel"), "gobuild", "charter", "monitor", 0o755),
                 (str(build.PANEL_APP / "Contents/MacOS/Abstraction Panel"), "swiftbuild", "charter", "launcher", 0o755),
                 (".local/bin/openabstractions", "gobuild", "charter", "serve", 0o755)]
        owner = {row[0]: build.BASE for row in items}
        prebuilt = self.root / "prebuilt"
        prebuilt.mkdir()
        for name in ("panel", "Abstraction Panel", "openabstractions"):
            (prebuilt / name).write_text(name)
        license_file = self.root / "LICENSE"
        license_file.write_text("license")

        def stage(rows, src, root, goos, goarch, **kwargs):
            for path, _, _, _, _ in rows:
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(path)
            return [(path, mode) for path, _, _, _, mode in rows]

        def package(root, files, out, version, work, owned):
            seal = (build.PANEL_APP / "Contents/_CodeSignature/CodeResources").as_posix()
            if seal in dict(files):
                self.assertEqual(owned[seal], build.BASE)
            out.write_text("package")
            return out

        base = ["build.py", "--platform", "macos", "--out", str(self.root / "dist"),
                "--bin", str(prebuilt), "--license", str(license_file)]
        with patch.object(build, "sources", return_value={}), patch.object(build, "payload", return_value=items), \
             patch.object(build, "feature_of", return_value=owner), patch.object(build, "needs"), \
             patch.object(build, "pinned"), patch.object(build, "stage", side_effect=stage), \
             patch.object(build, "pkg", side_effect=package), patch.object(build, "sign_panel_app", return_value=(
                 build.PANEL_APP / "Contents/_CodeSignature/CodeResources").as_posix()) as sign:
            with patch.object(sys, "argv", base):
                self.assertEqual(build.main(), 0)
            sign.assert_not_called()
            with patch.object(sys, "argv", base + ["--sign-app-identity", "Developer ID Application: Fixture"]):
                self.assertEqual(build.main(), 0)
            sign.assert_called_once()


if __name__ == "__main__":
    unittest.main()
