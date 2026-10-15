"""The package's minimum macOS version and the Swift launcher's agree.

The launcher's source states its minimum in monitor/macos/minimum-macos.txt
(published with the launcher); macos/Info.plist states the package's
LSMinimumSystemVersion (published here). build.py builds the launcher for
that version and stops when the two differ. These tests hold that rule with
fixture sources, so they read only files this repository publishes.

Run: python3 -m unittest test_macos_minimum (from installer/posix).
"""
import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import build


class MinimumMacosTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name) / "monitor/macos/PanelLauncher.swift"
        self.source.parent.mkdir(parents=True)
        self.source.write_text("// fixture launcher\n")

    def test_info_plist_declares_a_version(self):
        self.assertRegex(build.package_minimum_macos(), r"^\d+\.\d+$")

    def test_a_matching_launcher_minimum_is_the_build_target(self):
        declared = build.package_minimum_macos()
        (self.source.parent / "minimum-macos.txt").write_text(declared + "\n")
        self.assertEqual(build.launcher_minimum_macos(self.source), declared)
        with patch.object(build.subprocess, "run") as run:
            build.swiftbuild(self.source, Path(self.temp.name) / "out/Abstraction Panel", "arm64")
        argv = run.call_args.args[0]
        self.assertEqual(argv[argv.index("-target") + 1], "arm64-apple-macos" + declared)

    def test_a_different_launcher_minimum_stops_the_build(self):
        (self.source.parent / "minimum-macos.txt").write_text("99.0\n")
        with self.assertRaises(SystemExit) as stopped:
            build.launcher_minimum_macos(self.source)
        self.assertIn("99.0", str(stopped.exception))
        self.assertIn(build.package_minimum_macos(), str(stopped.exception))

    def test_the_private_workspace_launcher_states_the_package_version(self):
        # In the private workspace the launcher's source sits two folders up;
        # the published repository has no such folder and skips this.
        launcher = build.HERE.parents[1] / "monitor" / "macos" / "PanelLauncher.swift"
        if not launcher.is_file():
            self.skipTest("no launcher source beside this checkout (published layout)")
        self.assertEqual(build.launcher_minimum_macos(launcher), build.package_minimum_macos())

    def test_a_source_without_the_file_builds_for_the_package_version_with_a_note(self):
        printed = io.StringIO()
        with contextlib.redirect_stdout(printed):
            self.assertEqual(build.launcher_minimum_macos(self.source), build.package_minimum_macos())
        self.assertIn("no minimum-macos.txt", printed.getvalue())


if __name__ == "__main__":
    unittest.main()
