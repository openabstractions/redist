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
import os
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

    def test_cgo_build_uses_the_package_floor_even_with_a_newer_host_setting(self):
        with patch.dict(os.environ, MACOSX_DEPLOYMENT_TARGET="26.0"), patch.object(build.subprocess, "run") as run:
            build.gobuild(self.source.parent, Path(self.temp.name) / "out/panel", "darwin", "arm64")
        environment = run.call_args.kwargs["env"]
        self.assertEqual(environment["MACOSX_DEPLOYMENT_TARGET"], build.package_minimum_macos())
        self.assertEqual(environment["CGO_ENABLED"], "1")

    def test_emitted_and_prebuilt_macho_minima_are_received_before_packaging(self):
        image = Path(self.temp.name) / "panel"
        def output(version, platform="MACOS"):
            return f"{image}:\nLoad command 11\n cmd LC_BUILD_VERSION\n platform {platform}\n minos {version}\n sdk 27.0\n"
        def tool(text):
            return lambda args, **kwargs: "x86_64 arm64" if args[0] == "lipo" else text.get(args[3], "") if isinstance(text, dict) else text
        for text in (output("12.0"), output("11.0"),
                     "Load command 5\n cmd LC_VERSION_MIN_MACOSX\n version 12.0\n"):
            with self.subTest(valid=text), patch.object(build.subprocess, "check_output", side_effect=tool(text)):
                build.check_macos_minimum(image)
        for text in ("", output("26.0"), output("12.0") + output("12.0"), output("12.0", "IOS"), output("unknown"),
                     {"x86_64": output("12.0"), "arm64": ""}, {"x86_64": output("12.0"), "arm64": output("26.0")}):
            with self.subTest(refused=text), patch.object(build.subprocess, "check_output", side_effect=tool(text)):
                with self.assertRaises(SystemExit):
                    build.check_macos_minimum(image)
        prebuilt = Path(self.temp.name) / "prebuilt"
        prebuilt.mkdir()
        (prebuilt / "panel").write_bytes(b"inert prebuilt image")
        with patch.object(build.subprocess, "check_output", side_effect=tool(output("26.0"))), self.assertRaises(SystemExit):
            build.stage([("bin/panel", "gobuild", "charter", "monitor", "755")], {},
                        Path(self.temp.name) / "payload", "darwin", "arm64", prebuilt=prebuilt)

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
