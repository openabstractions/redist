"""Offline checks for the packaged macOS program signing boundary."""
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import build


DETAILS = ("Identifier=org.openabstractions.panel\n"
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
        (self.app / "Contents/Info.plist").write_bytes(plistlib.dumps({"CFBundleIdentifier": build.PANEL_IDENTIFIER}))

    def test_declared_app_icon_is_staged_in_the_service_bundle(self):
        destination = (build.PANEL_APP / "Contents/Resources/AppIcon.icns").as_posix()
        items = [item for item in build.payload("macos") if item[0] == destination]
        self.assertEqual(len(items), 1, "CFBundleIconFile's AppIcon must be in the package payload")
        self.assertEqual(build.feature_of("macos")[destination], build.BASE)
        source = self.root / "charter"
        expected = source / "monitor/icon/panel.icns"
        expected.parent.mkdir(parents=True)
        expected.write_bytes(b"fixture ICNS: \x89PNG\r\n\x1a\n\x00\xff")
        authored = self.root / "authored"
        authored.mkdir()
        (authored / "fixture.txt").write_bytes(b"authored\r\ntext\r\n")
        text_path = ".local/share/abstraction/dev/USING.txt"
        items.append((text_path, "authored", "posix", "fixture.txt", 0o644))
        with patch.object(build, "HERE", authored):
            files = build.stage(items, {"charter": source}, self.root, "darwin", "arm64", programs=False)
        self.assertEqual((self.root / destination).read_bytes(), expected.read_bytes())
        self.assertEqual((self.root / text_path).read_bytes(), b"authored\ntext\n")
        self.assertEqual(files, [(destination, 0o644), (text_path, 0o644)])

    def prebuilt_package_inputs(self):
        prebuilt = self.root / "universal"
        prebuilt.mkdir()
        for name in ("panel", "Abstraction Panel", "openabstractions"):
            (prebuilt / name).write_bytes(b"inert program fixture")
        license_file = self.root / "LICENSE"
        license_file.write_bytes(b"fixture license\r\n")
        argv = ["build.py", "--platform", "macos", "--out", str(self.root / "dist"),
                "--bin", str(prebuilt), "--license", str(license_file)]
        return prebuilt, argv

    def test_release_bin_route_carries_exact_icon_or_uses_explicit_source(self):
        prebuilt, argv = self.prebuilt_package_inputs()
        destination = (build.PANEL_APP / "Contents/Resources/AppIcon.icns").as_posix()
        icon = b"fixture ICNS: \x89PNG\r\n\x1a\n\x00\xff"

        def package(root, files, out, version, work, owned):
            self.assertEqual((root / destination).read_bytes(), icon)
            self.assertIn((destination, 0o644), files)
            self.assertEqual(owned[destination], build.BASE)
            self.assertEqual((root / ".local/share/abstraction/LICENSE").read_bytes(), b"fixture license\n")
            out.write_bytes(b"fixture package")
            return out

        for source_checkout in (False, True):
            with self.subTest(source_checkout=source_checkout):
                args = argv[:]
                if source_checkout:
                    (prebuilt / "AppIcon.icns").unlink()
                    source = self.root / "charter"
                    expected = source / "monitor/icon/panel.icns"
                    expected.parent.mkdir(parents=True)
                    expected.write_bytes(icon)
                    args += ["--src", "charter=" + str(source)]
                else:
                    (prebuilt / "AppIcon.icns").write_bytes(icon)
                with patch.object(build, "needs"), patch.object(build, "pkg", side_effect=package), \
                     patch.object(build, "sign_development_programs", return_value=(build.PANEL_APP / "Contents/_CodeSignature/CodeResources").as_posix()), \
                     patch.object(sys, "argv", args):
                    self.assertEqual(build.main(), 0)

    def test_release_bin_route_refuses_missing_required_icon(self):
        _, argv = self.prebuilt_package_inputs()
        with patch.object(build, "needs") as needs, patch.object(build, "pkg") as package, \
             patch.object(sys, "argv", argv):
            with self.assertRaisesRegex(SystemExit, "AppIcon.icns"):
                build.main()
        needs.assert_not_called()
        package.assert_not_called()

    def test_signs_nested_programs_before_outer_bundle_and_records_seal(self):
        calls = []
        identifiers = {}

        def run(args, **kwargs):
            calls.append(args)
            if args[1] == "--force":
                identifiers[args[-1]] = args[args.index("--identifier") + 1]
            if args[1] == "--force" and Path(args[-1]) == self.app:
                seal = self.app / "Contents/_CodeSignature/CodeResources"
                seal.parent.mkdir(parents=True)
                seal.write_text("sealed")
            details = DETAILS.replace(build.PANEL_IDENTIFIER, identifiers.get(args[-1], build.PANEL_IDENTIFIER))
            return subprocess.CompletedProcess(args, 0, stderr=details if kwargs.get("text") else None)

        with patch.object(build.subprocess, "run", side_effect=run):
            seal = build.sign_panel_app(self.root, "Developer ID Application: Fixture (TEAM)", self.root / "keychain")
        self.assertEqual(seal, (build.PANEL_APP / "Contents/_CodeSignature/CodeResources").as_posix())
        signed = [Path(call[-1]).name for call in calls if call[1] == "--force"]
        self.assertEqual(signed, ["panel", "Abstraction Panel", "Abstraction Panel.app"])
        self.assertEqual(list(identifiers.values()), [build.PANEL_BACKEND_IDENTIFIER,
                         build.PANEL_IDENTIFIER, build.PANEL_IDENTIFIER])
        self.assertTrue(all("--timestamp" in call and "runtime" in call for call in calls if call[1] == "--force"))
        self.assertEqual(calls[-1][1:5], ["--verify", "--deep", "--strict", "--verbose=2"])
        self.assertEqual(Path(calls[-1][-1]), self.app)

    def test_runtime_uses_stable_distinct_identifier_and_configured_signer(self):
        items = [item for item in build.payload("macos") if item[0] == build.RUNTIME_PROGRAM.as_posix()]
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0][1:4], ("gobuild", "charter", "serve"))
        self.assertEqual(build.feature_of("macos")[items[0][0]], build.BASE)
        runtime = self.root / build.RUNTIME_PROGRAM
        runtime.write_bytes(b"runtime fixture")
        keychain = self.root / "existing-login.keychain-db"
        details = DETAILS.replace(build.PANEL_IDENTIFIER, build.RUNTIME_IDENTIFIER)
        with patch.object(build.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, stderr=details)) as run:
            build.sign_runtime(self.root, "Developer ID Application: Existing (TEAM)", keychain)
        sign = run.call_args_list[0].args[0]
        self.assertEqual(sign[sign.index("--identifier") + 1], "org.openabstractions.runtime")
        self.assertEqual(sign[sign.index("--sign") + 1], "Developer ID Application: Existing (TEAM)")
        self.assertEqual(sign[sign.index("--keychain") + 1], str(keychain))
        self.assertEqual(sign[-1], str(runtime))
        self.assertEqual(len({build.RUNTIME_IDENTIFIER, build.PANEL_IDENTIFIER, build.PANEL_BACKEND_IDENTIFIER}), 3)
        self.assertNotIn("--entitlements", sign)
        self.assertNotIn("--deep", sign)

    def test_runtime_signing_refuses_wrong_identifier_and_propagates_native_failure(self):
        runtime = self.root / build.RUNTIME_PROGRAM
        runtime.write_bytes(b"runtime fixture")
        with patch.object(build.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, stderr=DETAILS)):
            with self.assertRaisesRegex(RuntimeError, "unexpected signing identifier"):
                build.sign_runtime(self.root, "Developer ID Application: Fixture")
        failure = subprocess.CalledProcessError(1, ["codesign"])
        with patch.object(build.subprocess, "run", side_effect=failure) as run:
            with self.assertRaises(subprocess.CalledProcessError):
                build.sign_runtime(self.root, "Developer ID Application: Fixture")
        self.assertEqual(run.call_count, 1)
        runtime.unlink()
        with patch.object(build.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "runtime program"):
                build.sign_runtime(self.root, "Developer ID Application: Fixture")
        run.assert_not_called()

    def test_panel_bundle_identifier_matches_roster_before_signing(self):
        (self.app / "Contents/Info.plist").write_bytes(plistlib.dumps({"CFBundleIdentifier": build.RUNTIME_IDENTIFIER}))
        with patch.object(build.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "signing roster"):
                build.sign_panel_app(self.root, "Developer ID Application: Fixture")
        run.assert_not_called()

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

    def test_local_unsigned_package_requires_all_program_signatures_before_packaging(self):
        prebuilt, argv = self.prebuilt_package_inputs()
        (prebuilt / "AppIcon.icns").write_bytes(b"inert icon")
        (prebuilt / "openabstractions-mcp").write_bytes(b"inert optional MCP")
        signed = {}
        events = []

        def run(args, **kwargs):
            self.assertEqual(args[0], "codesign")
            target = Path(args[-1])
            if args[1] == "--force":
                self.assertEqual(args[args.index("--sign") + 1], "-")
                self.assertNotIn("--keychain", args)
                self.assertNotIn("--timestamp", args)
                signed[str(target)] = args[args.index("--identifier") + 1]
                events.append(target.name)
                if target.name == "Abstraction Panel.app":
                    seal = target / "Contents/_CodeSignature/CodeResources"
                    seal.parent.mkdir(parents=True)
                    seal.write_bytes(b"inert resource seal")
            elif args[1] == "--verify":
                self.assertIn("--all-architectures", args)
                self.assertIn(str(target), signed)
            identifier = signed[str(target)]
            return subprocess.CompletedProcess(args, 0, stdout='# designated => identifier "' + identifier + '"\n',
                                               stderr='Identifier=' + identifier + '\nSignature=adhoc\nTeamIdentifier=not set\n')

        def package(root, files, out, version, work, owner):
            expected = [root / path for path, kind, *_ in build.payload("macos")
                        if kind in ("gobuild", "swiftbuild")]
            self.assertTrue(expected)
            self.assertTrue(all(str(path) in signed for path in expected), "unsigned branch packaged a program without structural signature")
            self.assertEqual(events[-1], "Abstraction Panel.app")
            seal = (build.PANEL_APP / "Contents/_CodeSignature/CodeResources").as_posix()
            self.assertIn((seal, 0o644), files)
            self.assertEqual(owner[seal], build.BASE)
            self.assertTrue((root / seal).is_file())
            out.write_bytes(b"unsigned package")
            return out

        with patch.object(build, "needs"), patch.object(build.subprocess, "run", side_effect=run), \
             patch.object(build, "pkg", side_effect=package), patch.object(sys, "argv", argv):
            self.assertEqual(build.main(), 0)
        self.assertEqual(set(events), {"openabstractions", "panel", "Abstraction Panel", "openabstractions-mcp", "Abstraction Panel.app"})

    def test_development_native_failure_and_missing_requirement_refuse(self):
        items = [(str(build.PANEL_APP / "Contents/MacOS/panel"), "gobuild", "charter", "monitor", 0o755)]
        with patch.object(build.subprocess, "run", side_effect=subprocess.CalledProcessError(1, ["codesign"])):
            with self.assertRaises(subprocess.CalledProcessError):
                build.sign_development_programs(self.root, items)
        for metadata in ("Identifier=" + build.PANEL_BACKEND_IDENTIFIER + "\nSignature=adhoc\n",
                         "Identifier=wrong\nSignature=adhoc\ndesignated => identifier wrong\n",
                         "Identifier=" + build.PANEL_BACKEND_IDENTIFIER + "\nSignature=adhoc\nAuthority=Developer ID Application: Fixture\ndesignated => fixture\n"):
            with self.subTest(metadata=metadata), patch.object(build.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, stdout="", stderr=metadata)):
                with self.assertRaisesRegex(RuntimeError, "development ad-hoc identity or designated requirement"):
                    build.sign_development_programs(self.root, items)

    def test_developer_id_helpers_still_refuse_ad_hoc_identity(self):
        runtime = self.root / build.RUNTIME_PROGRAM
        runtime.write_bytes(b"inert runtime")
        with patch.object(build.subprocess, "run") as run:
            for call in (lambda: build.sign_program(runtime, "-", None, build.RUNTIME_IDENTIFIER),
                         lambda: build.sign_runtime(self.root, "-"), lambda: build.sign_panel_app(self.root, "-")):
                with self.assertRaisesRegex(ValueError, "Developer ID Application identity"):
                    call()
        run.assert_not_called()

    def test_cli_development_and_developer_id_routes_pass_seal_to_package_ledger(self):
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
             patch.object(build, "pkg", side_effect=package) as package_call, patch.object(build, "sign_runtime") as runtime_sign, \
             patch.object(build, "sign_panel_app", return_value=(
                 build.PANEL_APP / "Contents/_CodeSignature/CodeResources").as_posix()) as sign, \
             patch.object(build, "sign_development_programs", return_value=(
                 build.PANEL_APP / "Contents/_CodeSignature/CodeResources").as_posix()) as development:
            with patch.object(sys, "argv", base):
                self.assertEqual(build.main(), 0)
            sign.assert_not_called()
            runtime_sign.assert_not_called()
            development.assert_called_once()
            with patch.object(sys, "argv", base + ["--sign-app-identity", "Developer ID Application: Fixture"]):
                self.assertEqual(build.main(), 0)
            sign.assert_called_once()
            runtime_sign.assert_called_once()
            self.assertEqual(runtime_sign.call_args.args[1], "Developer ID Application: Fixture")
            runtime_sign.reset_mock()
            sign.reset_mock()
            package_call.reset_mock()
            runtime_sign.side_effect = subprocess.CalledProcessError(1, ["codesign"])
            with patch.object(sys, "argv", base + ["--sign-app-identity", "Developer ID Application: Fixture"]):
                with self.assertRaises(subprocess.CalledProcessError):
                    build.main()
            runtime_sign.assert_called_once()
            sign.assert_not_called()
            package_call.assert_not_called()


if __name__ == "__main__":
    unittest.main()
