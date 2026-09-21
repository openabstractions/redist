"""Isolated pre-replacement fixtures: python3 test_preinstall.py [-h]."""
import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("lifecycle_fixtures", HERE.parent / "test_lifecycle.py")
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)

class Preinstall(unittest.TestCase):
    command = fixtures.Lifecycle.command

    def setUp(self):
        fixtures.Lifecycle.setUp(self)
        self.command("stat", 'echo "${TARGET_UID:-1000}"')
        launchctl = self.bin / "launchctl"
        original = launchctl.read_text()
        launchctl.write_text(original.replace("#!/bin/sh\n", '#!/bin/sh\nif [ "$1" = asuser ]; then shift 3; exec "$0" "$@"; fi\n', 1))
        self.scripts = self.root / "scripts"
        self.scripts.mkdir()
        (self.scripts / "preinstall").write_text((HERE / "preinstall").read_text())
        (self.scripts / "lifecycle.sh").write_text(self.mac_helper)

    def run_preflight(self, **env):
        return subprocess.run(["sh", str(self.scripts / "preinstall")], env=dict(self.env, **env), text=True, capture_output=True, timeout=fixtures.SCRIPT_TIMEOUT)

    def test_stop_precedes_replacement_and_retains_work(self):
        result = self.run_preflight()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.root / "calls.stopped").exists())
        self.assertIn("bootout gui/1000/com.openabstractions.runtime", (self.root / "calls").read_text())
        self.assertIn("booted out running previous LaunchAgent", result.stdout)
        self.assertNotIn("no previous LaunchAgent com.openabstractions.runtime", result.stdout)
        self.assertEqual(self.payload.read_text(), "payload")
        self.assertEqual(self.data.read_text(), "accepted work")

    def test_a_retired_label_is_booted_out_before_replacement(self):
        result = self.run_preflight(AGENT_LABEL="com.openabstractions.jobd")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = (self.root / "calls").read_text()
        self.assertIn("bootout gui/1000/com.openabstractions.jobd", calls)
        self.assertNotIn("bootout gui/1000/com.openabstractions.runtime", calls)
        self.assertIn("no previous LaunchAgent com.openabstractions.runtime", result.stdout)
        self.assertEqual(self.payload.read_text(), "payload")

    def test_stop_failure_or_unverifiable_absence_blocks_replacement(self):
        for env in ({"FAIL":"stop"}, {"ACTIVE":"active"}, {"FAIL":"after"}, {"FAIL":"format"}, {"FAIL":"manager_query"}, {"MANAGER_UID":"0"}, {"MANAGER_NAME":"Background"}, {"TARGET_UID":"0"}):
            with self.subTest(env=env):
                (self.root / "calls.stopped").unlink(missing_ok=True)
                result = self.run_preflight(**env)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.payload.read_text(), "payload")
                self.assertEqual(self.data.read_text(), "accepted work")

    def test_fresh_absence_needs_verified_manager(self):
        result = self.run_preflight(ABSENT="yes", FAIL="stop")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("bootout", (self.root / "calls").read_text())
        self.assertIn("no previous LaunchAgent com.openabstractions.runtime registered in gui/1000; nothing booted out", result.stdout)
        self.assertNotIn("booted out running", result.stdout)

    def test_conflicting_user_target_refuses_before_manager(self):
        other = self.root / "other-user"
        other.mkdir()
        result = subprocess.run(["sh", str(self.scripts / "preinstall"), "package.pkg", str(other)], env=self.env, text=True, capture_output=True, timeout=fixtures.SCRIPT_TIMEOUT)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("conflicting user-home", result.stderr)
        self.assertFalse((self.root / "calls").exists())
        for target in ("/", str(self.home)):
            result = subprocess.run(["sh", str(self.scripts / "preinstall"), "package.pkg", target], env=dict(self.env, ABSENT="yes"), text=True, capture_output=True, timeout=fixtures.SCRIPT_TIMEOUT)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_package_stages_preflight_and_current_helper(self):
        spec = importlib.util.spec_from_file_location("posix_build", HERE.parent / "build.py")
        build = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(build)
        work = self.root / "build"
        package_root = self.root / "payload"
        share = package_root / ".local/share/abstraction"
        share.mkdir(parents=True)
        (share / "LICENSE").write_text("license")
        calls = []
        with mock.patch.object(build.subprocess, "run", side_effect=lambda args, **kw: calls.append(args)):
            build.pkg(package_root, [], self.root / "out.pkg", "0.1.0", work)
        for name in ("preinstall", "postinstall", "lifecycle.sh"):
            self.assertEqual((work / "scripts" / name).read_bytes(), (HERE / name).read_bytes().replace(b"\r\n", b"\n"))
        self.assertEqual(calls[0][0], "pkgbuild")
        self.assertIn(str(work / "scripts"), calls[0])

if __name__ == "__main__":
    unittest.main()
